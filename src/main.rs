mod catalog;
mod codec;
mod md5;
mod vhd;

use catalog::{BlockRec, Disk, Image};
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;
use vhd::VhdWriter;

const USAGE: &str = "\
mrimg2vhd - convert a Macrium Reflect .mrimg disk image into a dynamic (sparse) VHD

usage: mrimg2vhd <image.mrimg> [options]

options:
  -o, --output <path>   output .vhd (default: next to the image; _diskN suffix for multi-disk images)
      --disk <N>        only convert the N-th disk in the image (0-based)
      --info            print image layout and exit
      --no-verify       skip MD5 verification of each block
      --ignore-errors   write zeros for unreadable/corrupt blocks instead of aborting
  -h, --help            show this help

The VHD can be mounted read-only in Windows with:
  Mount-DiskImage -ImagePath <file.vhd> -Access ReadOnly
";

struct Opts {
    input: String,
    output: Option<String>,
    disk: Option<usize>,
    info: bool,
    verify: bool,
    ignore_errors: bool,
}

fn parse_args() -> Result<Opts, String> {
    let mut a = std::env::args().skip(1);
    let mut o = Opts {
        input: String::new(),
        output: None,
        disk: None,
        info: false,
        verify: true,
        ignore_errors: false,
    };
    while let Some(x) = a.next() {
        match x.as_str() {
            "-h" | "--help" => return Err(String::new()),
            "-o" | "--output" => o.output = Some(a.next().ok_or("missing value for --output")?),
            "--disk" => {
                o.disk = Some(
                    a.next()
                        .ok_or("missing value for --disk")?
                        .parse()
                        .map_err(|_| "bad --disk value")?,
                )
            }
            "--info" => o.info = true,
            "--no-verify" => o.verify = false,
            "--ignore-errors" => o.ignore_errors = true,
            s if s.starts_with('-') => return Err(format!("unknown option {s}")),
            s if o.input.is_empty() => o.input = s.to_string(),
            s => return Err(format!("unexpected argument {s}")),
        }
    }
    if o.input.is_empty() {
        return Err(String::new());
    }
    Ok(o)
}

fn human(n: u64) -> String {
    let u = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < u.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.2} {}", u[i])
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

struct Gpt {
    alt_lba: u64,
    hdr_size: usize,
    entries_lba: u64,
    entries_bytes: usize,
}

fn gpt_info(d: &Disk) -> Option<Gpt> {
    let h = &d.track0[512..1024];
    if &h[0..8] != b"EFI PART" {
        return None;
    }
    let le32 = |o: usize| u32::from_le_bytes(h[o..o + 4].try_into().unwrap());
    let le64 = |o: usize| u64::from_le_bytes(h[o..o + 8].try_into().unwrap());
    let hdr_size = le32(12) as usize;
    let g = Gpt {
        alt_lba: le64(32),
        hdr_size,
        entries_lba: le64(72),
        entries_bytes: le32(80) as usize * le32(84) as usize,
    };
    if !(92..=512).contains(&hdr_size) || g.alt_lba < 34 {
        return None;
    }
    Some(g)
}

fn disk_size(d: &Disk) -> u64 {
    let mut size = d.cylinders
        * d.tracks_per_cyl as u64
        * d.sectors_per_track as u64
        * d.bytes_per_sector as u64;
    if let Some(g) = gpt_info(d) {
        size = size.max((g.alt_lba + 1) * 512);
    }
    for p in &d.partitions {
        size = size.max(p.start + p.length);
    }
    for (lba, _) in &d.extra_sectors {
        size = size.max((lba + 1) * 512);
    }
    size.max(32256)
}

fn print_info(img: &Image) {
    println!("format version : {}", img.version);
    println!(
        "image id       : {}",
        img.image_id
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>()
    );
    println!("original path  : {}", img.original_path);
    println!("compressed     : {}", img.compressed);
    println!("encrypted      : {}", img.encrypted);
    for (i, d) in img.disks.iter().enumerate() {
        println!(
            "disk[{i}] #{} {} - {} ({}), {} partition(s){}",
            d.number,
            d.names
                .iter()
                .rfind(|s| !s.trim().is_empty())
                .map(|s| s.trim())
                .unwrap_or(""),
            human(disk_size(d)),
            disk_size(d),
            d.partitions.len(),
            if gpt_info(d).is_some() {
                ", GPT"
            } else {
                ", MBR"
            }
        );
        for p in &d.partitions {
            let used = p.blocks.iter().filter(|b| b.used()).count();
            println!(
                "  part {:>2}: type {:>3} start {:>14} len {:>14} ({:>10})  {:<12} blocks {}/{} x {}{}",
                p.number,
                p.fs_type,
                p.start,
                p.length,
                human(p.length),
                if p.label.is_empty() { "-" } else { &p.label },
                used,
                p.blocks.len(),
                p.block_size,
                p.raw_region.map(|(o, l)| format!("  raw {} @ {}", human(l as u64), o)).unwrap_or_default()
            );
        }
    }
}

/// Reads stored blocks from the image (and split siblings) with mostly sequential IO.
struct Source {
    base: PathBuf,
    files: Vec<Option<(BufReader<File>, u64)>>,
}

impl Source {
    fn new(path: &str) -> Self {
        Source {
            base: PathBuf::from(path),
            files: Vec::new(),
        }
    }

    /// Split sets end in "-NN.mrimg"; the split number replaces the last NN.
    fn split_path(&self, n: u16) -> PathBuf {
        if n == 0 {
            return self.base.clone();
        }
        let stem = self
            .base
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let ext = self
            .base
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_else(|| "mrimg".into());
        let name = match stem.rfind('-') {
            Some(i) if stem[i + 1..].chars().all(|c| c.is_ascii_digit()) => {
                format!("{}-{:02}.{ext}", &stem[..i], n)
            }
            _ => format!("{stem}-{n:02}.{ext}"),
        };
        self.base.with_file_name(name)
    }

    fn read(&mut self, file_no: u16, off: u64, len: usize, out: &mut Vec<u8>) -> io::Result<()> {
        let i = file_no as usize;
        if self.files.len() <= i {
            self.files.resize_with(i + 1, || None);
        }
        if self.files[i].is_none() {
            let p = self.split_path(file_no);
            let f = File::open(&p)
                .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", p.display())))?;
            self.files[i] = Some((BufReader::with_capacity(8 << 20, f), 0));
        }
        let (r, pos) = self.files[i].as_mut().unwrap();
        if *pos != off {
            r.seek_relative(off as i64 - *pos as i64)?;
        }
        out.resize(len, 0);
        r.read_exact(out)?;
        *pos = off + len as u64;
        Ok(())
    }
}

struct Job<'a> {
    disk_off: u64,
    write_len: usize,
    rec: &'a BlockRec,
    block_size: usize,
}

fn decode(
    img: &Image,
    job: &Job,
    stored: &[u8],
    verify: bool,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    if !img.compressed {
        out.clear();
        out.extend_from_slice(stored);
    } else if job.rec.is_qlz() {
        codec::qlz_decompress(stored, out, job.block_size)?;
    } else {
        codec::lzo_decompress_block(stored, out, job.block_size)?;
    }
    if verify && md5::md5(out) != job.rec.md5 {
        return Err("MD5 mismatch".into());
    }
    out.resize(job.block_size, 0);
    Ok(())
}

fn convert_disk(
    img: &Image,
    d: &Disk,
    src: &mut Source,
    out_path: &str,
    o: &Opts,
) -> Result<(), String> {
    let size = disk_size(d);
    let mut vhd = VhdWriter::create(out_path, size).map_err(|e| format!("{out_path}: {e}"))?;
    println!("writing {out_path} (virtual size {})", human(vhd.size()));
    let w = |r: io::Result<()>| r.map_err(|e| format!("write error: {e}"));

    w(vhd.write_at(0, &d.track0))?;
    for (lba, data) in &d.extra_sectors {
        w(vhd.write_at(lba * 512, data))?;
    }

    let mut parts: Vec<_> = d.partitions.iter().collect();
    parts.sort_by_key(|p| p.start);
    let total_used: u64 = parts
        .iter()
        .map(|p| p.blocks.iter().filter(|b| b.used()).count() as u64)
        .sum();
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(16);
    let started = Instant::now();
    let mut last_report = Instant::now();
    let mut done = 0u64;
    let mut bad = 0u64;
    let mut buf = Vec::new();

    for p in parts {
        let pend = p.start + p.length;
        if let Some((roff, rlen)) = p.raw_region {
            src.read(0, roff, rlen as usize, &mut buf)
                .map_err(|e| format!("read error: {e}"))?;
            w(vhd.write_at(p.start, &buf))?;
        }
        let bs = p.block_size as usize;
        let jobs: Vec<Job> = p
            .blocks
            .iter()
            .enumerate()
            .filter(|(_, r)| r.used())
            .filter_map(|(i, r)| {
                let off = p.block_base + i as u64 * bs as u64;
                (off < pend).then(|| Job {
                    disk_off: off,
                    write_len: bs.min((pend - off) as usize),
                    rec: r,
                    block_size: bs,
                })
            })
            .collect();
        if jobs.iter().any(|j| j.rec.encrypted()) {
            return Err(
                "image contains encrypted blocks; encrypted images are not supported".into(),
            );
        }

        for batch in jobs.chunks(threads * 32) {
            let mut stored: Vec<Vec<u8>> = Vec::with_capacity(batch.len());
            for j in batch {
                let mut v = Vec::new();
                src.read(j.rec.file_no, j.rec.file_off, j.rec.stored_len(), &mut v)
                    .map_err(|e| format!("read error at {}: {e}", j.rec.file_off))?;
                stored.push(v);
            }
            let mut decoded: Vec<Result<Vec<u8>, String>> =
                (0..batch.len()).map(|_| Ok(Vec::new())).collect();
            let per = batch.len().div_ceil(threads);
            std::thread::scope(|s| {
                for ((jobs, st), outs) in batch
                    .chunks(per)
                    .zip(stored.chunks(per))
                    .zip(decoded.chunks_mut(per))
                {
                    s.spawn(move || {
                        for ((j, sd), out) in jobs.iter().zip(st).zip(outs.iter_mut()) {
                            let mut v = Vec::with_capacity(j.block_size + 16);
                            *out = decode(img, j, sd, o.verify, &mut v).map(|_| v);
                        }
                    });
                }
            });
            for (j, r) in batch.iter().zip(decoded) {
                match r {
                    Ok(data) => w(vhd.write_at(j.disk_off, &data[..j.write_len]))?,
                    Err(e) => {
                        let msg = format!(
                            "partition {} block at disk offset {} (file offset {}): {e}",
                            p.number, j.disk_off, j.rec.file_off
                        );
                        if !o.ignore_errors {
                            return Err(msg + " (use --ignore-errors to continue)");
                        }
                        eprintln!("warning: {msg}; writing zeros");
                        bad += 1;
                    }
                }
            }
            done += batch.len() as u64;
            if last_report.elapsed().as_secs_f64() >= 1.0 {
                last_report = Instant::now();
                let el = started.elapsed().as_secs_f64();
                eprint!(
                    "\r  {done}/{total_used} blocks ({:.1}%), {:.0} MiB/s   ",
                    100.0 * done as f64 / total_used.max(1) as f64,
                    (done as f64 * 65536.0) / el / 1048576.0
                );
            }
        }
    }
    eprintln!();

    if let Some(g) = gpt_info(d) {
        let entries_sectors = g.entries_bytes.div_ceil(512) as u64;
        let have_backup = d.extra_sectors.iter().any(|(l, _)| *l == g.alt_lba);
        let eoff = g.entries_lba as usize * 512;
        if !have_backup && eoff + g.entries_bytes <= d.track0.len() {
            // Recreate the backup GPT (Macrium does not store it) so Windows sees a clean table.
            let entries = &d.track0[eoff..eoff + g.entries_bytes];
            let back_entries_lba = g.alt_lba - entries_sectors;
            let mut hdr = d.track0[512..512 + g.hdr_size].to_vec();
            hdr[24..32].copy_from_slice(&g.alt_lba.to_le_bytes());
            hdr[32..40].copy_from_slice(&1u64.to_le_bytes());
            hdr[72..80].copy_from_slice(&back_entries_lba.to_le_bytes());
            hdr[16..20].fill(0);
            let crc = crc32(&hdr);
            hdr[16..20].copy_from_slice(&crc.to_le_bytes());
            hdr.resize(512, 0);
            w(vhd.write_at(back_entries_lba * 512, entries))?;
            w(vhd.write_at(g.alt_lba * 512, &hdr))?;
        }
    }

    let alloc = vhd.allocated_blocks;
    let total = vhd.finish().map_err(|e| format!("finalize error: {e}"))?;
    println!(
        "done in {:.0}s: {} blocks, {} allocated in VHD -> file size {}{}",
        started.elapsed().as_secs_f64(),
        done,
        human(alloc * vhd::BLOCK),
        human(total),
        if bad > 0 {
            format!(", {bad} bad block(s) zero-filled")
        } else {
            String::new()
        }
    );
    Ok(())
}

fn run(o: &Opts) -> Result<(), String> {
    let img = catalog::read_image(&o.input).map_err(|e| format!("{}: {e}", o.input))?;
    if o.info {
        print_info(&img);
        return Ok(());
    }
    if img.encrypted {
        return Err("encrypted images are not supported".into());
    }
    if img.disks.is_empty() {
        return Err("image contains no disk information (file and folder backup?)".into());
    }
    let selected: Vec<usize> = match o.disk {
        Some(n) if n < img.disks.len() => vec![n],
        Some(n) => {
            return Err(format!(
                "--disk {n} out of range (image has {} disk(s))",
                img.disks.len()
            ))
        }
        None => (0..img.disks.len()).collect(),
    };
    let mut src = Source::new(&o.input);
    for &i in &selected {
        let out = match &o.output {
            Some(p) if selected.len() == 1 => p.clone(),
            Some(p) => {
                let pb = Path::new(p);
                let stem = pb.file_stem().unwrap_or_default().to_string_lossy();
                pb.with_file_name(format!("{stem}_disk{i}.vhd"))
                    .to_string_lossy()
                    .into()
            }
            None => {
                let pb = Path::new(&o.input);
                let stem = pb.file_stem().unwrap_or_default().to_string_lossy();
                let name = if img.disks.len() == 1 {
                    format!("{stem}.vhd")
                } else {
                    format!("{stem}_disk{i}.vhd")
                };
                pb.with_file_name(name).to_string_lossy().into()
            }
        };
        convert_disk(&img, &img.disks[i], &mut src, &out, o)?;
    }
    Ok(())
}

fn main() -> ExitCode {
    let o = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("error: {e}\n");
            }
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&o) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
