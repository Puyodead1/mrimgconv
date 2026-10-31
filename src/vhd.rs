//! Minimal dynamic VHD (Microsoft Virtual Hard Disk v1.0) writer.
//!
//! Layout: [footer copy][dynamic header][BAT][data blocks...][footer]
//! Only 2 MiB blocks that contain non-zero data are allocated, so the file stays
//! roughly the size of the used data. Windows mounts these natively.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::time::{SystemTime, UNIX_EPOCH};

pub const BLOCK: u64 = 2 * 1024 * 1024;
const SECTOR: u64 = 512;
const BITMAP: u64 = 512; // 4096 sectors per block -> 512-byte sector bitmap
const UNUSED: u32 = 0xFFFF_FFFF;

pub struct VhdWriter {
    file: File,
    size: u64,
    bat: Vec<u32>,
    data_start: u64,
    next_free: u64,
    cur: Option<u64>,
    cur_dirty: bool,
    buf: Vec<u8>,
    footer: [u8; 512],
    pub allocated_blocks: u64,
}

fn checksum(b: &[u8]) -> u32 {
    !b.iter().fold(0u32, |a, &x| a.wrapping_add(x as u32))
}

fn chs(size: u64) -> (u16, u8, u8) {
    let mut total = size / SECTOR;
    if total > 65535 * 16 * 255 {
        total = 65535 * 16 * 255;
    }
    let (spt, heads, cth);
    if total >= 65535 * 16 * 63 {
        spt = 255u64;
        heads = 16u64;
        cth = total / spt;
    } else {
        let mut s = 17u64;
        let mut c = total / s;
        let mut h = c.div_ceil(1024).max(4);
        if c >= h * 1024 || h > 16 {
            s = 31;
            h = 16;
            c = total / s;
        }
        if c >= h * 1024 {
            s = 63;
            h = 16;
            c = total / s;
        }
        spt = s;
        heads = h;
        cth = c;
    }
    ((cth / heads) as u16, heads as u8, spt as u8)
}

fn uuid() -> [u8; 16] {
    // Not cryptographic; just needs to be unique per disk.
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut x = (t as u64) ^ ((std::process::id() as u64) << 32) ^ 0x9E37_79B9_7F4A_7C15;
    let mut out = [0u8; 16];
    for chunk in out.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        chunk.copy_from_slice(&x.to_le_bytes());
    }
    out[6] = (out[6] & 0x0F) | 0x40;
    out[8] = (out[8] & 0x3F) | 0x80;
    out
}

impl VhdWriter {
    pub fn create(path: &str, size: u64) -> io::Result<Self> {
        let size = size.div_ceil(SECTOR) * SECTOR;
        if size > 2040 * (1u64 << 30) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VHD format is limited to 2040 GiB",
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        let entries = size.div_ceil(BLOCK) as usize;
        let bat_bytes = ((entries as u64 * 4).div_ceil(SECTOR)) * SECTOR;
        let data_start = 512 + 1024 + bat_bytes;

        let mut footer = [0u8; 512];
        footer[0..8].copy_from_slice(b"conectix");
        footer[8..12].copy_from_slice(&2u32.to_be_bytes());
        footer[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        footer[16..24].copy_from_slice(&512u64.to_be_bytes());
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(946_684_800);
        footer[24..28].copy_from_slice(&(ts as u32).to_be_bytes());
        footer[28..32].copy_from_slice(b"mr2v");
        footer[32..36].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        footer[36..40].copy_from_slice(b"Wi2k");
        footer[40..48].copy_from_slice(&size.to_be_bytes());
        footer[48..56].copy_from_slice(&size.to_be_bytes());
        let (c, h, s) = chs(size);
        footer[56..58].copy_from_slice(&c.to_be_bytes());
        footer[58] = h;
        footer[59] = s;
        footer[60..64].copy_from_slice(&3u32.to_be_bytes());
        footer[68..84].copy_from_slice(&uuid());
        let ck = checksum(&footer);
        footer[64..68].copy_from_slice(&ck.to_be_bytes());

        Ok(VhdWriter {
            file,
            size,
            bat: vec![UNUSED; entries],
            data_start,
            next_free: data_start,
            cur: None,
            cur_dirty: false,
            buf: vec![0; BLOCK as usize],
            footer,
            allocated_blocks: 0,
        })
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    fn load(&mut self, idx: u64) -> io::Result<()> {
        if self.cur == Some(idx) {
            return Ok(());
        }
        self.flush_cur()?;
        let e = self.bat[idx as usize];
        if e == UNUSED {
            self.buf.fill(0);
        } else {
            self.file
                .seek(SeekFrom::Start(e as u64 * SECTOR + BITMAP))?;
            self.file.read_exact(&mut self.buf)?;
        }
        self.cur = Some(idx);
        self.cur_dirty = false;
        Ok(())
    }

    fn flush_cur(&mut self) -> io::Result<()> {
        let Some(idx) = self.cur else { return Ok(()) };
        if !self.cur_dirty {
            return Ok(());
        }
        let e = self.bat[idx as usize];
        if e == UNUSED {
            if self.buf.iter().all(|&b| b == 0) {
                self.cur_dirty = false;
                return Ok(());
            }
            let pos = self.next_free;
            self.file.seek(SeekFrom::Start(pos))?;
            self.file.write_all(&[0xFF; BITMAP as usize])?;
            self.file.write_all(&self.buf)?;
            self.bat[idx as usize] = (pos / SECTOR) as u32;
            self.next_free = pos + BITMAP + BLOCK;
            self.allocated_blocks += 1;
        } else {
            self.file
                .seek(SeekFrom::Start(e as u64 * SECTOR + BITMAP))?;
            self.file.write_all(&self.buf)?;
        }
        self.cur_dirty = false;
        Ok(())
    }

    /// Write `data` at virtual disk offset `off`. All-zero data never allocates blocks.
    pub fn write_at(&mut self, mut off: u64, mut data: &[u8]) -> io::Result<()> {
        if off + data.len() as u64 > self.size {
            let keep = self.size.saturating_sub(off) as usize;
            data = &data[..keep.min(data.len())];
        }
        while !data.is_empty() {
            let idx = off / BLOCK;
            let inner = (off % BLOCK) as usize;
            let n = data.len().min(BLOCK as usize - inner);
            let piece = &data[..n];
            let allocated = self.bat[idx as usize] != UNUSED || self.cur == Some(idx);
            if allocated || piece.iter().any(|&b| b != 0) {
                self.load(idx)?;
                self.buf[inner..inner + n].copy_from_slice(piece);
                self.cur_dirty = true;
            }
            off += n as u64;
            data = &data[n..];
        }
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<u64> {
        self.flush_cur()?;
        let entries = self.bat.len() as u32;

        let mut dh = [0u8; 1024];
        dh[0..8].copy_from_slice(b"cxsparse");
        dh[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        dh[16..24].copy_from_slice(&(512u64 + 1024).to_be_bytes());
        dh[24..28].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        dh[28..32].copy_from_slice(&entries.to_be_bytes());
        dh[32..36].copy_from_slice(&(BLOCK as u32).to_be_bytes());
        let ck = checksum(&dh);
        dh[36..40].copy_from_slice(&ck.to_be_bytes());

        let mut bat = Vec::with_capacity((self.data_start - 1536) as usize);
        for e in &self.bat {
            bat.extend_from_slice(&e.to_be_bytes());
        }
        bat.resize((self.data_start - 1536) as usize, 0xFF);

        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&self.footer)?;
        self.file.write_all(&dh)?;
        self.file.write_all(&bat)?;
        self.file.seek(SeekFrom::Start(self.next_free))?;
        self.file.write_all(&self.footer)?;
        let total = self.next_free + 512;
        self.file.set_len(total)?;
        self.file.sync_all()?;
        Ok(total)
    }
}
