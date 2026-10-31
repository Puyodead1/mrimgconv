//! Parser for the .mrimg catalog (index), reverse engineered from MRVerify.exe.
//!
//! File layout:
//!   [block data ...][catalog][u64 catalog offset][22-byte magic][u16 version][16-byte MD5]
//! The catalog is an MFC CArchive-style stream (see sub_434470 / sub_45C280 /
//! sub_458240 / sub_464590 / sub_421470 in MRVerify.exe).

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};

pub const MAGIC: &[u8; 22] = b"__79241006_2651_11D4_\0";

#[derive(Debug, Clone)]
pub struct BlockRec {
    /// Offset of the stored block inside the image file (0 = unused block).
    pub file_off: u64,
    pub md5: [u8; 16],
    /// Length word: bits 0..23 (or 0..29 if bit 30 set) = stored length,
    /// bit 24 = QuickLZ codec, bit 30 = 30-bit length + QuickLZ, bit 31 = encrypted.
    pub lenword: u32,
    /// Index of the split file holding this block.
    pub file_no: u16,
}

impl BlockRec {
    pub fn stored_len(&self) -> usize {
        if self.lenword & 0x4000_0000 != 0 {
            (self.lenword & 0x3FFF_FFFF) as usize
        } else {
            (self.lenword & 0xFF_FFFF) as usize
        }
    }
    pub fn is_qlz(&self) -> bool {
        self.lenword >> 30 != 0 || (self.lenword >> 24) & 1 == 1
    }
    pub fn encrypted(&self) -> bool {
        self.lenword >> 31 != 0
    }
    pub fn used(&self) -> bool {
        self.stored_len() != 0 && !(self.file_off == 0 && self.md5 == [0; 16])
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Partition {
    pub number: u16,
    pub label: String,
    pub volume: String,
    /// Partition start / length on the disk, in bytes.
    pub start: u64,
    pub length: u64,
    /// Disk offset where block 0 of the block index begins.
    pub block_base: u64,
    pub block_size: u32,
    pub fs_type: u16,
    /// Optional region stored uncompressed: (file offset, length), mapped to `start`.
    pub raw_region: Option<(u64, u32)>,
    pub blocks: Vec<BlockRec>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Disk {
    pub number: u32,
    pub signature: [u8; 4],
    pub names: Vec<String>,
    pub cylinders: u64,
    pub tracks_per_cyl: u32,
    pub sectors_per_track: u32,
    pub bytes_per_sector: u32,
    /// First 63 sectors of the disk (MBR, GPT header and entries).
    pub track0: Vec<u8>,
    /// Additional raw sectors (e.g. extended partition EBRs): (lba, data).
    pub extra_sectors: Vec<(u64, Vec<u8>)>,
    pub partitions: Vec<Partition>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Image {
    pub version: u16,
    pub image_id: [u8; 8],
    pub original_path: String,
    pub compressed: bool,
    pub encrypted: bool,
    pub xml: String,
    pub disks: Vec<Disk>,
}

struct Ar<R: Read> {
    r: R,
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

impl<R: Read> Ar<R> {
    fn raw(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let mut v = vec![0; n];
        self.r.read_exact(&mut v)?;
        Ok(v)
    }
    fn skip(&mut self, n: usize) -> io::Result<()> {
        self.raw(n).map(|_| ())
    }
    fn u8(&mut self) -> io::Result<u8> {
        let mut b = [0; 1];
        self.r.read_exact(&mut b)?;
        Ok(b[0])
    }
    fn u16(&mut self) -> io::Result<u16> {
        let mut b = [0; 2];
        self.r.read_exact(&mut b)?;
        Ok(u16::from_le_bytes(b))
    }
    fn u32(&mut self) -> io::Result<u32> {
        let mut b = [0; 4];
        self.r.read_exact(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn u64(&mut self) -> io::Result<u64> {
        let mut b = [0; 8];
        self.r.read_exact(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    /// MFC CString serialization (sub_44E9F0): length-prefixed, 0xFFFE marks UTF-16.
    fn cstr(&mut self) -> io::Result<String> {
        let mut wide = false;
        let mut n = self.u8()? as u32;
        if n == 0xFF {
            n = self.u16()? as u32;
            if n == 0xFFFE {
                wide = true;
                n = self.u8()? as u32;
                if n == 0xFF {
                    n = self.u16()? as u32;
                }
            }
            if n == 0xFFFF {
                n = self.u32()?;
                if n == 0xFFFF_FFFF {
                    n = 0;
                }
            }
        }
        if wide {
            let b = self.raw(n as usize * 2)?;
            let w: Vec<u16> = b
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Ok(String::from_utf16_lossy(&w))
        } else {
            let b = self.raw(n as usize)?;
            Ok(String::from_utf8(b.clone())
                .unwrap_or_else(|_| b.iter().map(|&c| c as char).collect()))
        }
    }
}

pub fn read_image(path: &str) -> io::Result<Image> {
    let mut f = File::open(path)?;
    let size = f.seek(SeekFrom::End(0))?;
    if size < 48 {
        return Err(bad("file too small"));
    }
    f.seek(SeekFrom::End(-48))?;
    let mut tail = [0u8; 48];
    f.read_exact(&mut tail)?;
    let cat_off = u64::from_le_bytes(tail[0..8].try_into().unwrap());
    if &tail[8..30] != MAGIC {
        return Err(bad("not a Macrium image (footer magic missing)"));
    }
    let version = u16::from_le_bytes([tail[30], tail[31]]);
    if version < 3 {
        return Err(bad(&format!(
            "image format version {version} is not supported (need >= 3)"
        )));
    }
    if cat_off >= size - 48 {
        return Err(bad("catalog offset out of range"));
    }
    let end = size - 48;

    // The block index record size is 30 bytes in all images seen so far, but MRVerify
    // also knows a 34-byte variant; try both and keep the one that ends exactly at the footer.
    let mut last_err = None;
    for rec_size in [30usize, 34] {
        f.seek(SeekFrom::Start(cat_off))?;
        let mut ar = Ar {
            r: Counting {
                r: BufReader::with_capacity(1 << 20, &mut f),
                n: 0,
            },
        };
        match parse_catalog(&mut ar, version, rec_size) {
            Ok(img) if cat_off + ar.r.n == end => return Ok(img),
            Ok(_) => {
                last_err = Some(bad(&format!(
                    "catalog parse ended at {} but footer starts at {end} (record size {rec_size})",
                    cat_off + ar.r.n
                )))
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap())
}

struct Counting<R> {
    r: R,
    n: u64,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let k = self.r.read(buf)?;
        self.n += k as u64;
        Ok(k)
    }
}

fn parse_catalog<R: Read>(ar: &mut Ar<R>, version: u16, rec_size: usize) -> io::Result<Image> {
    let mut image_id = [0u8; 8];
    image_id.copy_from_slice(&ar.raw(8)?);
    ar.u16()?;
    ar.u16()?;
    let original_path = ar.cstr()?;
    ar.u16()?;
    if ar.u8()? != 0 {
        // file-and-folder backup section
        ar.cstr()?;
        ar.cstr()?;
        ar.u32()?;
        ar.u32()?;
        let n = ar.u32()?;
        if n > 500 {
            return Err(bad("invalid file"));
        }
        for _ in 0..n {
            ar.cstr()?;
        }
    }
    if ar.u8()? != 0 {
        ar.skip(8)?;
    }
    ar.u64()?; // split file size
    ar.u16()?;
    ar.u16()?;
    let compression = ar.u32()?; // +1468: > 0 means blocks are compressed
    ar.u16()?;
    ar.u16()?;
    ar.u16()?;
    let encrypted = ar.u8()? != 0; // +1476
    ar.u8()?;
    ar.u16()?;
    ar.u16()?;
    let xml = ar.cstr()?;
    ar.u32()?; // timestamp
    ar.skip(16)?;
    let mut disks = Vec::new();
    if ar.u8()? != 0 {
        let nd = ar.u32()?;
        if nd > 100 {
            return Err(bad("file error: disk count"));
        }
        for _ in 0..nd {
            disks.push(parse_disk(ar, version, rec_size)?);
        }
    }
    Ok(Image {
        version,
        image_id,
        original_path,
        compressed: compression as i32 > 0,
        encrypted,
        xml,
        disks,
    })
}

fn parse_disk<R: Read>(ar: &mut Ar<R>, version: u16, rec_size: usize) -> io::Result<Disk> {
    let number = ar.u32()?;
    let mut signature = [0u8; 4];
    signature.copy_from_slice(&ar.raw(4)?);
    let mut names = Vec::new();
    for _ in 0..5 {
        names.push(ar.cstr()?);
    }
    let cylinders = ar.u64()?;
    ar.u32()?; // media type
    let tracks_per_cyl = ar.u32()?;
    let sectors_per_track = ar.u32()?;
    let bytes_per_sector = ar.u32()?;
    let track0 = if version >= 2 {
        ar.raw(32256)?
    } else {
        let mut t = ar.raw(512)?;
        t.resize(32256, 0);
        t
    };
    ar.u32()?;
    let n_extra = ar.u32()?;
    let mut extra_sectors = Vec::new();
    for _ in 0..n_extra {
        let data = ar.raw(512)?;
        let lba = ar.u64()?;
        extra_sectors.push((lba, data));
    }
    let np = ar.u32()?;
    let mut partitions = Vec::new();
    for _ in 0..np {
        partitions.push(parse_partition(ar, version, rec_size)?);
    }
    Ok(Disk {
        number,
        signature,
        names,
        cylinders,
        tracks_per_cyl,
        sectors_per_track,
        bytes_per_sector,
        track0,
        extra_sectors,
        partitions,
    })
}

fn parse_partition<R: Read>(
    ar: &mut Ar<R>,
    version: u16,
    rec_size: usize,
) -> io::Result<Partition> {
    // sub_458240
    ar.u64()?;
    ar.u64()?;
    ar.u64()?;
    ar.skip(16)?;
    // sub_464590
    ar.skip(12)?;
    ar.u8()?;
    let volume = ar.cstr()?;
    let label = ar.cstr()?;
    let number = ar.u16()?;
    let fs_type = ar.u16()?;
    ar.u32()?;
    ar.u32()?;
    ar.u32()?;
    ar.u32()?; // timestamp
    let start = ar.u64()?;
    let length = ar.u64()?;
    let block_base = ar.u64()?;
    ar.u64()?;
    ar.u64()?;
    ar.u64()?; // end offset
    for _ in 0..7 {
        ar.u32()?;
    }
    let block_size = ar.u32()?;
    let m = ar.u32()?;
    for _ in 0..m {
        ar.u16()?;
        if version >= 4 {
            ar.cstr()?;
            ar.u32()?;
        }
    }
    ar.u32()?;
    // sub_421470: block index
    ar.u16()?;
    let raw_off = ar.u64()?;
    let raw_len = ar.u32()?;
    ar.skip(16)?;
    let n = ar.u32()? as usize;
    if block_size == 0 || block_size > 64 << 20 {
        return Err(bad("implausible block size"));
    }
    let data = ar.raw(
        n.checked_mul(rec_size)
            .ok_or_else(|| bad("index too large"))?,
    )?;
    let blocks = data
        .chunks_exact(rec_size)
        .map(|r| BlockRec {
            file_off: u64::from_le_bytes(r[0..8].try_into().unwrap()),
            md5: r[8..24].try_into().unwrap(),
            lenword: u32::from_le_bytes(r[24..28].try_into().unwrap()),
            file_no: u16::from_le_bytes(r[28..30].try_into().unwrap()),
        })
        .collect();
    Ok(Partition {
        number,
        label,
        volume,
        start,
        length,
        block_base,
        block_size,
        fs_type,
        raw_region: if raw_len > 0 {
            Some((raw_off, raw_len))
        } else {
            None
        },
        blocks,
    })
}
