//! Sparse raw disk image writer.
//!
//! The file is sized to the full disk up front and only non-zero 4 KiB pieces are
//! written, so unused space stays as holes on filesystems with sparse file support
//! (ext4, XFS, Btrfs, APFS, NTFS). Linux can attach it with `losetup -P`.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};

const PIECE: usize = 4096;

pub struct RawWriter {
    file: File,
    size: u64,
    /// Disjoint, merged `start -> end` ranges that hold written data. A zero piece
    /// only has to be written when it overwrites one of these; elsewhere it is a hole.
    written: BTreeMap<u64, u64>,
    pub sparse: bool,
}

impl RawWriter {
    pub fn create(path: &str, size: u64) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        let sparse = set_sparse(&file);
        file.set_len(size)?;
        Ok(RawWriter {
            file,
            size,
            written: BTreeMap::new(),
            sparse,
        })
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    /// Bytes of the image that hold written data.
    pub fn data_bytes(&self) -> u64 {
        self.written.iter().map(|(s, e)| e - s).sum()
    }

    fn overlaps_written(&self, s: u64, e: u64) -> bool {
        self.written
            .range(..e)
            .next_back()
            .is_some_and(|(_, &end)| end > s)
    }

    fn mark_written(&mut self, mut s: u64, mut e: u64) {
        while let Some((&ps, &pe)) = self.written.range(..=e).next_back() {
            if pe < s {
                break;
            }
            self.written.remove(&ps);
            s = s.min(ps);
            e = e.max(pe);
        }
        self.written.insert(s, e);
    }

    fn flush_run(&mut self, off: u64, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.file.seek(SeekFrom::Start(off))?;
        self.file.write_all(data)?;
        self.mark_written(off, off + data.len() as u64);
        Ok(())
    }

    /// Write `data` at disk offset `off`, skipping all-zero pieces that would land in holes.
    pub fn write_at(&mut self, off: u64, mut data: &[u8]) -> io::Result<()> {
        if off + data.len() as u64 > self.size {
            let keep = self.size.saturating_sub(off) as usize;
            data = &data[..keep.min(data.len())];
        }
        let mut run_start = 0;
        let mut i = 0;
        while i < data.len() {
            // Align pieces to the disk so holes line up with filesystem blocks.
            let pos = off + i as u64;
            let n = (PIECE - (pos % PIECE as u64) as usize).min(data.len() - i);
            let piece = &data[i..i + n];
            let keep = piece.iter().any(|&b| b != 0) || self.overlaps_written(pos, pos + n as u64);
            if !keep {
                self.flush_run(off + run_start as u64, &data[run_start..i])?;
                run_start = i + n;
            }
            i += n;
        }
        self.flush_run(off + run_start as u64, &data[run_start..])
    }

    pub fn finish(self) -> io::Result<u64> {
        self.file.sync_all()?;
        Ok(self.size)
    }
}

/// NTFS only leaves unwritten ranges unallocated once the file is marked sparse.
/// Returns false when the filesystem does not support it (e.g. FAT32/exFAT).
#[cfg(windows)]
fn set_sparse(f: &File) -> bool {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null_mut;

    #[link(name = "kernel32")]
    extern "system" {
        fn DeviceIoControl(
            h: *mut c_void,
            code: u32,
            inbuf: *mut c_void,
            insize: u32,
            outbuf: *mut c_void,
            outsize: u32,
            returned: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
    }
    const FSCTL_SET_SPARSE: u32 = 0x0009_00C4;
    let mut n = 0u32;
    // SAFETY: valid file handle, no buffers, synchronous call.
    unsafe {
        DeviceIoControl(
            f.as_raw_handle(),
            FSCTL_SET_SPARSE,
            null_mut(),
            0,
            null_mut(),
            0,
            &mut n,
            null_mut(),
        ) != 0
    }
}

/// Unix filesystems create holes for unwritten ranges automatically.
#[cfg(not(windows))]
fn set_sparse(_f: &File) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn tmp(name: &str) -> String {
        std::env::temp_dir()
            .join(format!("mrimgconv-test-{}-{name}", std::process::id()))
            .to_string_lossy()
            .into()
    }

    #[test]
    fn writes_data_and_keeps_zero_overwrites() {
        let p = tmp("raw.img");
        let mut w = RawWriter::create(&p, 64 * 1024).unwrap();
        w.write_at(100, &[1; 10_000]).unwrap();
        // Zeros over written data must land; zeros over a hole are skipped.
        w.write_at(4096, &[0; 4096]).unwrap();
        w.write_at(40_000, &[0; 8192]).unwrap();
        w.write_at(60_000, &[2; 10_000]).unwrap(); // clipped to the disk size
        assert_eq!(w.data_bytes(), 10_000 + (65_536 - 60_000));
        assert_eq!(w.finish().unwrap(), 65_536);

        let mut got = Vec::new();
        File::open(&p).unwrap().read_to_end(&mut got).unwrap();
        std::fs::remove_file(&p).unwrap();
        let mut want = vec![0u8; 65_536];
        want[100..10_100].fill(1);
        want[4096..8192].fill(0);
        want[60_000..].fill(2);
        assert_eq!(got, want);
    }

    #[cfg(unix)]
    fn allocated(p: &str) -> u64 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(p).unwrap().blocks() * 512
    }

    #[cfg(windows)]
    fn allocated(p: &str) -> u64 {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        extern "system" {
            fn GetCompressedFileSizeW(name: *const u16, high: *mut u32) -> u32;
        }
        let w: Vec<u16> = std::ffi::OsStr::new(p).encode_wide().chain([0]).collect();
        let mut high = 0u32;
        // SAFETY: NUL-terminated path, valid out pointer.
        let low = unsafe { GetCompressedFileSizeW(w.as_ptr(), &mut high) };
        ((high as u64) << 32) | low as u64
    }

    #[test]
    fn holes_are_not_allocated() {
        let p = tmp("sparse.img");
        let mut w = RawWriter::create(&p, 256 << 20).unwrap();
        assert!(w.sparse);
        w.write_at(128 << 20, &[7; 65536]).unwrap();
        w.write_at(0, &vec![0; 64 << 20]).unwrap();
        w.finish().unwrap();
        let used = allocated(&p);
        std::fs::remove_file(&p).unwrap();
        assert!(used < 8 << 20, "{used} bytes allocated for 64 KiB of data");
    }

    #[test]
    fn merges_written_ranges() {
        let p = tmp("merge.img");
        let mut w = RawWriter::create(&p, 1 << 20).unwrap();
        w.write_at(8192, &[1; 4096]).unwrap();
        w.write_at(0, &[1; 4096]).unwrap();
        w.write_at(4096, &[1; 4096]).unwrap();
        assert_eq!(w.written.len(), 1);
        assert_eq!(w.data_bytes(), 12_288);
        drop(w);
        std::fs::remove_file(&p).unwrap();
    }
}
