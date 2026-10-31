# mrimg2vhd

Converts a Macrium Reflect 8 `.mrimg` disk image into a **dynamic VHD** that Windows can
mount natively (no Macrium driver needed), so you can browse the backed-up files in Explorer.

Dynamic VHDs only store 2 MiB blocks that contain data, so a 500 GB disk with 22 GB used
becomes a ~22 GB file. (Windows refuses to mount NTFS-*sparse* fixed VHDs, which is why
the dynamic format is used instead.)

## Install

Download a prebuilt binary for Windows, Linux or macOS from the
[Releases](https://github.com/Puyodead1/mrimg2vhd/releases) page, or build from source:

```
cargo build --release
```

Produces `target/release/mrimg2vhd.exe` (no dependencies). The converter itself is portable;
only mounting the resulting VHD is Windows-specific.

## Use

```
mrimg2vhd image.mrimg                # writes image.vhd next to the image
mrimg2vhd image.mrimg -o D:\out.vhd
mrimg2vhd image.mrimg --info         # show disks / partitions / used blocks
```

Then mount read-only (recommended, so nothing on the backup copy changes):

```
Mount-DiskImage -ImagePath D:\out.vhd -Access ReadOnly
```

or double-click the `.vhd`. If the original disk is still attached to the same machine,
Windows may keep the VHD offline because of a disk-ID collision; bring it online in Disk
Management. Unmount with `Dismount-DiskImage -ImagePath D:\out.vhd`.

Options: `--disk N` (convert one disk of a multi-disk image), `--no-verify` (skip per-block
MD5 check), `--ignore-errors` (zero-fill corrupt blocks instead of aborting).

## Limitations

- Encrypted (AES) images are not supported.
- Incremental/differential images need their parent chain; only full images are handled.
- Split image sets are looked up as `...-NN.mrimg` siblings (untested).
- The LZO-style codec (used when a block record does not select QuickLZ) is ported from the
  binary but has not been exercised by a real image yet.

## Format notes (reverse engineered from MRVerify.exe)

```
[block data ...][catalog][u64 catalog offset]["__79241006_2651_11D4_\0"][u16 version][MD5]
```

The catalog is an MFC `CArchive` stream: image header (8-byte id, paths, flags,
compression, encryption), the backup-definition XML, then per disk: number, signature,
5 strings, geometry, first 63 sectors (MBR + GPT), extra sectors, partitions. Each
partition has its geometry (start, length, block base, block size, ...), an optional
uncompressed region `(file offset, length)` mapped to the partition start (used for FAT
metadata), and the block index: one 30-byte record per block:

| bytes | field |
|-------|-------|
| 0-7   | file offset of the stored block (0 = unused) |
| 8-23  | MD5 of the decompressed block |
| 24-27 | length word: low 24 bits length (30 if bit 30), bit 24 = QuickLZ, bit 31 = encrypted |
| 28-29 | split file number |

Block `i` lives at disk offset `block_base + i * block_size`. Stored blocks start with a
QuickLZ header (`flags`, stored size, raw size); the payload is a QuickLZ level-3 variant
with an added RLE opcode.

The `re/` directory holds the Python prototypes used while reversing the format
(`parse_cat.py` dumps a catalog, `proto_qlz.py` is the decompressor prototype,
`check_vhd.py` sanity-checks a generated VHD).

## Disclaimer

This is an independent, unofficial tool. It is not affiliated with or endorsed by Paramount
Software UK Ltd. "Macrium" and "Macrium Reflect" are trademarks of their respective owner.
It only reads images; always keep the original `.mrimg`. No warranty, see [LICENSE](LICENSE).

## License

MIT
