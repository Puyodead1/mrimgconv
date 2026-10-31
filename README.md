# mrimgconv

Converts a Macrium Reflect 8 `.mrimg` disk image into a disk image you can mount without
Macrium, so you can browse the backed-up files:

- **Dynamic VHD** (`.vhd`): Windows mounts it natively. Only 2 MiB blocks that contain data
  are stored, so a 500 GB disk with 22 GB used becomes a ~22 GB file. (Windows refuses to
  mount NTFS-*sparse* fixed VHDs, which is why the dynamic format is used.)
- **Sparse raw image** (`.img`): a plain byte-for-byte disk image for Linux (`losetup`,
  `mount -o loop`, `kpartx`, QEMU, ...). Unused space is left as file holes, so it also only
  takes the used size on disk, on any filesystem with sparse file support (ext4, XFS, Btrfs,
  APFS, NTFS).

## Install

Download a prebuilt binary for Windows, Linux or macOS from the
[Releases](https://github.com/Puyodead1/mrimgconv/releases) page, or build from source:

```
cargo build --release
```

Produces `target/release/mrimgconv` (no dependencies).

## Use

```
mrimgconv image.mrimg                # image.vhd on Windows, image.img elsewhere
mrimgconv image.mrimg -o D:\out.vhd
mrimgconv image.mrimg -o out.img     # format follows the extension (.vhd, or .img/.raw/.bin)
mrimgconv image.mrimg -f img         # or pick it explicitly: -f vhd | -f img
mrimgconv image.mrimg --info         # show disks / partitions / used blocks
```

### Linux (raw image)

Attach read-only with partition scanning, then mount the partition you want:

```
sudo losetup -r -P -f --show out.img     # prints e.g. /dev/loop0
sudo mount -o ro /dev/loop0p2 /mnt
```

Unmount with `sudo umount /mnt && sudo losetup -d /dev/loop0`. Keep the image on a filesystem
that supports sparse files, and copy it with `cp --sparse=always` / `rsync -S` so the holes
are preserved.

### Windows (VHD)

Mount read-only (recommended, so nothing on the backup copy changes):

```
Mount-DiskImage -ImagePath D:\out.vhd -Access ReadOnly
```

or double-click the `.vhd`. If the original disk is still attached to the same machine,
Windows may keep the VHD offline because of a disk-ID collision; bring it online in Disk
Management. Unmount with `Dismount-DiskImage -ImagePath D:\out.vhd`.

### Options

`-f vhd|img` (output format), `--disk N` (convert one disk of a multi-disk image), `--no-verify` (skip per-block
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
