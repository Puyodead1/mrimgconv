# Changelog

## [0.1.0] - 2026-10-31

Initial release.

- Convert full Macrium Reflect 8 `.mrimg` images to dynamic VHD (only used 2 MiB blocks are stored).
- `--info` to list disks, partitions and used blocks.
- `--disk N` to convert a single disk of a multi-disk image.
- Per-block MD5 verification (`--no-verify` to skip), `--ignore-errors` to zero-fill corrupt blocks.
- QuickLZ (level 3 + RLE) decompression.
