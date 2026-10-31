import struct, sys, zlib
f = open(sys.argv[1], 'rb')
f.seek(-512, 2); foot = f.read(512)
f.seek(0); foot0 = f.read(512); dh = f.read(1024)
def ck(b, at):
    z = bytearray(b); z[at:at+4] = b'\0\0\0\0'
    return (~sum(z)) & 0xffffffff == struct.unpack_from('>I', b, at)[0]
print('footer cookie', foot[:8], 'copy match', foot == foot0, 'ck', ck(foot, 64), 'type', struct.unpack_from('>I', foot, 60)[0])
size = struct.unpack_from('>Q', foot, 48)[0]
tab = struct.unpack_from('>Q', dh, 16)[0]; n = struct.unpack_from('>I', dh, 28)[0]; bs = struct.unpack_from('>I', dh, 32)[0]
print('dyn', dh[:8], 'ck', ck(dh, 36), 'size', size, 'entries', n, 'bs', bs)
f.seek(tab); bat = struct.unpack('>%dI' % n, f.read(4 * n))
print('allocated', sum(1 for e in bat if e != 0xffffffff))
def rd(off, ln):
    out = bytearray()
    while ln:
        i, inner = divmod(off, bs); k = min(ln, bs - inner)
        e = bat[i]
        if e == 0xffffffff: out += bytes(k)
        else: f.seek(e * 512 + 512 + inner); out += f.read(k)
        off += k; ln -= k
    return bytes(out)
hdr = rd(512, 512); print('primary GPT', hdr[:8], 'alt lba', struct.unpack_from('<Q', hdr, 32)[0])
alt = struct.unpack_from('<Q', hdr, 32)[0]
bh = rd(alt * 512, 512); hs = struct.unpack_from('<I', bh, 12)[0]
z = bytearray(bh[:hs]); crc = struct.unpack_from('<I', z, 16)[0]; z[16:20] = bytes(4)
print('backup GPT', bh[:8], 'crc ok', zlib.crc32(z) == crc, 'entries crc ok', zlib.crc32(rd(struct.unpack_from('<Q', bh, 72)[0]*512, 128*128)) == struct.unpack_from('<I', bh, 88)[0])
ents = rd(1024, 128 * 128)
for i in range(4):
    e = ents[i*128:(i+1)*128]; first, last = struct.unpack_from('<QQ', e, 32)
    name = e[56:128].decode('utf-16le').rstrip('\0')
    boot = rd(first * 512, 512)
    print(f' part {i}: lba {first}-{last} {name!r} boot oem {boot[3:11]!r}')
    if boot[3:11] == b'NTFS    ':
        bps, spc = struct.unpack_from('<HB', boot, 11); mft = struct.unpack_from('<Q', boot, 48)[0]
        cl = bps * spc; base = first * 512 + mft * cl
        names = []; bad = 0
        blob = rd(base, 1024 * 64)
        for rec in range(64):
            r = bytearray(blob[rec*1024:(rec+1)*1024])
            if r[:4] != b'FILE': bad += 1; continue
            usa, usn = struct.unpack_from('<HH', r, 4)
            for k in range(1, usn): r[k*512-2:k*512] = r[usa+2*k:usa+2*k+2]
            a = struct.unpack_from('<H', r, 20)[0]
            while a < 1024 - 8:
                t, ln = struct.unpack_from('<II', r, a)
                if t == 0xffffffff or ln == 0: break
                if t == 0x30:
                    vo = struct.unpack_from('<H', r, a + 20)[0]; v = a + vo
                    nl = r[v + 64]; names.append(r[v+66:v+66+2*nl].decode('utf-16le')); break
                a += ln
        print(f'    first 64 MFT records: {64-bad} valid; names: {names[:40]}')
