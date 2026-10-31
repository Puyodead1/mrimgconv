import struct, sys

class R:
    def __init__(s, f, off):
        s.f = f; f.seek(off)
    def tell(s): return s.f.tell()
    def raw(s, n): return s.f.read(n)
    def u8(s): return s.raw(1)[0]
    def u16(s): return struct.unpack('<H', s.raw(2))[0]
    def u32(s): return struct.unpack('<I', s.raw(4))[0]
    def u64(s): return struct.unpack('<Q', s.raw(8))[0]
    def cstr(s):
        w = 1
        n = s.u8()
        if n == 0xff:
            n = s.u16()
            if n == 0xfffe:
                w = 2
                n = s.u8()
                if n == 0xff:
                    n = s.u16()
            if n == 0xffff:
                n = s.u32()
        b = s.raw(n * w)
        return b.decode('utf-16le' if w == 2 else 'latin-1')

f = open(sys.argv[1], 'rb')
f.seek(-48, 2)
cat = struct.unpack('<Q', f.read(8))[0]
magic = f.read(22); ver = struct.unpack('<H', f.read(2))[0]
print('catalog', cat, 'ver', ver)
r = R(f, cat)
imgid = r.raw(8)
r.u16(); r.u16()
path = r.cstr(); r.u16()
if r.u8():
    r.cstr(); r.cstr(); r.u32(); r.u32()
    for _ in range(r.u32()): r.cstr()
if r.u8(): r.raw(8)
splitsz = r.u64()
hdr = dict(f1452=r.u16(), f12=r.u16(), f1468=r.u32(), f1600lo=r.u16(), f1472=r.u16(), f1604=r.u16(),
           enc=r.u8(), b191=r.u8(), f1600hi=r.u16(), f1480=r.u16())
print(imgid.hex(), path, splitsz, hdr)
xml = r.cstr()
t = r.u32(); r.raw(16)
if r.u8():
    nd = r.u32()
    for d in range(nd):
        dnum = r.u32(); dsig = r.raw(4)
        strs = [r.cstr() for _ in range(5)]
        geom = struct.unpack('<6I', r.raw(24))
        track0 = r.raw(32256)
        r.u32()
        extra = []
        for _ in range(r.u32()):
            sec = r.raw(512); lba = r.u64(); extra.append(lba)
        np_ = r.u32()
        print('disk', dnum, dsig.hex(), strs, geom, 'extra', extra, 'parts', np_)
        for p in range(np_):
            a, b, c = r.u64(), r.u64(), r.u64(); g = r.raw(16)
            p12 = r.raw(12); ch = r.u8(); s1 = r.cstr(); s2 = r.cstr()
            q = [r.u16(), r.u16(), r.u32(), r.u32(), r.u32(), r.u32()]
            q64 = [r.u64() for _ in range(6)]
            q32 = [r.u32() for _ in range(8)]
            m = r.u32()
            for _ in range(m):
                r.u16()
                if ver >= 4: r.cstr(); r.u32()
            f573 = r.u32()
            iu16 = r.u16(); iu64 = r.u64(); iu32 = r.u32(); ih = r.raw(16); n = r.u32()
            idx = r.tell()
            print(f' part {p}: {a} {b} {c} p12={p12.hex()} ch={ch} {s1!r} {s2!r} q={q} q64={q64} q32={q32} m={m} f573={f573}')
            print(f'   index u16={iu16} u64={iu64} u32={iu32} n={n} at {idx}')
            first = r.raw(30 * min(n, 6))
            for i in range(0, len(first), 30): print('    ', first[i:i+30].hex())
            r.f.seek(idx + 30 * n)
print('end', r.tell())
