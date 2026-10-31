import struct, sys, hashlib

LIT = [4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0]


def u32(b, i):
    if i + 4 <= len(b):
        return struct.unpack_from('<I', b, i)[0]
    return 0xFFFFFFFF


def copy_up(out, op, src, n):
    # mirrors sub_4C7F80: dword copies, may overrun by up to 3 bytes
    if n < 5:
        out[op:op + 4] = out[src:src + 4]
        return
    for k in range((n + 3) >> 2):
        out[op + 4 * k:op + 4 * k + 4] = out[src + 4 * k:src + 4 * k + 4]


def qlz_block(blk):
    flags = blk[0]
    hl = 4 if flags & 2 else 1
    csize = int.from_bytes(blk[1:1 + hl], 'little')
    dsize = int.from_bytes(blk[1 + hl:1 + 2 * hl], 'little')
    src = blk[1 + 2 * hl:csize]
    if not flags & 1:
        return bytes(src[:dsize])
    out = bytearray(dsize + 16)
    ip = op = 0
    cword = 1
    limit = dsize - 4
    if dsize <= 4:
        return bytes(src[4:4 + dsize])
    while op < limit:
        if cword == 1:
            cword = u32(src, ip) | 0x80000000
            ip += 4
        f = u32(src, ip)
        if cword & 1:
            cword >>= 1
            if f & 3 == 0:
                off = (f & 0xff) >> 2
                out[op:op + 4] = out[op - off:op - off + 4]; op += 3; ip += 1
            elif f & 2 == 0:
                off = (f & 0xffff) >> 2
                out[op:op + 4] = out[op - off:op - off + 4]; op += 3; ip += 2
            elif f & 1 == 0:
                n = ((f >> 2) & 0xF) + 3; off = (f & 0xffff) >> 6; ip += 2
                copy_up(out, op, op - off, n); op += n
            elif f & 4 == 0:
                off = (f >> 8) & 0xffff; n = ((f & 0xff) >> 3) + 3; ip += 3
                copy_up(out, op, op - off, n); op += n
            elif f & 8 == 0:
                off = f >> 15
                if off:
                    n = ((f >> 4) & 0x7ff) + 3; ip += 4
                else:
                    n = u32(src, ip + 4); off = u32(src, ip + 8); ip += 12
                copy_up(out, op, op - off, n); op += n
            else:
                c = (f >> 16) & 0xff; n = (f & 0xffff) >> 4
                if n:
                    ip += 3
                else:
                    n = u32(src, ip + 3); ip += 7
                out[op:op + n] = bytes([c]) * n; op += n
        else:
            out[op:op + 4] = src[ip:ip + 4]
            n = LIT[cword & 0xF]
            op += n; ip += n; cword >>= n
    while op < dsize:
        if cword == 1:
            ip += 4; cword = 0x80000000
        out[op] = src[ip]; op += 1; ip += 1; cword >>= 1
    return bytes(out[:dsize])


if __name__ == '__main__':
    f = open(sys.argv[1], 'rb')
    for idx in map(int, sys.argv[2:]):
        f.seek(idx)
        rec = f.read(30)
        off, md5, ln = struct.unpack_from('<Q16sI', rec)
        f.seek(off)
        blk = f.read(ln & 0xFFFFFF)
        d = qlz_block(blk)
        print(hex(off), blk[0], len(d), md5.hex(), hashlib.md5(d).hexdigest(), rec[24:].hex(), d[:32].hex())
