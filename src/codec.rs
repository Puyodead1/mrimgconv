//! Block decompressors, ported from MRVerify.exe.
//!
//! Every compressed block carries a QuickLZ-style header (sub_4C7E30):
//!   flags u8 (bit0 = compressed, bit1 = 4-byte size fields), stored size, raw size.
//! Compressed payloads use a QuickLZ level-3 variant (sub_4C61C0) with an extra RLE op.
//! Blocks whose index record selects the other codec are raw LZO-style streams
//! (sub_4C79A0) without that header.

pub type Result<T> = std::result::Result<T, String>;

const LIT_TABLE: [usize; 16] = [4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0];

#[inline]
fn rd32(b: &[u8], i: usize) -> u32 {
    match b.get(i..i + 4) {
        Some(s) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
        None => u32::MAX,
    }
}

/// Decode a block with a QuickLZ header into `out` (cleared and resized to the raw size).
pub fn qlz_decompress(blk: &[u8], out: &mut Vec<u8>, max_out: usize) -> Result<()> {
    if blk.is_empty() {
        return Err("empty block".into());
    }
    let flags = blk[0];
    let hl = if flags & 2 != 0 { 4 } else { 1 };
    if blk.len() < 1 + 2 * hl {
        return Err("block header truncated".into());
    }
    let field = |i: usize| -> usize {
        let mut v = 0usize;
        for k in 0..hl {
            v |= (blk[i + k] as usize) << (8 * k);
        }
        v
    };
    let csize = field(1);
    let dsize = field(1 + hl);
    if dsize > max_out {
        return Err(format!("raw size {dsize} exceeds block size {max_out}"));
    }
    if csize > blk.len() || csize < 1 + 2 * hl {
        return Err("stored size out of range".into());
    }
    out.clear();
    if flags & 1 == 0 {
        if csize - (1 + 2 * hl) < dsize {
            return Err("stored block truncated".into());
        }
        out.extend_from_slice(&blk[1 + 2 * hl..1 + 2 * hl + dsize]);
        return Ok(());
    }
    // Pad the source so 4-byte fetches near the end stay in bounds.
    let mut src = Vec::with_capacity(csize + 16);
    src.extend_from_slice(&blk[1 + 2 * hl..csize]);
    let slen = src.len();
    src.resize(slen + 16, 0);
    out.resize(dsize + 16, 0);
    let o = &mut out[..];

    if dsize <= 4 {
        if slen < 4 + dsize {
            return Err("tiny block truncated".into());
        }
        o[..dsize].copy_from_slice(&src[4..4 + dsize]);
        out.truncate(dsize);
        return Ok(());
    }

    let limit = dsize - 4;
    let mut ip = 0usize;
    let mut op = 0usize;
    let mut cword: u32 = 1;
    let err = || Err::<(), String>("corrupt QuickLZ stream".into());

    // Overlapping forward copy in 4-byte steps, exactly like sub_4C7F80.
    fn copy_up(o: &mut [u8], op: usize, from: usize, n: usize) {
        if n < 5 {
            let t = [o[from], o[from + 1], o[from + 2], o[from + 3]];
            o[op..op + 4].copy_from_slice(&t);
            return;
        }
        let words = (n + 3) >> 2;
        for k in 0..words {
            let s = from + 4 * k;
            let t = [o[s], o[s + 1], o[s + 2], o[s + 3]];
            o[op + 4 * k..op + 4 * k + 4].copy_from_slice(&t);
        }
    }

    while op < limit {
        if cword == 1 {
            cword = rd32(&src[..slen], ip) | 0x8000_0000;
            ip += 4;
        }
        let f = rd32(&src[..slen], ip);
        if cword & 1 != 0 {
            cword >>= 1;
            if f & 3 == 0 {
                let off = ((f & 0xff) >> 2) as usize;
                if off > op || off == 0 || limit - op < 3 {
                    return err();
                }
                copy_up(o, op, op - off, 3);
                op += 3;
                ip += 1;
            } else if f & 2 == 0 {
                let off = ((f & 0xffff) >> 2) as usize;
                if off > op || off == 0 || limit - op < 3 {
                    return err();
                }
                copy_up(o, op, op - off, 3);
                op += 3;
                ip += 2;
            } else {
                let (n, off, fill);
                if f & 1 == 0 {
                    n = (((f >> 2) & 0xF) + 3) as usize;
                    off = ((f & 0xffff) >> 6) as usize;
                    fill = None;
                    ip += 2;
                } else if f & 4 == 0 {
                    off = ((f >> 8) & 0xffff) as usize;
                    n = (((f & 0xff) >> 3) + 3) as usize;
                    fill = None;
                    ip += 3;
                } else if f & 8 == 0 {
                    if f >> 15 != 0 {
                        off = (f >> 15) as usize;
                        n = (((f >> 4) & 0x7ff) + 3) as usize;
                        ip += 4;
                    } else {
                        n = rd32(&src[..slen], ip + 4) as usize;
                        off = rd32(&src[..slen], ip + 8) as usize;
                        ip += 12;
                    }
                    fill = None;
                } else {
                    let c = ((f >> 16) & 0xff) as u8;
                    let mut k = ((f & 0xffff) >> 4) as usize;
                    if k != 0 {
                        ip += 3;
                    } else {
                        k = rd32(&src[..slen], ip + 3) as usize;
                        ip += 7;
                    }
                    n = k;
                    off = 0;
                    fill = Some(c);
                }
                if n > limit - op {
                    return err();
                }
                match fill {
                    Some(c) => o[op..op + n].fill(c),
                    None => {
                        if off > op || off == 0 {
                            return err();
                        }
                        copy_up(o, op, op - off, n);
                    }
                }
                op += n;
            }
        } else {
            if dsize - op < 4 || ip > slen + 4 {
                return err();
            }
            let t = [src[ip], src[ip + 1], src[ip + 2], src[ip + 3]];
            o[op..op + 4].copy_from_slice(&t);
            let n = LIT_TABLE[(cword & 0xF) as usize];
            op += n;
            ip += n;
            cword >>= n;
        }
    }
    while op < dsize {
        if cword == 1 {
            ip += 4;
            cword = 0x8000_0000;
        }
        if ip >= slen {
            return err();
        }
        o[op] = src[ip];
        op += 1;
        ip += 1;
        cword >>= 1;
    }
    out.truncate(dsize);
    Ok(())
}

/// LZO-style decompressor used for blocks whose record does not select QuickLZ
/// (port of sub_4C79A0; returns Ok on the end marker, trailing input is tolerated).
pub fn lzo_decompress(src: &[u8], out: &mut Vec<u8>, max_out: usize) -> Result<()> {
    out.clear();
    let end = src.len();
    let mut ip = 0usize;
    let err = |m: &str| Err::<(), String>(format!("corrupt LZO stream: {m}"));

    macro_rules! need_out {
        ($n:expr) => {
            if out.len() + $n > max_out {
                return err("output overrun");
            }
        };
    }

    #[derive(Clone, Copy)]
    enum St {
        Top,
        AfterLit,
    }
    let mut st = St::Top;
    loop {
        match st {
            St::Top => {
                if ip >= end {
                    return err("eof not found");
                }
                let t = src[ip] as usize;
                ip += 1;
                if t >= 0x20 {
                    match_op(src, &mut ip, out, max_out, t, &mut st)?;
                    continue;
                }
                let run = if t != 0 {
                    t
                } else {
                    if ip >= end {
                        return err("input overrun");
                    }
                    let v = src[ip] as usize;
                    ip += 1;
                    if v >= 0xF8 {
                        let k = v - 248;
                        let len = if k == 0 { 280 } else { 256usize << k };
                        if end - ip < len {
                            return err("input overrun");
                        }
                        need_out!(len);
                        out.extend_from_slice(&src[ip..ip + len]);
                        ip += len;
                        continue;
                    }
                    v + 32
                };
                if end - ip < run {
                    return err("input overrun");
                }
                need_out!(run);
                out.extend_from_slice(&src[ip..ip + run]);
                ip += run;
                st = St::AfterLit;
            }
            St::AfterLit => {
                if ip >= end {
                    return err("eof not found");
                }
                let t = src[ip] as usize;
                ip += 1;
                if t >= 0x20 {
                    match_op(src, &mut ip, out, max_out, t, &mut st)?;
                    continue;
                }
                if end - ip < 2 {
                    return err("input overrun");
                }
                let dist = t | ((src[ip] as usize) << 5);
                let op = out.len();
                if dist + 1 > op {
                    return err("lookbehind overrun");
                }
                let m = op - dist - 1;
                need_out!(4);
                let (a, b, c) = (out[m], out[m + 1], out[m + 2]);
                out.extend_from_slice(&[a, b, c, src[ip + 1]]);
                ip += 2;
            }
        }
    }

    fn match_op(
        src: &[u8],
        ip: &mut usize,
        out: &mut Vec<u8>,
        max_out: usize,
        t: usize,
        st: &mut St,
    ) -> Result<()> {
        let end = src.len();
        let e = |m: &str| Err::<(), String>(format!("corrupt LZO stream: {m}"));
        if t >= 0x40 {
            if *ip >= end {
                return e("input overrun");
            }
            let dist = (t & 0x1f) | ((src[*ip] as usize) << 5);
            *ip += 1;
            let op = out.len();
            if dist + 1 > op {
                return e("lookbehind overrun");
            }
            let m = op - dist - 1;
            let n = 2 + (t >> 5) - 1;
            if out.len() + n > max_out {
                return e("output overrun");
            }
            for k in 0..n {
                let b = out[m + k];
                out.push(b);
            }
            *st = St::Top;
            return Ok(());
        }
        let mut len = t & 0x1f;
        if len == 0 {
            if *ip >= end {
                return e("input overrun");
            }
            while src[*ip] == 0 {
                *ip += 1;
                len += 255;
                if *ip >= end {
                    return e("input overrun");
                }
            }
            len += src[*ip] as usize + 31;
            *ip += 1;
        }
        if end - *ip < 2 {
            return e("input overrun");
        }
        let b0 = src[*ip] as usize;
        let dist = (b0 & 0x3f) + ((src[*ip + 1] as usize) << 6);
        *ip += 2;
        let op = out.len();
        if dist == 0 {
            // end-of-stream marker
            return Err(String::new());
        }
        if dist > op {
            return e("lookbehind overrun");
        }
        let m = op - dist;
        let n = len + 3;
        if out.len() + n > max_out {
            return e("output overrun");
        }
        for k in 0..n {
            let b = out[m + k];
            out.push(b);
        }
        let trail = b0 >> 6;
        if trail != 0 {
            if end - *ip < trail {
                return e("input overrun");
            }
            if out.len() + trail > max_out {
                return e("output overrun");
            }
            out.extend_from_slice(&src[*ip..*ip + trail]);
            *ip += trail;
            *st = St::AfterLit;
        } else {
            *st = St::Top;
        }
        Ok(())
    }
}

/// Wrapper turning the end-marker sentinel (empty error string) into success.
pub fn lzo_decompress_block(src: &[u8], out: &mut Vec<u8>, max_out: usize) -> Result<()> {
    match lzo_decompress(src, out, max_out) {
        Err(e) if e.is_empty() => Ok(()),
        r => r,
    }
}
