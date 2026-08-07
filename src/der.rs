//! DER (ASN.1) minimal parser for PKCS#15 structures.

#[derive(Clone, Copy)]
pub struct DerTlv<'a> {
    pub tag: u32,
    pub hdr_len: usize,
    pub val: &'a [u8],
}

impl<'a> DerTlv<'a> {
    pub fn full_slice(&self, base: &'a [u8]) -> &'a [u8] {
        let start = self.val.as_ptr() as usize - base.as_ptr() as usize - self.hdr_len;
        &base[start..start + self.hdr_len + self.val.len()]
    }
}

pub fn next<'a>(data: &'a [u8], mut off: usize) -> Result<(DerTlv<'a>, usize), ()> {
    if off >= data.len() {
        return Err(());
    }
    let tag_start = off;
    let mut tag = data[off] as u32;
    off += 1;
    let mut hdr = 1usize;
    if (tag & 0x1F) == 0x1F {
        if off >= data.len() {
            return Err(());
        }
        tag = (tag << 8) | data[off] as u32;
        off += 1;
        hdr += 1;
    }
    if off >= data.len() {
        return Err(());
    }
    let len = if data[off] & 0x80 != 0 {
        let n = (data[off] & 0x7F) as usize;
        off += 1;
        hdr += 1;
        if n == 0 || n > 4 || off + n > data.len() {
            return Err(());
        }
        let mut l = 0usize;
        for i in 0..n {
            l = (l << 8) | data[off + i] as usize;
            hdr += 1;
        }
        off += n;
        l
    } else {
        hdr += 1;
        let l = data[off] as usize;
        off += 1;
        l
    };
    if off + len > data.len() {
        return Err(());
    }
    let val = &data[off..off + len];
    off += len;
    let _ = tag_start;
    Ok((
        DerTlv {
            tag,
            hdr_len: hdr,
            val,
        },
        off,
    ))
}

pub fn get_bytes<'a>(t: &'a DerTlv<'a>) -> Result<&'a [u8], ()> {
    if t.tag == 0x03 {
        if t.val.is_empty() {
            return Err(());
        }
        Ok(&t.val[1..])
    } else {
        Ok(t.val)
    }
}

pub fn enter<'a>(t: &'a DerTlv<'a>) -> Result<&'a [u8], ()> {
    if t.tag & 0x20 == 0 {
        return Err(());
    }
    Ok(t.val)
}
