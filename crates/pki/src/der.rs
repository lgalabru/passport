//! Just enough DER: a reader that keeps every element's position in its
//! source (the enrollment circuit needs byte offsets, and a signature covers
//! the bytes as sent, not a re-encoding), and a writer for the fixtures.

use crate::{Error, Result};

/// One element: its tag, where it sits in the outermost buffer, and its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The tag bytes, `0x30` or `0x5F1F` style, as a number.
    pub tag: u32,
    /// The whole element, tag through value.
    pub raw: &'a [u8],
    pub value: &'a [u8],
    /// Offset of `raw` in the buffer the reader started from.
    pub offset: usize,
    /// Length of tag plus length bytes.
    pub header: usize,
}

impl<'a> Tlv<'a> {
    /// Offset of `value` in the outermost buffer.
    pub fn value_offset(&self) -> usize {
        self.offset + self.header
    }

    /// The elements inside a constructed value.
    pub fn children(&self) -> Reader<'a> {
        Reader {
            buf: self.value,
            pos: 0,
            base: self.value_offset(),
        }
    }

    pub fn expect(self, tag: u32) -> Result<Self> {
        if self.tag == tag {
            Ok(self)
        } else {
            Err(Error::Malformed(format!(
                "expected tag {tag:#x}, found {:#x} at {}",
                self.tag, self.offset
            )))
        }
    }

    /// A non-negative INTEGER that fits a `u64`.
    pub fn small_uint(&self) -> Result<u64> {
        self.expect_tag(0x02)?;
        let v = self.value;
        if v.is_empty() || v.len() > 9 || (v.len() == 9 && v[0] != 0) || v[0] & 0x80 != 0 {
            return Err(Error::Malformed("integer out of range".into()));
        }
        Ok(v.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64))
    }

    fn expect_tag(&self, tag: u32) -> Result<()> {
        self.expect(tag).map(|_| ())
    }
}

/// Reads consecutive elements from a buffer.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    base: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            base: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// The next element without consuming it.
    pub fn peek(&self) -> Result<Option<Tlv<'a>>> {
        self.clone().next_tlv()
    }

    pub fn next_tlv(&mut self) -> Result<Option<Tlv<'a>>> {
        if self.is_empty() {
            return Ok(None);
        }
        let start = self.pos;
        let b = self.buf;
        let short = || Error::Malformed(format!("truncated element at {}", self.base + start));
        let mut i = start;
        let first = *b.get(i).ok_or_else(short)?;
        let mut tag = first as u32;
        i += 1;
        if first & 0x1F == 0x1F {
            loop {
                let t = *b.get(i).ok_or_else(short)?;
                if tag > 0x00FF_FFFF {
                    return Err(Error::Malformed("tag too long".into()));
                }
                tag = (tag << 8) | t as u32;
                i += 1;
                if t & 0x80 == 0 {
                    break;
                }
            }
        }
        let l0 = *b.get(i).ok_or_else(short)?;
        i += 1;
        let len = if l0 < 0x80 {
            l0 as usize
        } else {
            let n = (l0 & 0x7F) as usize;
            if n == 0 || n > 4 {
                return Err(Error::Malformed("indefinite or oversized length".into()));
            }
            let bytes = b.get(i..i + n).ok_or_else(short)?;
            i += n;
            let len = bytes.iter().fold(0usize, |acc, &x| (acc << 8) | x as usize);
            // DER: the shortest form.
            if len < 0x80 || bytes[0] == 0 {
                return Err(Error::Malformed("non-minimal length".into()));
            }
            len
        };
        let end = i.checked_add(len).ok_or_else(short)?;
        let value = b.get(i..end).ok_or_else(short)?;
        self.pos = end;
        Ok(Some(Tlv {
            tag,
            raw: &b[start..end],
            value,
            offset: self.base + start,
            header: i - start,
        }))
    }

    /// The next element, which must be there.
    pub fn take(&mut self) -> Result<Tlv<'a>> {
        self.next_tlv()?
            .ok_or_else(|| Error::Malformed("missing element".into()))
    }

    /// The next element if it has `tag`.
    pub fn take_if(&mut self, tag: u32) -> Result<Option<Tlv<'a>>> {
        match self.peek()? {
            Some(t) if t.tag == tag => self.next_tlv(),
            _ => Ok(None),
        }
    }

    pub fn finish(&self) -> Result<()> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed(format!(
                "trailing data at {}",
                self.base + self.pos
            )))
        }
    }
}

/// Parses exactly one element spanning `buf`.
pub fn parse(buf: &[u8]) -> Result<Tlv<'_>> {
    let mut r = Reader::new(buf);
    let t = r.take()?;
    r.finish()?;
    Ok(t)
}

// ---- writer ----

/// `tag || length || value`.
pub fn tlv(tag: u32, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 8);
    for shift in [24u32, 16, 8] {
        let byte = (tag >> shift) as u8;
        if byte != 0 || !out.is_empty() {
            out.push(byte);
        }
    }
    out.push(tag as u8);
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(value);
    out
}

pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

pub fn set(parts: &[&[u8]]) -> Vec<u8> {
    // DER orders SET OF by encoding.
    let mut sorted: Vec<&[u8]> = parts.to_vec();
    sorted.sort();
    tlv(0x31, &sorted.concat())
}

pub fn uint(value: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = value.iter().copied().skip_while(|&b| b == 0).collect();
    if v.is_empty() || v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    tlv(0x02, &v)
}

pub fn small(n: u64) -> Vec<u8> {
    uint(&n.to_be_bytes())
}

pub fn octets(v: &[u8]) -> Vec<u8> {
    tlv(0x04, v)
}

/// `[n] EXPLICIT`.
pub fn explicit(n: u8, inner: &[u8]) -> Vec<u8> {
    tlv(0xA0 | n as u32, inner)
}

pub fn null() -> Vec<u8> {
    vec![0x05, 0x00]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_short_and_long_forms() {
        for len in [0usize, 1, 127, 128, 255, 256, 70_000] {
            let value = vec![0xAB; len];
            let enc = tlv(0x04, &value);
            let t = parse(&enc).unwrap();
            assert_eq!((t.tag, t.value.len(), t.raw.len()), (0x04, len, enc.len()));
        }
        let enc = tlv(0x5F1F, b"abc");
        let t = parse(&enc).unwrap();
        assert_eq!((t.tag, t.value), (0x5F1F, &b"abc"[..]));
    }

    #[test]
    fn offsets_are_absolute() {
        let inner = seq(&[&octets(b"xy"), &small(5)]);
        let outer = tlv(0x77, &inner);
        let t = parse(&outer).unwrap();
        let s = t.children().take().unwrap();
        let mut c = s.children();
        let o = c.take().unwrap();
        assert_eq!(&outer[o.value_offset()..o.value_offset() + 2], b"xy");
        assert_eq!(c.take().unwrap().small_uint().unwrap(), 5);
        c.finish().unwrap();
    }

    #[test]
    fn rejects_what_der_forbids() {
        assert!(
            parse(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5]).is_err(),
            "long form for < 128"
        );
        assert!(parse(&[0x04, 0x80]).is_err(), "indefinite length");
        assert!(parse(&[0x04, 0x05, 1, 2]).is_err(), "truncated");
        assert!(parse(&[0x04, 0x01, 1, 0]).is_err(), "trailing data");
        assert!(
            parse(&[0x02, 0x01, 0x80]).unwrap().small_uint().is_err(),
            "negative"
        );
    }

    #[test]
    fn integers_are_minimal_and_positive() {
        assert_eq!(uint(&[0x00, 0x00, 0x7F]), vec![0x02, 0x01, 0x7F]);
        assert_eq!(uint(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(uint(&[]), vec![0x02, 0x01, 0x00]);
    }
}
