//! Minimal DER for the two ASN.1 types that are actually decoded.
//!
//! Only `DG1` and `COM` are ever decoded, and both are fixed-shape
//! `APPLICATION`-tagged implicit SEQUENCEs, so a small TLV reader is enough
//! and avoids a generic ASN.1 runtime on a device with 256 KB of RAM.

use alloc::vec::Vec;

use crate::types::{Asn1Error, DataGroup};

/// An ASN.1/DER tag, either one byte or a two-byte form for numbers >= 31
/// (`0x5F <n>`, which is how `[APPLICATION 31]` and `[APPLICATION 54]` encode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    pub first: u8,
    pub second: Option<u8>,
}

impl Tag {
    pub const fn single(first: u8) -> Self {
        Tag {
            first,
            second: None,
        }
    }

    /// `[APPLICATION n]` primitive/implicit tag as it appears on the wire.
    pub const fn application(number: u16) -> Self {
        if number < 31 {
            Tag {
                first: 0x40 | number as u8,
                second: None,
            }
        } else {
            Tag {
                first: 0x5F,
                second: Some(number as u8),
            }
        }
    }

    /// `[APPLICATION n] CONSTRUCTED` (implicit SEQUENCE).
    pub const fn application_constructed(number: u16) -> Self {
        if number < 31 {
            Tag {
                first: 0x60 | number as u8,
                second: None,
            }
        } else {
            Tag {
                first: 0x7F,
                second: Some(number as u8),
            }
        }
    }

    pub const fn number(self) -> u16 {
        match self.second {
            Some(second) => second as u16,
            None => (self.first & 0x1F) as u16,
        }
    }

    pub const fn constructed(self) -> bool {
        self.first & 0x20 != 0
    }

    pub const fn application_class(self) -> bool {
        self.first & 0xC0 == 0x40
    }

    pub fn encoded(self) -> Vec<u8> {
        match self.second {
            Some(second) => Vec::from([self.first, second]),
            None => Vec::from([self.first]),
        }
    }

    pub fn matches(self, other: Self) -> bool {
        self.first == other.first && self.second == other.second
    }
}

/// Parse a tag at the front of `bytes`; returns the tag and its size.
pub fn read_tag(bytes: &[u8]) -> Option<(Tag, usize)> {
    let first = *bytes.first()?;
    if first & 0x1F == 0x1F {
        let second = *bytes.get(1)?;
        Some((
            Tag {
                first,
                second: Some(second),
            },
            2,
        ))
    } else {
        Some((
            Tag {
                first,
                second: None,
            },
            1,
        ))
    }
}

/// Parse a definite DER length; returns the value and the number of length
/// bytes consumed. Indefinite lengths (`0x80`) and forms above two bytes are
/// rejected: eMRTD files here never need them.
pub fn read_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    if first < 0x80 {
        return Some((first as usize, 1));
    }
    match first {
        0x81 => Some((*bytes.get(1)? as usize, 2)),
        0x82 => {
            let hi = *bytes.get(1)? as usize;
            let lo = *bytes.get(2)? as usize;
            Some((hi << 8 | lo, 3))
        }
        // 0x80 (indefinite) and multi-byte lengths are not used by eMRTD files
        // of this size.
        _ => None,
    }
}

/// Length value from up to three bytes of length encoding; 0 when unsupported.
pub fn der_length(data: &[u8]) -> usize {
    read_length(data).map(|(len, _)| len).unwrap_or(0)
}

/// How many bytes the length encoding occupies; 0 when unsupported.
pub fn length_of_length(data: &[u8]) -> usize {
    read_length(data).map(|(_, size)| size).unwrap_or(0)
}

/// One TLV triple.
#[derive(Debug, Clone, Copy)]
pub struct Element<'a> {
    pub tag: Tag,
    pub value: &'a [u8],
    /// Offset of the tag within the buffer that was parsed.
    pub offset: usize,
}

/// Read the first TLV element of `bytes`.
pub fn read_element(bytes: &[u8]) -> Option<(Element<'_>, usize)> {
    let (tag, tag_len) = read_tag(bytes)?;
    let (value_len, len_len) = read_length(bytes.get(tag_len..)?)?;
    let start = tag_len + len_len;
    let value = bytes.get(start..start.checked_add(value_len)?)?;
    Some((
        Element {
            tag,
            value,
            offset: 0,
        },
        start + value_len,
    ))
}

/// Iterator over top-level elements, like asn1c's `constr_SEQUENCE` walker but
/// without the recursion.
#[derive(Debug, Clone)]
pub struct Elements<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Elements<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl<'a> Iterator for Elements<'a> {
    type Item = Element<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let rest = self.bytes.get(self.offset..)?;
        if rest.is_empty() {
            return None;
        }
        let (mut element, consumed) = read_element(rest)?;
        element.offset = self.offset;
        self.offset += consumed;
        Some(element)
    }
}

/// Total size of a data-group file from its first bytes.
///
/// Computed from a 4-byte header: tag + length encoding + value. Returns `None` when the encoding is not supported.
pub fn file_total_size(header: &[u8]) -> Option<usize> {
    let tag_len = read_tag(header)?.1;
    let (value_len, len_len) = read_length(header.get(tag_len..)?)?;
    Some(tag_len + len_len + value_len)
}

/// `EF.COM` (ICAO Doc 9303 Part 10, `COM ::= [APPLICATION 0]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Com {
    /// LDS version bytes (`[APPLICATION 1]`), e.g. `01 00 05 00`.
    pub lds_version: Vec<u8>,
    /// Unicode version bytes (`[APPLICATION 54]`).
    pub unicode_version: Vec<u8>,
    /// Raw tag bitmap from `[APPLICATION 28]`, one byte per present data group.
    pub data_groups: Vec<u8>,
}

impl Com {
    /// Tag numbers for the data groups the card announced, in announcement
    /// order, skipping tags that cannot be read (DG16, SOD, issuer data).
    pub fn data_group_list(&self) -> Vec<DataGroup> {
        let mut groups: Vec<DataGroup> = Vec::new();
        for tag in &self.data_groups {
            if let Some(group) = DataGroup::from_tag_byte(*tag)
                && !groups.contains(&group)
            {
                groups.push(group);
            }
        }
        groups
    }
}

/// Decode `EF.COM`.
pub fn parse_com(bytes: &[u8]) -> Result<Com, Asn1Error> {
    let outer_tag = Tag::application_constructed(0);
    let (outer, _) = read_element(bytes).ok_or(Asn1Error::Truncated)?;
    if !outer.tag.matches(outer_tag) {
        return Err(Asn1Error::UnexpectedTag {
            expected: outer_tag.first,
            found: outer.tag.first,
        });
    }

    let mut lds_version = Vec::new();
    let mut unicode_version = Vec::new();
    let mut data_groups = Vec::new();
    for element in Elements::new(outer.value) {
        match element.tag.number() {
            1 => lds_version = element.value.to_vec(),
            54 => unicode_version = element.value.to_vec(),
            28 => data_groups = element.value.to_vec(),
            // `optionalUsages` / `authenticationMethods` are not used.
            _ => {}
        }
    }

    if data_groups.is_empty() {
        return Err(Asn1Error::NoDataGroups);
    }

    Ok(Com {
        lds_version,
        unicode_version,
        data_groups,
    })
}

/// Decode `DG1` (`[APPLICATION 1] IMPLICIT SEQUENCE { mrz [APPLICATION 31] }`)
/// and return the MRZ bytes.
pub fn parse_dg1(bytes: &[u8]) -> Result<&[u8], Asn1Error> {
    let (outer, _) = read_element(bytes).ok_or(Asn1Error::Truncated)?;
    let expected = Tag::application_constructed(1);
    if !outer.tag.matches(expected) {
        return Err(Asn1Error::UnexpectedTag {
            expected: expected.first,
            found: outer.tag.first,
        });
    }
    for element in Elements::new(outer.value) {
        if element.tag.matches(Tag::application(31)) {
            return Ok(element.value);
        }
    }
    Err(Asn1Error::MissingMrz)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_encode_and_decode() {
        assert_eq!(Tag::application(1).first, 0x41);
        assert_eq!(Tag::application_constructed(1).first, 0x61);
        assert_eq!(Tag::application_constructed(0).first, 0x60);

        let mrz = Tag::application(31);
        assert_eq!((mrz.first, mrz.second), (0x5F, Some(31)));
        assert_eq!(mrz.encoded(), [0x5F, 31]);
        assert_eq!(mrz.number(), 31);
        assert!(!mrz.constructed() && mrz.application_class());

        let seq = Tag::application_constructed(31);
        assert_eq!((seq.first, seq.second), (0x7F, Some(31)));
        assert!(seq.constructed());

        assert_eq!(Tag::single(0x30).encoded(), [0x30]);
        assert_eq!(Tag::application(2).number(), 2);
        assert!(Tag::application(2).matches(Tag::application(2)));
        assert!(!Tag::application(2).matches(Tag::application(3)));
    }

    #[test]
    fn read_tag_handles_one_and_two_byte_forms() {
        assert_eq!(
            read_tag(&[0x61, 0x00]).map(|(t, n)| (t.first, n)),
            Some((0x61, 1))
        );
        let (tag, size) = read_tag(&[0x5F, 0x1F, 0x00]).unwrap();
        assert_eq!((tag.second, size), (Some(0x1F), 2));
        assert!(read_tag(&[]).is_none());
        assert!(read_tag(&[0x5F]).is_none(), "second tag byte missing");
    }

    #[test]
    fn lengths_in_all_supported_forms() {
        assert_eq!(read_length(&[0x00]), Some((0, 1)));
        assert_eq!(read_length(&[0x7F]), Some((127, 1)));
        assert_eq!(read_length(&[0x81, 0x80]), Some((128, 2)));
        assert_eq!(read_length(&[0x82, 0x01, 0x00]), Some((256, 3)));
        assert_eq!(der_length(&[0x82, 0x12, 0x34]), 0x1234);
        assert_eq!(length_of_length(&[0x82, 0x12, 0x34]), 3);
    }

    #[test]
    fn unsupported_or_truncated_lengths_are_rejected() {
        assert_eq!(read_length(&[]), None);
        assert_eq!(read_length(&[0x80]), None, "indefinite");
        assert_eq!(read_length(&[0x83, 1, 2, 3]), None);
        assert_eq!(read_length(&[0x81]), None);
        assert_eq!(read_length(&[0x82, 0x01]), None);
        assert_eq!((der_length(&[0x80]), length_of_length(&[0x80])), (0, 0));
    }

    #[test]
    fn file_size_includes_tag_and_length_bytes() {
        assert_eq!(file_total_size(&[0x61, 0x5B, 0x5F, 0x1F]), Some(2 + 0x5B));
        assert_eq!(
            file_total_size(&[0x75, 0x82, 0x01, 0x00]),
            Some(1 + 3 + 256)
        );
        assert_eq!(
            file_total_size(&[0x7F, 0x61, 0x81, 0x90]),
            Some(2 + 2 + 0x90)
        );
        assert_eq!(file_total_size(&[0x75, 0x83]), None);
        assert_eq!(file_total_size(&[]), None);
    }

    #[test]
    fn element_walker_stops_at_truncation() {
        let bytes = [0x41, 0x01, 0xAA, 0x42, 0x05, 0x01];
        let found: Vec<_> = Elements::new(&bytes)
            .map(|e| (e.tag.first, e.value.len(), e.offset))
            .collect();
        assert_eq!(found, [(0x41, 1, 0)]);
        assert!(read_element(&[0x41, 0x05, 0x00]).is_none());
        assert_eq!(Elements::new(&[]).count(), 0);
    }

    #[test]
    fn com_decodes_versions_and_groups() {
        let com = [
            0x60, 0x14, 0x5F, 0x01, 0x04, 0x30, 0x31, 0x30, 0x37, 0x5F, 0x36, 0x06, 0x30, 0x34,
            0x30, 0x30, 0x30, 0x30, 0x5C, 0x02, 0x61, 0x75,
        ];
        let parsed = parse_com(&com).unwrap();
        assert_eq!(parsed.lds_version, b"0107");
        assert_eq!(parsed.unicode_version, b"040000");
        assert_eq!(parsed.data_groups, [0x61, 0x75]);
    }

    #[test]
    fn com_group_list_skips_unreadable_tags_and_duplicates() {
        let com = Com {
            lds_version: Vec::new(),
            unicode_version: Vec::new(),
            data_groups: vec![0x61, 0x75, 0x61, 0x77, 0x70, 0x6B],
        };
        assert_eq!(
            com.data_group_list(),
            [DataGroup::Dg1, DataGroup::Dg2, DataGroup::Dg11]
        );
    }

    #[test]
    fn com_errors() {
        assert_eq!(parse_com(&[]), Err(Asn1Error::Truncated));
        assert_eq!(
            parse_com(&[0x61, 0x00]),
            Err(Asn1Error::UnexpectedTag {
                expected: 0x60,
                found: 0x61
            })
        );
        assert_eq!(parse_com(&[0x60, 0x00]), Err(Asn1Error::NoDataGroups));
    }

    #[test]
    fn dg1_returns_the_mrz_octets() {
        let mut dg1 = vec![0x61, 0x07, 0x5F, 0x1F, 0x04];
        dg1.extend_from_slice(b"ABCD");
        assert_eq!(parse_dg1(&dg1), Ok(&b"ABCD"[..]));
    }

    #[test]
    fn dg1_errors() {
        assert_eq!(parse_dg1(&[]), Err(Asn1Error::Truncated));
        assert_eq!(
            parse_dg1(&[0x60, 0x00]),
            Err(Asn1Error::UnexpectedTag {
                expected: 0x61,
                found: 0x60
            })
        );
        assert_eq!(
            parse_dg1(&[0x61, 0x02, 0x01, 0x00]),
            Err(Asn1Error::MissingMrz)
        );
    }
}
