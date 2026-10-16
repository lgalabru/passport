//! Sniffing the compressed image inside a biometric data group (DG2 / DG7).

use core::fmt;

/// Compressed image encoding found in DG2 / DG7, with the extension used when
/// naming the saved file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    /// `FF D8 FF E0` — JFIF.
    Jpeg,
    /// `00 00 00 0C 6A 50` — JPEG 2000 codestream with JP2 header.
    Jpeg2000,
    /// `FF 4F FF 51` — raw JPEG 2000 codestream.
    Jpeg2000Cs,
    /// Nothing recognised: dump the raw data group.
    Raw,
}

impl ImageFormat {
    /// Magic bytes searched for, in detection precedence order.
    pub fn magic(self) -> &'static [u8] {
        match self {
            ImageFormat::Jpeg => &[0xFF, 0xD8, 0xFF, 0xE0],
            ImageFormat::Jpeg2000 => &[0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50],
            ImageFormat::Jpeg2000Cs => &[0xFF, 0x4F, 0xFF, 0x51],
            ImageFormat::Raw => &[],
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            ImageFormat::Jpeg => "jpeg",
            ImageFormat::Jpeg2000 => "jp2",
            ImageFormat::Jpeg2000Cs => "jpc",
            ImageFormat::Raw => "bin",
        }
    }

    /// The format a saved file's extension names (`jpeg`, `jp2`, `jpc`, `bin`).
    pub fn from_extension(extension: &str) -> Option<Self> {
        [
            ImageFormat::Jpeg,
            ImageFormat::Jpeg2000,
            ImageFormat::Jpeg2000Cs,
            ImageFormat::Raw,
        ]
        .into_iter()
        .find(|format| format.extension() == extension)
    }

    /// Extension including the dot.
    pub fn dotted_extension(self) -> &'static str {
        match self {
            ImageFormat::Jpeg => ".jpeg",
            ImageFormat::Jpeg2000 => ".jp2",
            ImageFormat::Jpeg2000Cs => ".jpc",
            ImageFormat::Raw => ".bin",
        }
    }
}

impl fmt::Display for ImageFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ImageFormat::Jpeg => "JPEG",
            ImageFormat::Jpeg2000 => "JPEG2000",
            ImageFormat::Jpeg2000Cs => "JPEG2000-CS",
            ImageFormat::Raw => "raw",
        })
    }
}

/// First index of `needle` in `haystack`.
pub fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    // Naive scan is fine at 120-byte look-aheads and avoids a memchr dependency.
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Detect the image encoding inside a look-ahead buffer.
///
/// Returns the format and the offset of its magic bytes, which is where
/// streaming to storage starts.
pub fn detect_image_format(lookahead: &[u8]) -> (ImageFormat, usize) {
    for format in [
        ImageFormat::Jpeg,
        ImageFormat::Jpeg2000,
        ImageFormat::Jpeg2000Cs,
    ] {
        if let Some(offset) = find_subsequence(lookahead, format.magic()) {
            return (format, offset);
        }
    }
    (ImageFormat::Raw, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subsequence_search() {
        assert_eq!(find_subsequence(b"abcabc", b"ca"), Some(2));
        assert_eq!(find_subsequence(b"abc", b""), Some(0));
        assert_eq!(find_subsequence(b"ab", b"abc"), None);
        assert_eq!(find_subsequence(b"", b"a"), None);
        assert_eq!(find_subsequence(b"abc", b"abc"), Some(0));
    }

    #[test]
    fn each_format_is_detected_at_its_offset() {
        for format in [
            ImageFormat::Jpeg,
            ImageFormat::Jpeg2000,
            ImageFormat::Jpeg2000Cs,
        ] {
            let mut data = vec![0x11; 10];
            data.extend_from_slice(format.magic());
            data.extend_from_slice(&[0x22; 5]);
            assert_eq!(detect_image_format(&data), (format, 10));
        }
    }

    #[test]
    fn unknown_data_is_raw_from_the_start() {
        assert_eq!(detect_image_format(&[1, 2, 3]), (ImageFormat::Raw, 0));
        assert_eq!(detect_image_format(&[]), (ImageFormat::Raw, 0));
    }

    #[test]
    fn jpeg_wins_when_several_magics_are_present() {
        let data = [ImageFormat::Jpeg2000Cs.magic(), ImageFormat::Jpeg.magic()].concat();
        assert_eq!(detect_image_format(&data).0, ImageFormat::Jpeg);
    }

    #[test]
    fn names_and_extensions() {
        let table = [
            (ImageFormat::Jpeg, "jpeg", "JPEG"),
            (ImageFormat::Jpeg2000, "jp2", "JPEG2000"),
            (ImageFormat::Jpeg2000Cs, "jpc", "JPEG2000-CS"),
            (ImageFormat::Raw, "bin", "raw"),
        ];
        for (format, extension, label) in table {
            assert_eq!(format.extension(), extension);
            assert_eq!(format.dotted_extension(), alloc::format!(".{extension}"));
            assert_eq!(alloc::format!("{format}"), label);
        }
        assert!(ImageFormat::Raw.magic().is_empty());
    }
}
