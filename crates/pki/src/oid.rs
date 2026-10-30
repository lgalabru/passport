//! Object identifiers, as the content bytes of their DER encoding.

/// The content bytes of the OID `dotted` (`"1.2.840.113549.1.7.2"`).
pub fn encode(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').map(|a| a.parse().expect("arc")).collect();
    let mut out = Vec::new();
    let mut push = |mut v: u64| {
        let mut chunk = vec![(v & 0x7F) as u8];
        v >>= 7;
        while v > 0 {
            chunk.push(0x80 | (v & 0x7F) as u8);
            v >>= 7;
        }
        chunk.reverse();
        out.extend(chunk);
    };
    push(arcs[0] * 40 + arcs[1]);
    for &a in &arcs[2..] {
        push(a);
    }
    out
}

/// An OID element (`06 len content`).
pub fn der(dotted: &str) -> Vec<u8> {
    crate::der::tlv(0x06, &encode(dotted))
}

pub const SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
pub const LDS_SECURITY_OBJECT: &str = "2.23.136.1.1.1";
pub const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
pub const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";

pub const SHA1: &str = "1.3.14.3.2.26";
pub const SHA224: &str = "2.16.840.1.101.3.4.2.4";
pub const SHA256: &str = "2.16.840.1.101.3.4.2.1";
pub const SHA384: &str = "2.16.840.1.101.3.4.2.2";
pub const SHA512: &str = "2.16.840.1.101.3.4.2.3";

pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
pub const SHA1_WITH_RSA: &str = "1.2.840.113549.1.1.5";
pub const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
pub const SHA384_WITH_RSA: &str = "1.2.840.113549.1.1.12";
pub const SHA512_WITH_RSA: &str = "1.2.840.113549.1.1.13";
pub const SHA224_WITH_RSA: &str = "1.2.840.113549.1.1.14";
pub const RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
pub const MGF1: &str = "1.2.840.113549.1.1.8";

pub const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
pub const ECDSA_SHA1: &str = "1.2.840.10045.4.1";
pub const ECDSA_SHA224: &str = "1.2.840.10045.4.3.1";
pub const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
pub const ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
pub const ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";
pub const P256: &str = "1.2.840.10045.3.1.7";
pub const P384: &str = "1.3.132.0.34";

pub const COUNTRY: &str = "2.5.4.6";
pub const COMMON_NAME: &str = "2.5.4.3";

#[cfg(test)]
mod tests {
    #[test]
    fn encodes_known_oids() {
        assert_eq!(
            super::der(super::SHA256),
            [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
            ]
        );
        assert_eq!(
            super::encode(super::RSA_ENCRYPTION),
            [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
        );
    }
}
