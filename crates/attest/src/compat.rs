//! Whether a passport can enroll: every check the enrollment proof will make,
//! run natively on what the reader got from the chip, each reported on its
//! own so the holder learns *why* a document cannot enroll (an ECDSA signer,
//! no Active Authentication) before anything is downloaded or proved.
//!
//! What this cannot say is whether the registry trusts the document's
//! signer: that is the publisher's DSC list, checked when enrolling.

use passport_pki::der;
use passport_pki::sig::{self, Hash, SigAlg};
use passport_pki::{ChipKey, Sod, verify_active_authentication};

use crate::enroll::{self, DSC_DEPTH, Passport};
use crate::registry::Tree;
use crate::{Error, Fr};

/// One check, as the app lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Stable identifier: `security_object`, `data_groups`, `signer`,
    /// `chip_key`, `active_authentication`, `layout`.
    pub id: &'static str,
    pub label: &'static str,
    /// `None` when an earlier failure left nothing to check.
    pub passed: Option<bool>,
    pub detail: String,
}

/// What the chip holds, and whether the enrollment circuit takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub checks: Vec<Check>,
    /// The MRZ's issuing state, e.g. `UTO`.
    pub issuing_state: String,
    /// e.g. `RSA-2048 (e = 65537), PKCS#1 v1.5 with SHA-256`.
    pub document_signer: Option<String>,
    /// e.g. `RSA-1024 (e = 65537)`; `None` without DG15.
    pub chip_key: Option<String>,
}

impl Report {
    /// Every check ran and passed.
    pub fn enrollable(&self) -> bool {
        self.checks.iter().all(|c| c.passed == Some(true))
    }
}

/// What the chip returned.
#[derive(Debug, Clone, Copy)]
pub struct Read<'a> {
    pub dg1: &'a [u8],
    /// `None`: the chip has no DG15, so no Active Authentication.
    pub dg15: Option<&'a [u8]>,
    pub sod: &'a [u8],
    /// The challenge sent in INTERNAL AUTHENTICATE and the chip's answer.
    pub active_authentication: Option<(&'a [u8; 8], &'a [u8])>,
}

fn hash_name(h: Hash) -> &'static str {
    match h {
        Hash::Sha1 => "SHA-1",
        Hash::Sha224 => "SHA-224",
        Hash::Sha256 => "SHA-256",
        Hash::Sha384 => "SHA-384",
        Hash::Sha512 => "SHA-512",
    }
}

fn alg_name(a: SigAlg) -> String {
    match a {
        SigAlg::RsaPkcs1(h) => format!("PKCS#1 v1.5 with {}", hash_name(h)),
        SigAlg::RsaPss { hash, .. } => format!("RSA-PSS with {}", hash_name(hash)),
        SigAlg::Ecdsa(h) => format!("ECDSA with {}", hash_name(h)),
    }
}

fn key_name(spki: &[u8]) -> String {
    match der::parse(spki).map(ChipKey::from_spki) {
        Ok(Ok(ChipKey::Rsa { n, e })) => format!("RSA-{} (e = {e})", n.bits()),
        _ => "an elliptic-curve key".into(),
    }
}

struct Checks(Vec<Check>);

impl Checks {
    fn push(&mut self, id: &'static str, label: &'static str, outcome: Result<String, String>) {
        let (passed, detail) = match outcome {
            Ok(d) => (Some(true), d),
            Err(d) => (Some(false), d),
        };
        self.0.push(Check {
            id,
            label,
            passed,
            detail,
        });
    }

    fn skip(&mut self, id: &'static str, label: &'static str, why: &str) {
        self.0.push(Check {
            id,
            label,
            passed: None,
            detail: why.into(),
        });
    }

    fn all_passed(&self) -> bool {
        self.0.iter().all(|c| c.passed == Some(true))
    }
}

/// The checks, in the order the enrollment circuit depends on them. The
/// `secret` only shapes the commitment the AA challenge comes from; the
/// verdict does not depend on it.
pub fn check(secret: Fr, read: &Read) -> Report {
    let mut checks = Checks(Vec::new());
    let issuing_state = passport_pki::passive::issuing_state(read.dg1)
        .map(|s| String::from_utf8_lossy(&s).into_owned())
        .unwrap_or_default();
    let mut document_signer = None;
    let chip_key = read.dg15.map(|dg15| match ChipKey::from_dg15(dg15) {
        Ok(ChipKey::Rsa { n, e }) => format!("RSA-{} (e = {e})", n.bits()),
        Err(_) => "an elliptic-curve key".into(),
    });

    // 1. The SOD is signed by the Document Signer it carries.
    let sod = Sod::parse(read.sod).map_err(|e| e.to_string());
    match &sod {
        Ok(sod) => {
            let signed = sod.dsc().map_err(|e| e.to_string()).and_then(|dsc| {
                document_signer =
                    Some(format!("{}, {}", key_name(dsc.spki), alg_name(sod.sig_alg)));
                if sod.digest.digest(sod.econtent()) != sod.message_digest() {
                    return Err("the signed digest does not match the content".into());
                }
                sig::verify(
                    dsc.spki,
                    sod.sig_alg,
                    &sod.signed_attributes_der(),
                    sod.signature(),
                )
                .map_err(|_| "the Document Signer's signature does not verify".to_string())
            });
            checks.push(
                "security_object",
                "Signed by the issuing state",
                signed.map(|()| {
                    "The chip's security object verifies under its Document Signer.".into()
                }),
            );
        }
        Err(e) => checks.push(
            "security_object",
            "Signed by the issuing state",
            Err(format!("The security object does not parse: {e}")),
        ),
    }

    // 2. The data groups are the ones it signed.
    if let Ok(sod) = &sod {
        let mut groups: Vec<(u8, &[u8])> = vec![(1, read.dg1)];
        if let Some(dg15) = read.dg15 {
            groups.push((15, dg15));
        }
        let outcome = groups
            .iter()
            .try_for_each(|&(n, bytes)| match sod.dg_hash(n) {
                Some(h) if sod.lds_hash.digest(bytes) == h => Ok(()),
                Some(_) => Err(format!("DG{n} does not match its signed hash.")),
                None => Err(format!("The security object does not cover DG{n}.")),
            })
            .map(|()| {
                let names: Vec<String> = groups.iter().map(|g| format!("DG{}", g.0)).collect();
                format!("{} match their signed hashes.", names.join(" and "))
            });
        checks.push("data_groups", "Data unaltered", outcome);
    } else {
        checks.skip(
            "data_groups",
            "Data unaltered",
            "Needs the security object.",
        );
    }

    // 3. The signer is one the circuit verifies.
    match &sod {
        Ok(sod) => {
            let outcome = sod
                .dsc()
                .map_err(|e| e.to_string())
                .and_then(|dsc| {
                    let spki = der::parse(dsc.spki).map_err(|e| e.to_string())?;
                    match ChipKey::from_spki(spki) {
                        Ok(ChipKey::Rsa { n, e }) if n.bits() == 2048 && e == 65537u32.into() => {
                            Ok(())
                        }
                        _ => Err(format!(
                            "Its Document Signer uses {}; enrollment verifies RSA-2048 signers.",
                            key_name(dsc.spki)
                        )),
                    }
                })
                .and_then(|()| {
                    if sod.sig_alg != SigAlg::RsaPkcs1(Hash::Sha256) {
                        return Err(format!(
                            "It is signed with {}; enrollment verifies PKCS#1 v1.5 with SHA-256.",
                            alg_name(sod.sig_alg)
                        ));
                    }
                    if sod.lds_hash != Hash::Sha256 || sod.digest != Hash::Sha256 {
                        return Err(format!(
                            "Its data groups are hashed with {}; enrollment needs SHA-256.",
                            hash_name(sod.lds_hash)
                        ));
                    }
                    Ok("RSA-2048 with SHA-256, which enrollment verifies.".into())
                });
            checks.push("signer", "Signature scheme supported", outcome);
        }
        Err(_) => checks.skip(
            "signer",
            "Signature scheme supported",
            "Needs the security object.",
        ),
    }

    // 4. The chip has the key Active Authentication needs.
    let chip_key_ok = match read.dg15 {
        None => {
            checks.push(
                "chip_key",
                "Chip can prove it is genuine",
                Err("The chip has no Active Authentication key (DG15), so a copy of its data could not be told from the document.".into()),
            );
            false
        }
        Some(dg15) => {
            let outcome = match ChipKey::from_dg15(dg15) {
                Ok(ChipKey::Rsa { n, e }) if n.bits() == 1024 && e == 65537u32.into() => {
                    Ok("RSA-1024, which enrollment verifies.".to_string())
                }
                Ok(ChipKey::Rsa { n, .. }) => Err(format!(
                    "Its chip key is RSA-{}; enrollment verifies RSA-1024.",
                    n.bits()
                )),
                Err(_) => Err(
                    "Its chip key is an elliptic-curve key; enrollment verifies RSA-1024.".into(),
                ),
            };
            let ok = outcome.is_ok();
            checks.push("chip_key", "Chip can prove it is genuine", outcome);
            ok
        }
    };

    // 5. The chip answered the challenge.
    match (read.dg15, read.active_authentication) {
        (Some(dg15), Some((challenge, signature))) => {
            let outcome = verify_active_authentication(dg15, challenge, signature)
                .map(|_| "The chip signed a fresh challenge with its key.".to_string())
                .map_err(|e| format!("The chip's answer does not verify: {e}"));
            checks.push("active_authentication", "Chip is genuine", outcome);
        }
        (Some(_), None) => checks.push(
            "active_authentication",
            "Chip is genuine",
            Err("The chip did not answer the Active Authentication challenge.".into()),
        ),
        (None, _) => checks.skip("active_authentication", "Chip is genuine", "Needs DG15."),
    }

    // 6. Everything fits the circuit: sizes and the layout it locates.
    if checks.all_passed() && chip_key_ok {
        let (challenge, signature) = read.active_authentication.expect("checked above");
        let dg15 = read.dg15.expect("checked above");
        let passport = Passport {
            dg1: read.dg1,
            dg15,
            sod: read.sod,
        };
        let outcome = enroll::prepare(secret, &passport).and_then(|prepared| {
            if &prepared.challenge != challenge {
                return Err(Error::Document(
                    "the chip signed another challenge than this enrollment's".into(),
                ));
            }
            let tree = Tree::with_depth(DSC_DEPTH, vec![prepared.enrollment.dsc_leaf]);
            enroll::witness(&prepared, &passport, signature, &tree, 0).map(|_| ())
        });
        checks.push(
            "layout",
            "Fits the enrollment proof",
            outcome
                .map(|()| "Every field is where and as large as the proof expects.".into())
                .map_err(|e| match e {
                    Error::Unsupported(what) => format!("Not supported yet: {what}."),
                    other => other.to_string(),
                }),
        );
    } else {
        checks.skip(
            "layout",
            "Fits the enrollment proof",
            "Needs every check above.",
        );
    }

    Report {
        checks: checks.0,
        issuing_state,
        document_signer,
        chip_key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use passport_pki::fixtures::{TestChip, TestPki};

    const TD3: &[u8] =
        b"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";

    fn dg1() -> Vec<u8> {
        [&[0x61, 0x5B, 0x5F, 0x1F, 0x58][..], TD3].concat()
    }

    #[test]
    fn a_supported_passport_passes_every_check() {
        let pki = TestPki::generate(61, "UT");
        let chip = TestChip::generate(61);
        let (dg1, dg15) = (dg1(), chip.dg15());
        let sod = pki.sign_sod(&[(1, &dg1), (15, &dg15)]);
        let secret = Fr::from(7u8);
        let prepared = enroll::prepare(
            secret,
            &Passport {
                dg1: &dg1,
                dg15: &dg15,
                sod: &sod,
            },
        )
        .unwrap();
        let aa = chip.internal_authenticate(&prepared.challenge);
        let report = check(
            secret,
            &Read {
                dg1: &dg1,
                dg15: Some(&dg15),
                sod: &sod,
                active_authentication: Some((&prepared.challenge, &aa)),
            },
        );
        assert!(report.enrollable(), "{:#?}", report.checks);
        assert_eq!(report.issuing_state, "UTO");
        assert_eq!(report.chip_key.as_deref(), Some("RSA-1024 (e = 65537)"));
        assert!(
            report
                .document_signer
                .as_deref()
                .unwrap()
                .starts_with("RSA-2048")
        );

        // Another challenge than the enrollment's cannot be reused.
        let other = [9u8; 8];
        let aa = chip.internal_authenticate(&other);
        let report = check(
            secret,
            &Read {
                dg1: &dg1,
                dg15: Some(&dg15),
                sod: &sod,
                active_authentication: Some((&other, &aa)),
            },
        );
        assert_eq!(report.checks.last().unwrap().passed, Some(false));
    }

    #[test]
    fn each_failure_is_named() {
        let pki = TestPki::generate(62, "UT");
        let chip = TestChip::generate(62);
        let (dg1, dg15) = (dg1(), chip.dg15());
        let sod = pki.sign_sod(&[(1, &dg1), (15, &dg15)]);
        let by_id = |r: &Report, id: &str| r.checks.iter().find(|c| c.id == id).unwrap().passed;

        // No DG15: no Active Authentication, nothing to fit.
        let sod_no_aa = pki.sign_sod(&[(1, &dg1)]);
        let r = check(
            Fr::from(1u8),
            &Read {
                dg1: &dg1,
                dg15: None,
                sod: &sod_no_aa,
                active_authentication: None,
            },
        );
        assert!(!r.enrollable());
        assert_eq!(by_id(&r, "security_object"), Some(true));
        assert_eq!(by_id(&r, "signer"), Some(true));
        assert_eq!(by_id(&r, "chip_key"), Some(false));
        assert_eq!(by_id(&r, "active_authentication"), None);
        assert_eq!(by_id(&r, "layout"), None);

        // An altered DG1.
        let mut altered = dg1.clone();
        altered[20] ^= 1;
        let r = check(
            Fr::from(1u8),
            &Read {
                dg1: &altered,
                dg15: Some(&dg15),
                sod: &sod,
                active_authentication: Some((&[0; 8], &[0; 128])),
            },
        );
        assert_eq!(by_id(&r, "data_groups"), Some(false));
        assert_eq!(by_id(&r, "active_authentication"), Some(false));

        // Garbage for a SOD.
        let r = check(
            Fr::from(1u8),
            &Read {
                dg1: &dg1,
                dg15: Some(&dg15),
                sod: b"not a sod",
                active_authentication: None,
            },
        );
        assert_eq!(by_id(&r, "security_object"), Some(false));
        assert_eq!(by_id(&r, "data_groups"), None);
    }
}
