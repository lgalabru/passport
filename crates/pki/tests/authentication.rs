//! Passive and Active Authentication against the test PKI: a genuine
//! document passes, and every way of forging one fails for the right reason.

use std::sync::OnceLock;

use num_bigint::BigUint;
use passport_pki::fixtures::{Role, TestChip, TestPki};
use passport_pki::{Error, Sod, Trust, passive_authentication, verify_active_authentication};

const TODAY: u32 = 20261030;
const DG1: &[u8] = b"\x61\x5B\x5F\x1F\x58P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";
const DG2: &[u8] = b"\x75\x06photo!";

fn pki() -> &'static TestPki {
    static PKI: OnceLock<TestPki> = OnceLock::new();
    PKI.get_or_init(|| TestPki::generate(1, "UT"))
}

fn other_pki() -> &'static TestPki {
    static PKI: OnceLock<TestPki> = OnceLock::new();
    PKI.get_or_init(|| TestPki::generate(2, "UT"))
}

fn chip() -> &'static TestChip {
    static CHIP: OnceLock<TestChip> = OnceLock::new();
    CHIP.get_or_init(|| TestChip::generate(1))
}

fn document() -> (Vec<u8>, Vec<u8>) {
    let dg15 = chip().dg15();
    let sod = pki().sign_sod(&[(1, DG1), (2, DG2), (15, &dg15)]);
    (sod, dg15)
}

fn check(sod: &[u8], groups: &[(u8, &[u8])]) -> Result<(), Error> {
    passive_authentication(sod, groups, &pki().trust(), TODAY).map(|_| ())
}

#[test]
fn a_genuine_document_passes() {
    let (sod, dg15) = document();
    let pa = passive_authentication(
        &sod,
        &[(1, DG1), (2, DG2), (15, &dg15)],
        &pki().trust(),
        TODAY,
    )
    .unwrap();
    assert_eq!(pa.groups, vec![1, 2, 15]);
    assert_eq!(pa.dsc, pki().dsc_cert);
    assert_eq!(pa.csca, pki().csca_cert);
    // Checking a subset is fine: the reader may skip DG2.
    check(&sod, &[(1, DG1)]).unwrap();
}

#[test]
fn the_parse_points_at_the_bytes_the_circuit_will_use() {
    use sha2::{Digest, Sha256};
    let (sod, dg15) = document();
    let s = Sod::parse(&sod).unwrap();
    assert_eq!(s.dg_hash(1).unwrap(), Sha256::digest(DG1).as_slice());
    assert_eq!(s.dg_hash(15).unwrap(), Sha256::digest(&dg15).as_slice());
    assert_eq!(s.message_digest(), Sha256::digest(s.econtent()).as_slice());
    // Ranges are into EF.SOD itself.
    let r = &s.dg_hashes[0].value;
    assert_eq!(&sod[r.clone()], Sha256::digest(DG1).as_slice());
    assert_eq!(sod[s.signed_attrs.start], 0xA0);
    assert_eq!(s.signed_attributes_der()[0], 0x31);
    assert_eq!(s.dsc().unwrap().raw, pki().dsc_cert.as_slice());
    assert_eq!(s.signature().len(), 256);
}

#[test]
fn altered_data_groups_fail() {
    let (sod, dg15) = document();
    let mut dg1 = DG1.to_vec();
    dg1[40] = b'X'; // another name
    assert_eq!(check(&sod, &[(1, &dg1)]), Err(Error::HashMismatch(1)));
    let other_chip = TestChip::generate(9).dg15();
    assert_eq!(
        check(&sod, &[(15, &other_chip)]),
        Err(Error::HashMismatch(15))
    );
    assert_eq!(
        check(&sod, &[(11, b"\x6B\x00")]),
        Err(Error::NotCovered(11))
    );
    check(&sod, &[(15, &dg15)]).unwrap();
}

#[test]
fn an_altered_sod_fails() {
    let (sod, _) = document();
    let s = Sod::parse(&sod).unwrap();

    // Change the DG1 hash inside the signed content: the message digest breaks.
    let mut forged = sod.clone();
    forged[s.dg_hashes[0].value.start] ^= 1;
    assert_eq!(
        check(&forged, &[]),
        Err(Error::BadSignature("message digest"))
    );

    // Change the message digest to match: the signature breaks.
    let mut forged = sod.clone();
    forged[s.message_digest.start] ^= 1;
    assert_eq!(
        check(&forged, &[]),
        Err(Error::BadSignature("message digest"))
    );

    let mut forged = sod.clone();
    forged[s.signature.start + 100] ^= 1;
    assert_eq!(check(&forged, &[]), Err(Error::BadSignature("SOD")));
}

#[test]
fn a_sod_signed_by_anyone_else_fails() {
    // Signed with another key but carrying the genuine DSC.
    let forged = pki().sign_sod_with(&[(1, DG1)], &other_pki().dsc_key);
    assert_eq!(check(&forged, &[(1, DG1)]), Err(Error::BadSignature("SOD")));

    // A self-consistent SOD from another PKI: its DSC is not ours to trust.
    let foreign = other_pki().sign_sod(&[(1, DG1)]);
    assert_eq!(check(&foreign, &[(1, DG1)]), Err(Error::UntrustedSigner));
    assert_eq!(
        passive_authentication(&foreign, &[(1, DG1)], &Trust::default(), TODAY).unwrap_err(),
        Error::UntrustedSigner
    );
    passive_authentication(&foreign, &[(1, DG1)], &other_pki().trust(), TODAY).unwrap();
}

/// A CSCA certifies more than Document Signers: Master List Signers, its own
/// links, sometimes sub-CAs. Only a Document Signer may sign a SOD.
#[test]
fn only_document_signers_sign_documents() {
    let key = &other_pki().dsc_key;
    let as_role = |role: Role| {
        let cert = pki().issue(key, &[0x55], role);
        check(
            &pki().sign_sod_as(&[(1, DG1)], key, &cert, &[0x55]),
            &[(1, DG1)],
        )
    };
    as_role(Role::DocumentSigner).unwrap();
    assert_eq!(
        as_role(Role::MasterListSigner),
        Err(Error::WrongRole("a Master List or Deviation List Signer"))
    );
    assert_eq!(
        as_role(Role::SubCa),
        Err(Error::WrongRole("a CA certificate as a Document Signer"))
    );
    assert_eq!(
        as_role(Role::Bare),
        Err(Error::WrongRole(
            "a Document Signer without keyUsage digitalSignature"
        ))
    );
}

/// A trust anchor is a CA certificate: a Document Signer listed as one does
/// not let its key certify others.
#[test]
fn only_ca_certificates_anchor_trust() {
    let (sod, _) = document();
    let mut trust = pki().trust();
    trust.cscas[0].csca = pki().dsc_cert.clone();
    assert_eq!(
        passive_authentication(&sod, &[(1, DG1)], &trust, TODAY).unwrap_err(),
        Error::UntrustedSigner
    );
}

/// One trusted state's signer cannot vouch for another state's documents:
/// the MRZ's issuing state must be the one the CSCA is trusted for.
#[test]
fn the_issuing_state_is_the_csca_s() {
    let (sod, _) = document();
    passive_authentication(&sod, &[(1, DG1)], &pki().trust_for(*b"UTO"), TODAY).unwrap();
    assert_eq!(
        passive_authentication(&sod, &[(1, DG1)], &pki().trust_for(*b"FRA"), TODAY).unwrap_err(),
        Error::WrongIssuingState
    );
    // A state's own document claiming another state is refused too.
    let mut dg1 = DG1.to_vec();
    dg1[7..10].copy_from_slice(b"FRA");
    let sod = pki().sign_sod(&[(1, &dg1)]);
    assert_eq!(check(&sod, &[(1, &dg1)]), Err(Error::WrongIssuingState));
}

#[test]
fn certificates_must_be_valid_on_the_day() {
    let expired = TestPki::generate_with(3, "UT", "200101000000Z", "211231235959Z");
    let sod = expired.sign_sod(&[(1, DG1)]);
    assert_eq!(
        passive_authentication(&sod, &[(1, DG1)], &expired.trust(), TODAY).unwrap_err(),
        Error::NotValidNow("document signer")
    );
    passive_authentication(&sod, &[(1, DG1)], &expired.trust(), 20210601).unwrap();
    assert_eq!(
        passive_authentication(&sod, &[(1, DG1)], &expired.trust(), 20191231).unwrap_err(),
        Error::NotValidNow("document signer")
    );
}

#[test]
fn active_authentication_needs_the_chip() {
    let challenge = [1, 2, 3, 4, 5, 6, 7, 8];
    let dg15 = chip().dg15();
    let sig = chip().internal_authenticate(&challenge);
    let m1 = verify_active_authentication(&dg15, &challenge, &sig).unwrap();
    assert_eq!(m1.len(), 106);

    // The other representative, n − s, is just as valid.
    let passport_pki::ChipKey::Rsa { n, .. } = passport_pki::ChipKey::from_dg15(&dg15).unwrap();
    let alt = (&n - BigUint::from_bytes_be(&sig)).to_bytes_be();
    let mut alt_padded = vec![0u8; 128 - alt.len()];
    alt_padded.extend(alt);
    verify_active_authentication(&dg15, &challenge, &alt_padded).unwrap();

    // A replayed answer to another challenge, another chip's answer, noise.
    let other = [8, 7, 6, 5, 4, 3, 2, 1];
    assert!(verify_active_authentication(&dg15, &other, &sig).is_err());
    let clone = TestChip::generate(5).internal_authenticate(&challenge);
    assert!(verify_active_authentication(&dg15, &challenge, &clone).is_err());
    let mut bent = sig.clone();
    bent[64] ^= 0x10;
    assert!(verify_active_authentication(&dg15, &challenge, &bent).is_err());
    assert!(verify_active_authentication(&dg15, &challenge, &sig[1..]).is_err());
    assert!(verify_active_authentication(&dg15, &challenge, &[0xFF; 128]).is_err());
}

#[test]
fn malformed_input_is_an_error_not_a_panic() {
    let (sod, dg15) = document();
    for len in 0..sod.len() {
        assert!(Sod::parse(&sod[..len]).is_err(), "truncated at {len}");
    }
    for i in (0..sod.len()).step_by(7) {
        let mut bent = sod.clone();
        bent[i] ^= 0xFF;
        let _ = check(&bent, &[(1, DG1)]);
    }
    for len in 0..dg15.len() {
        assert!(passport_pki::ChipKey::from_dg15(&dg15[..len]).is_err());
    }
    assert!(check(b"", &[]).is_err());
    assert!(check(&[0x77, 0x00], &[]).is_err());
}
