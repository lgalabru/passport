//! The enrollment relation against the test PKI, through the circuit's
//! native validator (the circuit code itself, run on the host with every
//! constraint checked): a genuine, live passport enrolls, and each way of
//! faking one is refused. The witness comes from `passport_attest::enroll`,
//! so this also checks the native layout against the circuit.

use std::sync::OnceLock;

use passport_attest::Fr;
use passport_attest::enroll::{self, DSC_DEPTH, Passport, Prepared};
use passport_attest::registry::Tree;
use passport_attest::token::NamedInputs;
use passport_enroll::passport_enroll;
use passport_pki::fixtures::{TestChip, TestPki};

const TD3: &[u8] =
    b"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10";
const TD1: &[u8] =
    b"I<UTOD231458907<<<<<<<<<<<<<<<7408122F1204159UTO<<<<<<<<<<<6ERIKSSON<<ANNA<MARIA<<<<<<<<<<";

struct World {
    pki: TestPki,
    other_pki: TestPki,
    chip: TestChip,
    other_chip: TestChip,
}

fn world() -> &'static World {
    static W: OnceLock<World> = OnceLock::new();
    W.get_or_init(|| World {
        pki: TestPki::generate(21, "UT"),
        other_pki: TestPki::generate(22, "UT"),
        chip: TestChip::generate(21),
        other_chip: TestChip::generate(22),
    })
}

fn dg1(mrz: &[u8]) -> Vec<u8> {
    let (l, l2) = if mrz.len() == 90 {
        (0x5D, 0x5A)
    } else {
        (0x5B, 0x58)
    };
    [&[0x61, l, 0x5F, 0x1F, l2][..], mrz].concat()
}

/// A document: its files and the SOD the test PKI signed over them.
struct Doc {
    dg1: Vec<u8>,
    dg15: Vec<u8>,
    sod: Vec<u8>,
}

fn doc(mrz: &[u8]) -> Doc {
    let w = world();
    let dg1 = dg1(mrz);
    let dg2 = b"\x75\x08portrait".to_vec();
    let dg15 = w.chip.dg15();
    let sod = w.pki.sign_sod(&[(1, &dg1), (2, &dg2), (15, &dg15)]);
    Doc { dg1, dg15, sod }
}

impl Doc {
    fn passport(&self) -> Passport<'_> {
        Passport {
            dg1: &self.dg1,
            dg15: &self.dg15,
            sod: &self.sod,
        }
    }
}

const SECRET: u64 = 0x5EC2E7;

/// The DSC tree, our signer not first.
fn dsc_tree(leaf: Fr) -> Tree {
    Tree::with_depth(DSC_DEPTH, vec![Fr::from(11u8), leaf, Fr::from(13u8)])
}

fn prepared(d: &Doc) -> Prepared {
    enroll::prepare(Fr::from(SECRET), &d.passport()).unwrap()
}

/// Inputs for `d`, the chip answering `sign(challenge)`.
fn inputs_with(d: &Doc, sign: impl Fn(&[u8; 8]) -> Vec<u8>) -> NamedInputs {
    let p = prepared(d);
    let sig = sign(&p.challenge);
    let tree = dsc_tree(p.enrollment.dsc_leaf);
    enroll::witness(&p, &d.passport(), &sig, &tree, 1)
        .unwrap()
        .0
}

fn inputs(d: &Doc) -> NamedInputs {
    inputs_with(d, |c| world().chip.internal_authenticate(c))
}

fn get(inputs: &NamedInputs, name: &str) -> String {
    inputs
        .iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("no input {name}"))
        .1
        .to_string()
}

fn arr<const N: usize>(inputs: &NamedInputs, name: &str) -> [String; N] {
    core::array::from_fn(|i| get(inputs, &format!("{name}[{i}]")))
}

fn set(inputs: &mut NamedInputs, name: &str, value: Fr) {
    inputs.iter_mut().find(|(n, _)| n == name).unwrap().1 = value;
}

fn solves(i: &NamedInputs) -> bool {
    passport_enroll(
        get(i, "secret"),
        get(i, "td1"),
        arr(i, "dg1"),
        arr(i, "dg15"),
        get(i, "dg15_len"),
        get(i, "aa_key_at"),
        arr(i, "aa_n"),
        arr(i, "aa_sig"),
        arr(i, "econtent"),
        get(i, "econtent_len"),
        get(i, "dg1_hash_at"),
        get(i, "dg15_hash_at"),
        arr(i, "attrs"),
        get(i, "attrs_len"),
        get(i, "digest_at"),
        arr(i, "dsc_n"),
        arr(i, "sod_sig"),
        arr(i, "dsc_siblings"),
        arr(i, "dsc_index_bits"),
        get(i, "dsc_root"),
        get(i, "commitment"),
        get(i, "nullifier"),
    )
    .map_err(|e| eprintln!("refused: {e:?}"))
    .is_ok()
}

#[test]
fn a_genuine_passport_enrolls() {
    let d = doc(TD3);
    let i = inputs(&d);
    assert!(solves(&i));
    // The commitment is the claim circuit's leaf for this document.
    let p = prepared(&d);
    assert_eq!(get(&i, "commitment"), p.enrollment.commitment().to_string());
    assert_eq!(p.challenge, enroll::challenge(p.enrollment.commitment()));
}

#[test]
fn an_identity_card_enrolls() {
    assert!(solves(&inputs(&doc(TD1))));
}

#[test]
fn the_outputs_are_bound() {
    let d = doc(TD3);
    let good = inputs(&d);
    for name in ["commitment", "nullifier", "dsc_root"] {
        let mut i = good.clone();
        set(&mut i, name, Fr::from(1u8));
        assert!(!solves(&i), "{name} is free");
    }
    // Another secret is another commitment, and so another challenge.
    let mut i = good.clone();
    set(&mut i, "secret", Fr::from(SECRET + 1));
    assert!(!solves(&i));
}

#[test]
fn a_copy_of_the_files_cannot_enroll() {
    let d = doc(TD3);
    // An AA answer to another challenge (replayed from another session).
    assert!(!solves(&inputs_with(&d, |_| world()
        .chip
        .internal_authenticate(&[1, 2, 3, 4, 5, 6, 7, 8]))));
    // Another chip's answer.
    assert!(!solves(&inputs_with(&d, |c| world()
        .other_chip
        .internal_authenticate(c))));
    assert!(!solves(&inputs_with(&d, |_| vec![0x5A; 128])));
}

#[test]
fn the_document_signer_must_be_trusted_and_must_have_signed() {
    let w = world();
    let d = doc(TD3);
    let p = prepared(&d);
    let sig = w.chip.internal_authenticate(&p.challenge);

    // A DSC tree without our signer: its leaf at index 1 is someone else's.
    let stranger = Tree::with_depth(DSC_DEPTH, vec![Fr::from(11u8), Fr::from(12u8)]);
    assert!(enroll::witness(&p, &d.passport(), &sig, &stranger, 1).is_err());
    let mut i = enroll::witness(&p, &d.passport(), &sig, &dsc_tree(p.enrollment.dsc_leaf), 1)
        .unwrap()
        .0;
    set(&mut i, "dsc_root", stranger.root());
    assert!(!solves(&i));

    // An SOD signed by another key but carrying the genuine DSC certificate.
    let dg2 = b"\x75\x08portrait".to_vec();
    let forged = Doc {
        sod: w.pki.sign_sod_with(
            &[(1, &d.dg1), (2, &dg2), (15, &d.dg15)],
            &w.other_pki.dsc_key,
        ),
        dg1: d.dg1.clone(),
        dg15: d.dg15.clone(),
    };
    assert!(!solves(&inputs(&forged)));
}

/// A signer the publisher trusts for one state cannot enroll a document of
/// another: the leaf the circuit looks up carries the MRZ's issuing state.
#[test]
fn the_signer_is_trusted_for_the_documents_issuing_state() {
    let d = doc(TD3);
    let p = prepared(&d);
    let good = inputs(&d);
    let with_tree = |tree: &Tree| {
        let mut i = good.clone();
        let path = tree.path(1);
        for (k, s) in path.siblings.iter().enumerate() {
            set(&mut i, &format!("dsc_siblings[{k}]"), *s);
        }
        set(&mut i, "dsc_root", tree.root());
        i
    };
    let utopia = enroll::dsc_leaf(&p.dsc_modulus, *b"UTO");
    assert_eq!(utopia, p.enrollment.dsc_leaf);
    assert!(solves(&with_tree(&dsc_tree(utopia))));
    // The same key, listed for France: a UTO passport does not enroll.
    let france = enroll::dsc_leaf(&p.dsc_modulus, *b"FRA");
    assert!(!solves(&with_tree(&dsc_tree(france))));
}

#[test]
fn the_data_groups_must_be_the_signed_ones() {
    let w = world();
    let d = doc(TD3);
    // Another MRZ under the genuine SOD.
    let mut other_mrz = TD3.to_vec();
    other_mrz[5] = b'X';
    let altered = Doc {
        dg1: dg1(&other_mrz),
        dg15: d.dg15.clone(),
        sod: d.sod.clone(),
    };
    assert!(!solves(&inputs(&altered)));
    // Another chip key under the genuine SOD (a cloner's own chip).
    let cloned = Doc {
        dg1: d.dg1.clone(),
        dg15: w.other_chip.dg15(),
        sod: d.sod.clone(),
    };
    assert!(!solves(&inputs_with(&cloned, |c| w
        .other_chip
        .internal_authenticate(c))));
}

#[test]
fn offsets_cannot_point_elsewhere() {
    let d = doc(TD3);
    let good = inputs(&d);
    let at = |name: &str| get(&good, name).parse::<u64>().unwrap();
    let cases = [
        // The DG1 entry is followed by DG2's: point at it.
        ("dg1_hash_at", at("dg1_hash_at") + 39),
        ("dg15_hash_at", at("dg1_hash_at")),
        ("dg1_hash_at", at("dg1_hash_at") + 1),
        ("aa_key_at", at("aa_key_at") + 1),
        ("digest_at", at("digest_at") + 1),
        // Lengths: hash less (or more) than was signed.
        ("econtent_len", at("econtent_len") - 1),
        ("attrs_len", at("attrs_len") + 1),
        ("dg15_len", at("dg15_len") - 1),
        ("td1", 1),
    ];
    for (name, value) in cases {
        let mut i = good.clone();
        set(&mut i, name, Fr::from(value));
        assert!(!solves(&i), "{name} = {value} accepted");
    }
}
