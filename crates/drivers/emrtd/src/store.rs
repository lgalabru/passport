//! Naming and (de)serialising what gets written to storage.
//!
//! File *I/O* is a platform concern, but the shape of
//! what is stored is not: the `MRZ Info` file layout and the `<doc>-DGn.bin`
//! naming rule live here so they can be tested on a host.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::types::{MrzKey, ReadTarget, StorageError};

/// Header of the persisted MRZ key file.
pub const MRZ_FILE_HEADER: &str = "MRZ Info";
/// Version of the persisted MRZ key file.
pub const MRZ_FILE_VERSION: u32 = 1;
/// Base name of the persisted MRZ key file.
pub const MRZ_FILE_BASE_NAME: &str = "mrz_info";

/// FlipperFormat keys, spelled as existing files on devices have them.
pub const KEY_DOCUMENT_NUMBER: &str = "Passport Number";
pub const KEY_DATE_OF_BIRTH: &str = "Date of Birth";
pub const KEY_DATE_OF_EXPIRY: &str = "Date of Expiry";

/// `mrz_info.txt`, to be joined with the app data path by the host.
pub fn mrz_file_name() -> String {
    format!("{MRZ_FILE_BASE_NAME}.txt")
}

/// Key/value pairs for the MRZ file, in file order. Only non-empty fields are
/// emitted: a partial key is never persisted.
pub fn serialize_pairs(key: &MrzKey) -> Vec<(String, String)> {
    if !key.is_complete() {
        return Vec::new();
    }
    Vec::from([
        (
            String::from(KEY_DOCUMENT_NUMBER),
            String::from(key.document_number()),
        ),
        (
            String::from(KEY_DATE_OF_BIRTH),
            String::from(key.date_of_birth()),
        ),
        (
            String::from(KEY_DATE_OF_EXPIRY),
            String::from(key.date_of_expiry()),
        ),
    ])
}

/// Rebuild an [`MrzKey`] from a key/value reader.
///
/// `get` is asked for each key in file order; the Flipper host implements it
/// over `flipper_format_read_string`, tests over a slice of pairs.
///
/// Reads in file order (number, DoB, DoE) and fails on the first missing key.
/// `missing` builds the `ok_or_else` closure for one key.
fn missing(key: &str) -> impl FnOnce() -> StorageError + '_ {
    move || StorageError::MissingKey(String::from(key))
}

pub fn deserialize_pairs<'i, F>(mut get: F) -> Result<MrzKey, StorageError>
where
    F: FnMut(&str) -> Option<&'i str>,
{
    let document_number = get(KEY_DOCUMENT_NUMBER).ok_or_else(missing(KEY_DOCUMENT_NUMBER))?;
    let date_of_birth = get(KEY_DATE_OF_BIRTH).ok_or_else(missing(KEY_DATE_OF_BIRTH))?;
    let date_of_expiry = get(KEY_DATE_OF_EXPIRY).ok_or_else(missing(KEY_DATE_OF_EXPIRY))?;

    MrzKey::from_stored(document_number, date_of_birth, date_of_expiry)
        .ok_or_else(|| StorageError::MissingKey(String::from(KEY_DOCUMENT_NUMBER)))
}

/// Sanitise a path in place: keep `[A-Za-z0-9_-.]` plus `/`. This keeps path
/// separators; for a single file-name component use [`artifact_name`].
pub fn sanitize_filename(name: &mut String) -> usize {
    let original = core::mem::take(name);
    *name = original
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '/' | '.'))
        .collect();
    name.len()
}

/// File name for a stored data group: `<doc>-DG2.jpeg`, `<doc>-DG11.bin`.
///
/// Returns a bare file name; the host prepends its own data directory.
pub fn artifact_name(key: &MrzKey, target: ReadTarget, extension: &str) -> String {
    // The document number is typed by the user. Only the component is sanitised
    // (no `/` or `.`), so it can never act as a path: the host owns the directory.
    let document: String = key
        .filename_prefix()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
        .collect();
    format!("{document}-{}.{extension}", suffix(target))
}

/// `<doc>-COM.bin` style suffix without the extension.
fn suffix(target: ReadTarget) -> String {
    match target {
        ReadTarget::Com => String::from("COM"),
        ReadTarget::Dg(group) => format!("DG{}", group.number()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DataGroup;

    fn key() -> MrzKey {
        MrzKey::new("L898902C", "690806", "940623").unwrap()
    }

    #[test]
    fn file_layout_matches_the_c_app() {
        assert_eq!(mrz_file_name(), "mrz_info.txt");
        assert_eq!((MRZ_FILE_HEADER, MRZ_FILE_VERSION), ("MRZ Info", 1));
        assert_eq!(
            serialize_pairs(&key()),
            [
                ("Passport Number".into(), "L898902C<".into()),
                ("Date of Birth".into(), "690806".into()),
                ("Date of Expiry".into(), "940623".into()),
            ]
        );
    }

    #[test]
    fn serialise_then_deserialise_is_identity() {
        let pairs = serialize_pairs(&key());
        let restored = deserialize_pairs(|name| {
            pairs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        })
        .unwrap();
        assert_eq!(restored, key());
    }

    #[test]
    fn deserialise_reports_the_first_missing_key() {
        let missing = |absent: &'static str| {
            deserialize_pairs(move |name| (name != absent).then_some("690806"))
        };
        for key in [KEY_DOCUMENT_NUMBER, KEY_DATE_OF_BIRTH, KEY_DATE_OF_EXPIRY] {
            assert_eq!(missing(key), Err(StorageError::MissingKey(key.into())));
        }
    }

    #[test]
    fn deserialise_rejects_empty_values() {
        let result = deserialize_pairs(|_| Some(""));
        assert_eq!(
            result,
            Err(StorageError::MissingKey(KEY_DOCUMENT_NUMBER.into()))
        );
    }

    #[test]
    fn sanitiser_keeps_only_path_safe_characters() {
        let mut name = String::from("a b/c<d>:e-f_g.h\u{e9}\n");
        let len = sanitize_filename(&mut name);
        assert_eq!(name, "ab/cde-f_g.h");
        assert_eq!(len, name.len());
    }

    #[test]
    fn artifact_names() {
        assert_eq!(
            artifact_name(&key(), ReadTarget::Dg(DataGroup::Dg2), "jpeg"),
            "L898902C-DG2.jpeg"
        );
        assert_eq!(
            artifact_name(&key(), ReadTarget::Dg(DataGroup::Dg11), "bin"),
            "L898902C-DG11.bin"
        );
        assert_eq!(
            artifact_name(&key(), ReadTarget::Com, "bin"),
            "L898902C-COM.bin"
        );
    }

    #[test]
    fn hostile_document_numbers_cannot_escape_the_data_directory() {
        let key = MrzKey::new("../../etc/x", "690806", "940623").unwrap();
        let name = artifact_name(&key, ReadTarget::Com, "bin");
        assert!(!name.contains(".."), "{name}");
        assert!(!name.starts_with('/'), "{name}");
    }
}
