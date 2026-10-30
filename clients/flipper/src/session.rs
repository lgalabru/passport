//! What the user has entered, and the rules for changing it.

use alloc::string::String;
use alloc::vec::Vec;

use passport_driver_emrtd::store::{
    KEY_DATE_OF_BIRTH, KEY_DATE_OF_EXPIRY, KEY_DOCUMENT_NUMBER, deserialize_pairs, serialize_pairs,
};
use passport_driver_emrtd::types::{
    AuthMethod, MrzKey, MrzKeyError, ReadTarget, StorageError, normalize_date,
    normalize_document_number,
};

/// The MRZ key being edited plus the options chosen for the next read.
///
/// Fields are validated when set, so anything stored here is usable for BAC.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Session {
    document_number: String,
    date_of_birth: String,
    date_of_expiry: String,
    auth: Option<AuthMethod>,
    target: Option<ReadTarget>,
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }

    /// Document number as stored: upper-case, padded with `<` to 9 characters.
    pub fn document_number(&self) -> &str {
        &self.document_number
    }

    pub fn date_of_birth(&self) -> &str {
        &self.date_of_birth
    }

    pub fn date_of_expiry(&self) -> &str {
        &self.date_of_expiry
    }

    pub fn set_document_number(&mut self, raw: &str) -> Result<(), MrzKeyError> {
        if raw.trim().is_empty() {
            return Err(MrzKeyError::DocumentNumber);
        }
        self.document_number = normalize_document_number(raw);
        Ok(())
    }

    pub fn set_date_of_birth(&mut self, raw: &str) -> Result<(), MrzKeyError> {
        self.date_of_birth = normalize_date(raw).ok_or(MrzKeyError::DateOfBirth)?;
        Ok(())
    }

    pub fn set_date_of_expiry(&mut self, raw: &str) -> Result<(), MrzKeyError> {
        self.date_of_expiry = normalize_date(raw).ok_or(MrzKeyError::DateOfExpiry)?;
        Ok(())
    }

    /// The complete key, or `None` while any field is still missing.
    pub fn key(&self) -> Option<MrzKey> {
        MrzKey::new(
            &self.document_number,
            &self.date_of_birth,
            &self.date_of_expiry,
        )
        .ok()
    }

    pub fn has_key(&self) -> bool {
        self.key().is_some()
    }

    /// Key/value pairs to persist; empty until the key is complete, so a
    /// half-entered key is never written.
    pub fn to_pairs(&self) -> Vec<(String, String)> {
        self.key()
            .map(|key| serialize_pairs(&key))
            .unwrap_or_default()
    }

    /// Replace the key with one read back from storage. On error the session is
    /// left untouched.
    pub fn restore<'i>(
        &mut self,
        get: impl FnMut(&str) -> Option<&'i str>,
    ) -> Result<(), StorageError> {
        let key = deserialize_pairs(get)?;
        self.document_number = String::from(key.document_number());
        self.date_of_birth = String::from(key.date_of_birth());
        self.date_of_expiry = String::from(key.date_of_expiry());
        Ok(())
    }

    /// Forget the key (after deleting the stored file).
    pub fn clear_key(&mut self) {
        self.document_number.clear();
        self.date_of_birth.clear();
        self.date_of_expiry.clear();
    }

    /// The method shown in the auth menu. Entering that menu turns "None" into
    /// "Any".
    pub fn auth(&self) -> AuthMethod {
        self.auth.unwrap_or(AuthMethod::None)
    }

    pub fn enter_auth_menu(&mut self) -> AuthMethod {
        let method = self.auth().or_default_any();
        self.auth = Some(method);
        method
    }

    pub fn set_auth_from_menu_index(&mut self, index: u8) -> AuthMethod {
        let method = AuthMethod::from_menu_index(index);
        self.auth = Some(method);
        method
    }

    pub fn target(&self) -> Option<ReadTarget> {
        self.target
    }

    pub fn select_target(&mut self, target: ReadTarget) {
        self.target = Some(target);
    }
}

/// Keys used when persisting, re-exported so the device layer needs no other path.
pub const STORE_KEYS: [&str; 3] = [KEY_DOCUMENT_NUMBER, KEY_DATE_OF_BIRTH, KEY_DATE_OF_EXPIRY];

#[cfg(test)]
mod tests {
    use super::*;
    use passport_driver_emrtd::types::DataGroup;

    fn complete() -> Session {
        let mut s = Session::new();
        s.set_document_number("l898902c").unwrap();
        s.set_date_of_birth("690806").unwrap();
        s.set_date_of_expiry("940623").unwrap();
        s
    }

    #[test]
    fn starts_empty_and_incomplete() {
        let s = Session::new();
        assert!(!s.has_key());
        assert_eq!(s.key(), None);
        assert!(s.to_pairs().is_empty());
        assert_eq!(s.auth(), AuthMethod::None);
        assert_eq!(s.target(), None);
    }

    #[test]
    fn document_number_is_normalised() {
        let s = complete();
        assert_eq!(s.document_number(), "L898902C<");
    }

    #[test]
    fn invalid_input_is_rejected_and_leaves_the_field_alone() {
        let mut s = complete();
        assert_eq!(
            s.set_document_number("  "),
            Err(MrzKeyError::DocumentNumber)
        );
        assert_eq!(s.set_date_of_birth("69080"), Err(MrzKeyError::DateOfBirth));
        assert_eq!(s.set_date_of_birth("69O806"), Err(MrzKeyError::DateOfBirth));
        assert_eq!(
            s.set_date_of_expiry("94-06-23"),
            Err(MrzKeyError::DateOfExpiry)
        );
        assert_eq!(s.document_number(), "L898902C<");
        assert_eq!(s.date_of_birth(), "690806");
        assert_eq!(s.date_of_expiry(), "940623");
    }

    #[test]
    fn key_needs_all_three_fields() {
        let mut s = Session::new();
        s.set_document_number("A1").unwrap();
        assert!(!s.has_key());
        s.set_date_of_birth("690806").unwrap();
        assert!(!s.has_key());
        s.set_date_of_expiry("940623").unwrap();
        assert!(s.has_key());
        assert_eq!(s.key().unwrap().key_material().len(), 24);
    }

    #[test]
    fn partial_keys_are_never_persisted() {
        let mut s = Session::new();
        s.set_document_number("A1").unwrap();
        assert!(s.to_pairs().is_empty());
    }

    #[test]
    fn persists_and_restores_exactly() {
        let saved = complete().to_pairs();
        assert_eq!(saved.len(), 3);

        let mut restored = Session::new();
        restored
            .restore(|name| {
                saved
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.as_str())
            })
            .unwrap();
        assert_eq!(restored, complete());
    }

    #[test]
    fn failed_restore_leaves_session_untouched() {
        let mut s = complete();
        let before = s.clone();
        let result = s.restore(|name| (name != KEY_DATE_OF_EXPIRY).then_some("690806"));
        assert_eq!(
            result,
            Err(StorageError::MissingKey(KEY_DATE_OF_EXPIRY.into()))
        );
        assert_eq!(s, before);
    }

    #[test]
    fn clearing_forgets_the_key_but_not_the_options() {
        let mut s = complete();
        s.select_target(ReadTarget::Dg(DataGroup::Dg1));
        s.enter_auth_menu();
        s.clear_key();
        assert!(!s.has_key());
        assert_eq!(s.document_number(), "");
        assert_eq!(s.target(), Some(ReadTarget::Dg(DataGroup::Dg1)));
        assert_eq!(s.auth(), AuthMethod::Any);
    }

    #[test]
    fn entering_the_auth_menu_defaults_none_to_any_once() {
        let mut s = Session::new();
        assert_eq!(s.enter_auth_menu(), AuthMethod::Any);
        assert_eq!(s.set_auth_from_menu_index(2), AuthMethod::Bac);
        assert_eq!(
            s.enter_auth_menu(),
            AuthMethod::Bac,
            "a chosen method is kept"
        );
        assert_eq!(s.set_auth_from_menu_index(0), AuthMethod::None);
        assert_eq!(s.enter_auth_menu(), AuthMethod::Any);
    }

    #[test]
    fn store_keys_match_the_persisted_names() {
        assert_eq!(
            STORE_KEYS,
            ["Passport Number", "Date of Birth", "Date of Expiry"]
        );
    }
}
