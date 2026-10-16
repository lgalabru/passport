//! Authentication methods offered by the auth menu.

use core::fmt;

/// Which authentication the reader is allowed to attempt.
///
/// `Pace` is declared but not implemented: the UI keeps it hidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum AuthMethod {
    None = 0,
    Any = 1,
    Bac = 2,
    Pace = 3,
}

impl AuthMethod {
    /// Number of methods exposed in the menu (PACE is unimplemented).
    pub const MENU_LEN: u8 = 3;

    pub const MENU: [AuthMethod; 3] = [AuthMethod::None, AuthMethod::Any, AuthMethod::Bac];

    pub fn as_str(self) -> &'static str {
        match self {
            AuthMethod::None => "None",
            AuthMethod::Any => "Any",
            AuthMethod::Bac => "BAC",
            AuthMethod::Pace => "PACE",
        }
    }

    /// Menu index to variant; unknown indices fall back to [`AuthMethod::None`].
    pub fn from_menu_index(index: u8) -> Self {
        Self::MENU
            .get(index as usize)
            .copied()
            .unwrap_or(AuthMethod::None)
    }

    pub fn menu_index(self) -> u8 {
        match self {
            AuthMethod::None => 0,
            AuthMethod::Any => 1,
            AuthMethod::Bac => 2,
            AuthMethod::Pace => 3,
        }
    }

    /// Entering the auth menu defaults "None" to "Any".
    pub fn or_default_any(self) -> Self {
        if self == AuthMethod::None {
            AuthMethod::Any
        } else {
            self
        }
    }
}

impl fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_indices_round_trip() {
        for (index, method) in AuthMethod::MENU.iter().enumerate() {
            assert_eq!(method.menu_index() as usize, index);
            assert_eq!(AuthMethod::from_menu_index(index as u8), *method);
        }
        assert_eq!(AuthMethod::MENU.len(), AuthMethod::MENU_LEN as usize);
    }

    #[test]
    fn out_of_range_index_falls_back_to_none() {
        assert_eq!(AuthMethod::from_menu_index(200), AuthMethod::None);
        // PACE is deliberately not in the menu.
        assert_eq!(AuthMethod::from_menu_index(3), AuthMethod::None);
        assert_eq!(AuthMethod::Pace.menu_index(), 3);
    }

    #[test]
    fn none_defaults_to_any_and_others_are_kept() {
        assert_eq!(AuthMethod::None.or_default_any(), AuthMethod::Any);
        assert_eq!(AuthMethod::Bac.or_default_any(), AuthMethod::Bac);
        assert_eq!(AuthMethod::Any.or_default_any(), AuthMethod::Any);
    }

    #[test]
    fn labels() {
        let labels: alloc::vec::Vec<_> = [
            AuthMethod::None,
            AuthMethod::Any,
            AuthMethod::Bac,
            AuthMethod::Pace,
        ]
        .iter()
        .map(|m| alloc::format!("{m}"))
        .collect();
        assert_eq!(labels, ["None", "Any", "BAC", "PACE"]);
    }
}
