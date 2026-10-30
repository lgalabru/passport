//! Data groups / files an eMRTD can be asked to expose.
//!
//! Files are addressed by identifier (`0x011E` for `EF.COM`, `0x0101`..`0x010F`
//! for DG1..DG15); these types keep that mapping in one place.

use alloc::string::String;
use core::fmt;

/// A logical data group DG1..DG15.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DataGroup {
    Dg1,
    Dg2,
    Dg3,
    Dg4,
    Dg5,
    Dg6,
    Dg7,
    Dg8,
    Dg9,
    Dg10,
    Dg11,
    Dg12,
    Dg13,
    Dg14,
    Dg15,
}

/// Every data group, in menu order.
pub const ALL_DATA_GROUPS: [DataGroup; 15] = [
    DataGroup::Dg1,
    DataGroup::Dg2,
    DataGroup::Dg3,
    DataGroup::Dg4,
    DataGroup::Dg5,
    DataGroup::Dg6,
    DataGroup::Dg7,
    DataGroup::Dg8,
    DataGroup::Dg9,
    DataGroup::Dg10,
    DataGroup::Dg11,
    DataGroup::Dg12,
    DataGroup::Dg13,
    DataGroup::Dg14,
    DataGroup::Dg15,
];

impl DataGroup {
    pub const ALL: [DataGroup; 15] = ALL_DATA_GROUPS;

    /// 1..=15
    pub fn number(self) -> u8 {
        match self {
            DataGroup::Dg1 => 1,
            DataGroup::Dg2 => 2,
            DataGroup::Dg3 => 3,
            DataGroup::Dg4 => 4,
            DataGroup::Dg5 => 5,
            DataGroup::Dg6 => 6,
            DataGroup::Dg7 => 7,
            DataGroup::Dg8 => 8,
            DataGroup::Dg9 => 9,
            DataGroup::Dg10 => 10,
            DataGroup::Dg11 => 11,
            DataGroup::Dg12 => 12,
            DataGroup::Dg13 => 13,
            DataGroup::Dg14 => 14,
            DataGroup::Dg15 => 15,
        }
    }

    pub fn from_number(number: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|dg| dg.number() == number)
    }

    /// ISO 7816 file identifier used by SELECT FILE (`0x0100 + n`).
    pub fn file_id(self) -> u16 {
        0x0100 + self.number() as u16
    }

    pub fn from_file_id(file_id: u16) -> Option<Self> {
        if file_id & 0xFF00 != 0x0100 {
            return None;
        }
        Self::from_number((file_id & 0xFF) as u8)
    }

    /// Tag byte this data group is announced with inside the COM `dataGroups`
    /// bitmap (ICAO Doc 9303 Part 10, Table 1).
    ///
    /// Tags `0x70` / `0x77` / `0x42` (DG16, SOD, issuer data) have no
    /// `DataGroup` and yield `None`, so menus skip them.
    pub fn from_tag_byte(tag: u8) -> Option<Self> {
        let number = match tag {
            0x61 => 1,
            0x75 => 2,
            0x63 => 3,
            0x76 => 4,
            0x65 => 5,
            0x66 => 6,
            0x67 => 7,
            0x68 => 8,
            0x69 => 9,
            0x6A => 10,
            0x6B => 11,
            0x6C => 12,
            0x6D => 13,
            0x6E => 14,
            0x6F => 15,
            _ => return None,
        };
        Self::from_number(number)
    }

    pub fn tag_byte(self) -> u8 {
        match self {
            DataGroup::Dg1 => 0x61,
            DataGroup::Dg2 => 0x75,
            DataGroup::Dg3 => 0x63,
            DataGroup::Dg4 => 0x76,
            DataGroup::Dg5 => 0x65,
            DataGroup::Dg6 => 0x66,
            DataGroup::Dg7 => 0x67,
            DataGroup::Dg8 => 0x68,
            DataGroup::Dg9 => 0x69,
            DataGroup::Dg10 => 0x6A,
            DataGroup::Dg11 => 0x6B,
            DataGroup::Dg12 => 0x6C,
            DataGroup::Dg13 => 0x6D,
            DataGroup::Dg14 => 0x6E,
            DataGroup::Dg15 => 0x6F,
        }
    }

    /// Label shown in menus.
    pub fn label(self) -> &'static str {
        match self {
            DataGroup::Dg1 => "DG1 (MRZ)",
            DataGroup::Dg2 => "DG2 (Face)",
            DataGroup::Dg3 => "DG3 (fingers)",
            DataGroup::Dg4 => "DG4 (iris)",
            DataGroup::Dg5 => "DG5",
            DataGroup::Dg6 => "DG6",
            DataGroup::Dg7 => "DG7 (signature)",
            DataGroup::Dg8 => "DG8",
            DataGroup::Dg9 => "DG9",
            DataGroup::Dg10 => "DG10",
            DataGroup::Dg11 => "DG11 (addl person info)",
            DataGroup::Dg12 => "DG12 (addl doc info)",
            DataGroup::Dg13 => "DG13",
            DataGroup::Dg14 => "DG14",
            DataGroup::Dg15 => "DG15",
        }
    }

    /// DG2 / DG7 hold compressed images: they get the look-ahead + stream-to-file
    /// path instead of a plain `.bin` dump.
    pub fn is_image(self) -> bool {
        matches!(self, DataGroup::Dg2 | DataGroup::Dg7)
    }

    /// DG1 is decoded in RAM and rendered as text instead of being dumped.
    pub fn is_mrz(self) -> bool {
        self == DataGroup::Dg1
    }
}

impl fmt::Display for DataGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DG{}", self.number())
    }
}

/// What the reader was asked to fetch: `EF.COM`, `EF.SOD` or one data group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReadTarget {
    /// `EF.COM` (0x011E) — LDS compression/usage description, read for the advanced menu.
    Com,
    /// `EF.SOD` (0x011D) — the Document Security Object: the issuing state's
    /// signature over the data group hashes (Passive Authentication).
    Sod,
    Dg(DataGroup),
}

impl ReadTarget {
    pub fn file_id(self) -> u16 {
        match self {
            ReadTarget::Com => 0x011E,
            ReadTarget::Sod => 0x011D,
            ReadTarget::Dg(dg) => dg.file_id(),
        }
    }

    pub fn from_file_id(file_id: u16) -> Option<Self> {
        match file_id {
            0x011E => Some(ReadTarget::Com),
            0x011D => Some(ReadTarget::Sod),
            other => DataGroup::from_file_id(other).map(ReadTarget::Dg),
        }
    }

    /// Data group number, `None` for `EF.COM` and `EF.SOD`.
    pub fn dg_number(self) -> Option<u8> {
        match self {
            ReadTarget::Com | ReadTarget::Sod => None,
            ReadTarget::Dg(dg) => Some(dg.number()),
        }
    }

    pub fn is_com(self) -> bool {
        self == ReadTarget::Com
    }

    pub fn data_group(self) -> Option<DataGroup> {
        match self {
            ReadTarget::Com | ReadTarget::Sod => None,
            ReadTarget::Dg(dg) => Some(dg),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ReadTarget::Com => "COM",
            ReadTarget::Sod => "SOD",
            ReadTarget::Dg(dg) => dg.label(),
        }
    }

    /// `<doc>-DG<n>.bin` style suffix used for stored dumps (COM → `-COM.bin`).
    pub fn storage_suffix(self) -> String {
        match self {
            ReadTarget::Com => String::from("-COM"),
            ReadTarget::Sod => String::from("-SOD"),
            ReadTarget::Dg(dg) => alloc::format!("-DG{}", dg.number()),
        }
    }
}

impl fmt::Display for ReadTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;

    #[test]
    fn numbers_and_file_ids_cover_dg1_to_dg15() {
        for (i, dg) in DataGroup::ALL.iter().enumerate() {
            let number = i as u8 + 1;
            assert_eq!(dg.number(), number);
            assert_eq!(DataGroup::from_number(number), Some(*dg));
            assert_eq!(dg.file_id(), 0x0100 | u16::from(number));
            assert_eq!(DataGroup::from_file_id(dg.file_id()), Some(*dg));
            assert_eq!(format!("{dg}"), format!("DG{number}"));
        }
    }

    #[test]
    fn invalid_numbers_and_file_ids_are_rejected() {
        assert_eq!(DataGroup::from_number(0), None);
        assert_eq!(DataGroup::from_number(16), None);
        assert_eq!(DataGroup::from_file_id(0x0200), None);
        assert_eq!(DataGroup::from_file_id(0x0110), None);
        assert_eq!(
            DataGroup::from_file_id(0x011E),
            None,
            "COM is not a data group"
        );
    }

    #[test]
    fn tag_bytes_round_trip() {
        for dg in DataGroup::ALL {
            assert_eq!(DataGroup::from_tag_byte(dg.tag_byte()), Some(dg));
        }
        // DG16, SOD, issuer data: announced by cards, not readable here.
        for tag in [0x70, 0x77, 0x42, 0x00, 0xFF] {
            assert_eq!(DataGroup::from_tag_byte(tag), None);
        }
    }

    #[test]
    fn tag_bytes_are_unique() {
        let mut tags: alloc::vec::Vec<u8> = DataGroup::ALL.iter().map(|d| d.tag_byte()).collect();
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(tags.len(), 15);
    }

    #[test]
    fn classification() {
        assert!(DataGroup::Dg1.is_mrz() && !DataGroup::Dg2.is_mrz());
        assert!(DataGroup::Dg2.is_image() && DataGroup::Dg7.is_image());
        assert!(!DataGroup::Dg1.is_image() && !DataGroup::Dg11.is_image());
    }

    #[test]
    fn labels_are_non_empty_and_start_with_the_name() {
        for dg in DataGroup::ALL {
            assert!(dg.label().starts_with(&format!("{dg}")), "{}", dg.label());
        }
    }

    #[test]
    fn read_target_file_ids() {
        assert_eq!(ReadTarget::Com.file_id(), 0x011E);
        assert_eq!(ReadTarget::Dg(DataGroup::Dg2).file_id(), 0x0102);
        assert_eq!(ReadTarget::from_file_id(0x011E), Some(ReadTarget::Com));
        assert_eq!(
            ReadTarget::from_file_id(0x010B),
            Some(ReadTarget::Dg(DataGroup::Dg11))
        );
        assert_eq!(ReadTarget::from_file_id(0x7777), None);
    }

    #[test]
    fn read_target_accessors() {
        assert!(ReadTarget::Com.is_com());
        assert_eq!(ReadTarget::Com.dg_number(), None);
        assert_eq!(ReadTarget::Com.data_group(), None);
        assert_eq!(ReadTarget::Com.storage_suffix(), "-COM");
        assert_eq!(ReadTarget::Com.label(), "COM");

        let dg = ReadTarget::Dg(DataGroup::Dg7);
        assert!(!dg.is_com());
        assert_eq!(dg.dg_number(), Some(7));
        assert_eq!(dg.data_group(), Some(DataGroup::Dg7));
        assert_eq!(dg.storage_suffix(), "-DG7");
        assert_eq!(format!("{dg}"), "DG7 (signature)");
    }
}
