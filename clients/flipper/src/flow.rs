//! Which screen follows which. The device layer turns a [`Nav`] into calls on
//! the firmware's scene manager; keeping the decisions here makes them testable.

use passport_driver_emrtd::types::{DataGroup, ReadTarget};

use crate::screens::{AuthItem, MainItem};
use crate::session::Session;

/// A screen of the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scene {
    MainMenu,
    AuthMenu,
    Read,
    ReadError,
    ReadSuccess,
    PassportNumberInput,
    DobInput,
    DoeInput,
    Delete,
    DeleteSuccess,
    AdvancedMenu,
    KnownIssues,
    AdvWarning,
}

impl Scene {
    pub const ALL: [Scene; 13] = [
        Scene::MainMenu,
        Scene::AuthMenu,
        Scene::Read,
        Scene::ReadError,
        Scene::ReadSuccess,
        Scene::PassportNumberInput,
        Scene::DobInput,
        Scene::DoeInput,
        Scene::Delete,
        Scene::DeleteSuccess,
        Scene::AdvancedMenu,
        Scene::KnownIssues,
        Scene::AdvWarning,
    ];

    /// Index into the scene manager's handler tables.
    pub fn index(self) -> u32 {
        self as u32
    }

    pub fn from_index(index: u32) -> Option<Scene> {
        Scene::ALL.get(index as usize).copied()
    }
}

/// A navigation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nav {
    /// Nothing to do.
    Stay,
    /// Open a screen on top of the current one.
    Push(Scene),
    /// Back to the previous screen.
    Pop,
    /// Back to the nearest screen of this kind in the history.
    PopTo(Scene),
    /// Back to the nearest of these, trying them in the history order.
    PopToAny(&'static [Scene]),
    /// Leave the app.
    Exit,
}

/// Choice in the main menu.
pub fn main_select(item: MainItem, session: &mut Session) -> Nav {
    match item {
        // A guided tour while anything is missing, the overview once all is set.
        MainItem::EnterMrz => Nav::Push(next_missing(session).unwrap_or(Scene::AuthMenu)),
        MainItem::DeleteMrz => Nav::Push(Scene::Delete),
        MainItem::KnownIssues => Nav::Push(Scene::KnownIssues),
        MainItem::ReadDg1 => read(session, ReadTarget::Dg(DataGroup::Dg1), Scene::Read),
        MainItem::ReadDg2 => read(session, ReadTarget::Dg(DataGroup::Dg2), Scene::Read),
        // `EF.COM` first, to learn which groups exist; the warning comes before it.
        MainItem::ReadAdvanced => read(session, ReadTarget::Com, Scene::AdvWarning),
    }
}

fn read(session: &mut Session, target: ReadTarget, scene: Scene) -> Nav {
    session.select_target(target);
    Nav::Push(scene)
}

/// Choice in the auth menu.
pub fn auth_select(item: AuthItem) -> Nav {
    match item {
        AuthItem::DocumentNumber => Nav::Push(Scene::PassportNumberInput),
        AuthItem::DateOfBirth => Nav::Push(Scene::DobInput),
        AuthItem::DateOfExpiry => Nav::Push(Scene::DoeInput),
        // The method is changed in place with left/right.
        AuthItem::Method => Nav::Stay,
    }
}

/// Choice of a data group in the advanced menu.
pub fn advanced_select(group: DataGroup, session: &mut Session) -> Nav {
    read(session, ReadTarget::Dg(group), Scene::Read)
}

/// The user confirmed the advanced-menu warning.
pub fn warning_confirmed(session: &mut Session) -> Nav {
    read(session, ReadTarget::Com, Scene::Read)
}

/// Where a finished read goes: `EF.COM` feeds the advanced menu, anything else
/// is shown.
pub fn read_finished(target: ReadTarget) -> Nav {
    match target {
        ReadTarget::Com => Nav::Push(Scene::AdvancedMenu),
        ReadTarget::Dg(_) | ReadTarget::Sod => Nav::Push(Scene::ReadSuccess),
    }
}

/// A read failed: show the error.
pub fn read_failed() -> Nav {
    Nav::Push(Scene::ReadError)
}

/// The "Retry" button on the error screen.
pub fn retry() -> Nav {
    Nav::Pop
}

/// The delete confirmation.
pub fn delete_confirmed(deleted: bool) -> Nav {
    if deleted {
        Nav::Push(Scene::DeleteSuccess)
    } else {
        Nav::PopTo(Scene::MainMenu)
    }
}

/// The first entry screen whose field is still empty.
fn next_missing(session: &Session) -> Option<Scene> {
    if session.document_number().is_empty() {
        Some(Scene::PassportNumberInput)
    } else if session.date_of_birth().is_empty() {
        Some(Scene::DobInput)
    } else if session.date_of_expiry().is_empty() {
        Some(Scene::DoeInput)
    } else {
        None
    }
}

/// After an entry is saved. Opened from the overview, it goes back there; on
/// the guided tour it moves on to the next empty field and finally to the main
/// menu, where the read items have just appeared.
pub fn input_done(session: &Session, history: &[Scene]) -> Nav {
    if history.contains(&Scene::AuthMenu) {
        return Nav::Pop;
    }
    match next_missing(session) {
        Some(scene) => Nav::Push(scene),
        None => Nav::PopTo(Scene::MainMenu),
    }
}

const SUCCESS_BACK: &[Scene] = &[Scene::AdvancedMenu, Scene::MainMenu];

/// The back button. `history` is the scene stack, oldest first, not including
/// the current scene.
pub fn back(current: Scene, history: &[Scene]) -> Nav {
    match current {
        Scene::MainMenu => Nav::Exit,
        Scene::AdvancedMenu | Scene::Read | Scene::DeleteSuccess => Nav::PopTo(Scene::MainMenu),
        Scene::ReadError if history.contains(&Scene::AdvancedMenu) => {
            Nav::PopTo(Scene::AdvancedMenu)
        }
        Scene::ReadError => Nav::PopTo(Scene::MainMenu),
        Scene::ReadSuccess => Nav::PopToAny(SUCCESS_BACK),
        Scene::AuthMenu
        | Scene::PassportNumberInput
        | Scene::DobInput
        | Scene::DoeInput
        | Scene::Delete
        | Scene::KnownIssues
        | Scene::AdvWarning => Nav::Pop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dg(group: DataGroup) -> Option<ReadTarget> {
        Some(ReadTarget::Dg(group))
    }

    #[test]
    fn scene_indices_are_dense_and_round_trip() {
        for (i, scene) in Scene::ALL.iter().enumerate() {
            assert_eq!(scene.index() as usize, i);
            assert_eq!(Scene::from_index(i as u32), Some(*scene));
        }
        assert_eq!(Scene::from_index(13), None);
    }

    #[test]
    fn main_menu_routes() {
        let mut s = Session::new();
        assert_eq!(
            main_select(MainItem::EnterMrz, &mut s),
            Nav::Push(Scene::PassportNumberInput)
        );
        assert_eq!(
            main_select(MainItem::DeleteMrz, &mut s),
            Nav::Push(Scene::Delete)
        );
        assert_eq!(
            main_select(MainItem::KnownIssues, &mut s),
            Nav::Push(Scene::KnownIssues)
        );
        assert_eq!(
            s.target(),
            None,
            "navigation alone does not choose a target"
        );
    }

    #[test]
    fn reads_record_their_target() {
        let mut s = Session::new();
        assert_eq!(
            main_select(MainItem::ReadDg1, &mut s),
            Nav::Push(Scene::Read)
        );
        assert_eq!(s.target(), dg(DataGroup::Dg1));
        assert_eq!(
            main_select(MainItem::ReadDg2, &mut s),
            Nav::Push(Scene::Read)
        );
        assert_eq!(s.target(), dg(DataGroup::Dg2));
    }

    #[test]
    fn advanced_read_warns_first_then_reads_com() {
        let mut s = Session::new();
        assert_eq!(
            main_select(MainItem::ReadAdvanced, &mut s),
            Nav::Push(Scene::AdvWarning)
        );
        assert_eq!(s.target(), Some(ReadTarget::Com));
        s.select_target(ReadTarget::Dg(DataGroup::Dg1));
        assert_eq!(warning_confirmed(&mut s), Nav::Push(Scene::Read));
        assert_eq!(s.target(), Some(ReadTarget::Com));
    }

    #[test]
    fn advanced_menu_selection_reads_that_group() {
        let mut s = Session::new();
        assert_eq!(
            advanced_select(DataGroup::Dg11, &mut s),
            Nav::Push(Scene::Read)
        );
        assert_eq!(s.target(), dg(DataGroup::Dg11));
    }

    #[test]
    fn auth_menu_routes() {
        assert_eq!(
            auth_select(AuthItem::DocumentNumber),
            Nav::Push(Scene::PassportNumberInput)
        );
        assert_eq!(
            auth_select(AuthItem::DateOfBirth),
            Nav::Push(Scene::DobInput)
        );
        assert_eq!(
            auth_select(AuthItem::DateOfExpiry),
            Nav::Push(Scene::DoeInput)
        );
        assert_eq!(auth_select(AuthItem::Method), Nav::Stay);
    }

    #[test]
    fn finished_reads() {
        assert_eq!(
            read_finished(ReadTarget::Com),
            Nav::Push(Scene::AdvancedMenu)
        );
        for group in DataGroup::ALL {
            assert_eq!(
                read_finished(ReadTarget::Dg(group)),
                Nav::Push(Scene::ReadSuccess)
            );
        }
        assert_eq!(read_failed(), Nav::Push(Scene::ReadError));
        assert_eq!(retry(), Nav::Pop);
    }

    #[test]
    fn delete_outcomes() {
        assert_eq!(delete_confirmed(true), Nav::Push(Scene::DeleteSuccess));
        assert_eq!(delete_confirmed(false), Nav::PopTo(Scene::MainMenu));
    }

    #[test]
    fn back_from_the_main_menu_exits() {
        assert_eq!(back(Scene::MainMenu, &[]), Nav::Exit);
    }

    #[test]
    fn back_from_read_flows_returns_to_the_menu() {
        let history = [Scene::MainMenu];
        for scene in [Scene::Read, Scene::AdvancedMenu, Scene::DeleteSuccess] {
            assert_eq!(
                back(scene, &history),
                Nav::PopTo(Scene::MainMenu),
                "{scene:?}"
            );
        }
    }

    #[test]
    fn back_from_an_error_prefers_the_advanced_menu_when_it_is_underneath() {
        let plain = [Scene::MainMenu, Scene::Read];
        assert_eq!(back(Scene::ReadError, &plain), Nav::PopTo(Scene::MainMenu));
        let advanced = [
            Scene::MainMenu,
            Scene::AdvWarning,
            Scene::Read,
            Scene::AdvancedMenu,
            Scene::Read,
        ];
        assert_eq!(
            back(Scene::ReadError, &advanced),
            Nav::PopTo(Scene::AdvancedMenu)
        );
    }

    #[test]
    fn back_from_a_result_tries_advanced_then_main() {
        assert_eq!(
            back(Scene::ReadSuccess, &[Scene::MainMenu]),
            Nav::PopToAny(&[Scene::AdvancedMenu, Scene::MainMenu])
        );
    }

    #[test]
    fn plain_screens_just_pop() {
        for scene in [
            Scene::AuthMenu,
            Scene::PassportNumberInput,
            Scene::DobInput,
            Scene::DoeInput,
            Scene::Delete,
            Scene::KnownIssues,
            Scene::AdvWarning,
        ] {
            assert_eq!(back(scene, &[Scene::MainMenu]), Nav::Pop, "{scene:?}");
        }
    }

    #[test]
    fn every_scene_has_a_back_action() {
        for scene in Scene::ALL {
            let _ = back(scene, &[Scene::MainMenu]);
        }
    }

    #[test]
    fn guided_entry_walks_through_the_missing_fields() {
        let mut s = Session::new();
        let tour: &[Scene] = &[Scene::MainMenu, Scene::PassportNumberInput];

        s.set_document_number("L898902C").unwrap();
        assert_eq!(input_done(&s, tour), Nav::Push(Scene::DobInput));
        s.set_date_of_birth("690806").unwrap();
        assert_eq!(input_done(&s, tour), Nav::Push(Scene::DoeInput));
        s.set_date_of_expiry("940623").unwrap();
        assert_eq!(input_done(&s, tour), Nav::PopTo(Scene::MainMenu));
    }

    #[test]
    fn guided_entry_starts_at_the_first_empty_field() {
        let mut s = Session::new();
        s.set_document_number("L898902C").unwrap();
        assert_eq!(
            main_select(MainItem::EnterMrz, &mut s),
            Nav::Push(Scene::DobInput)
        );
        s.set_date_of_birth("690806").unwrap();
        s.set_date_of_expiry("940623").unwrap();
        assert_eq!(
            main_select(MainItem::EnterMrz, &mut s),
            Nav::Push(Scene::AuthMenu)
        );
    }

    #[test]
    fn editing_from_the_overview_returns_to_it() {
        let mut s = Session::new();
        s.set_document_number("L898902C").unwrap();
        let overview: &[Scene] = &[Scene::MainMenu, Scene::AuthMenu];
        assert_eq!(input_done(&s, overview), Nav::Pop);
    }
}
