//! Reusable display components for the CLI, shared with solex and pay: a
//! bordered box for listings and results, a railed notice for outcomes, info,
//! warnings and errors, hyperlinks, and identifier helpers. Commands compose
//! these instead of formatting output by hand.

// A component library ahead of its commands: not every helper has a caller yet.
#![allow(dead_code, unused_imports)]

pub mod boxed;
pub mod card;
pub mod label;
pub mod link;
pub mod notice;
pub(crate) mod terminal;

pub use card::Card;
pub use label::{rel, short};
pub use link::{click_hint, explorer_link, link};
pub use notice::{NoticeLevel, print_notice, print_notice_lines};
