//! `~/.config/passport/config.yaml`.

use serde::{Deserialize, Serialize};

/// Schema version written by this release. Bump it when a field changes
/// meaning, so older files can be migrated instead of misread.
pub const CONFIG_VERSION: u32 = 1;

/// User configuration. Every field has a default, so a partial or empty
/// file still loads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub version: u32,
    /// What `passport setup` installed, so a re-run refreshes the same set.
    pub integrations: Integrations,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            integrations: Integrations::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Integrations {
    /// Install the passport agent skill (skills.sh, user level).
    pub skill: bool,
    /// Register `passport mcp` with the agent CLIs found on PATH.
    pub mcp: bool,
}

impl Default for Integrations {
    fn default() -> Self {
        Self {
            skill: true,
            mcp: true,
        }
    }
}
