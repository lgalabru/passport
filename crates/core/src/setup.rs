//! `passport setup`: write the user config, install the agent skill and
//! register the MCP server with Claude Code and Codex.
//!
//! Each step reports what it did instead of printing, so the CLI can render
//! the report and the MCP `setup` tool can return it. A failing skill or MCP
//! step does not stop the others; only a config error aborts.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use passport_types::Config;
use serde::Serialize;

use crate::{Result, config};

pub const SKILL_REPO: &str = "https://github.com/lgalabru/passport";
pub const SKILL_NAME: &str = "passport";
/// Name the MCP server is registered under in each agent.
pub const MCP_NAME: &str = "passport";

#[derive(Debug, Clone, Default)]
pub struct SetupOptions {
    /// Skip installing the agent skill, and record that in a new config.
    pub no_skill: bool,
    /// Skip registering the MCP server, and record that in a new config.
    pub no_mcp: bool,
    /// Rewrite an existing config with defaults (and the flags above).
    pub force: bool,
    /// Binary the agents should launch as `<bin> mcp`. Defaults to the
    /// running executable.
    pub bin: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SetupReport {
    pub config: ConfigOutcome,
    pub skill: SkillOutcome,
    pub mcp: McpOutcome,
}

impl SetupReport {
    /// True when a step failed; the CLI exits non-zero.
    pub fn has_failures(&self) -> bool {
        matches!(self.skill, SkillOutcome::Failed { .. })
            || matches!(&self.mcp, McpOutcome::Done { failed, .. } if !failed.is_empty())
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ConfigOutcome {
    Created { path: PathBuf },
    Kept { path: PathBuf },
    Overwritten { path: PathBuf },
}

impl ConfigOutcome {
    pub fn path(&self) -> &std::path::Path {
        match self {
            Self::Created { path } | Self::Kept { path } | Self::Overwritten { path } => path,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SkillOutcome {
    Installed,
    Skipped,
    Failed { reason: String, retry: String },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum McpOutcome {
    Skipped,
    /// No agent CLI on PATH: `snippet` is the `mcpServers` entry to add by hand.
    NoHarness {
        snippet: serde_json::Value,
    },
    Done {
        registered: Vec<String>,
        failed: Vec<HarnessFailure>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct HarnessFailure {
    pub harness: String,
    pub reason: String,
}

pub fn run(opts: &SetupOptions) -> Result<SetupReport> {
    let path = config::config_path()?;
    let (cfg, config) = write_config(path, opts)?;

    let skill = if cfg.integrations.skill {
        install_skill()
    } else {
        SkillOutcome::Skipped
    };
    let mcp = if cfg.integrations.mcp {
        let bin = opts.bin.clone().unwrap_or_else(current_bin);
        register_mcp(&bin)
    } else {
        McpOutcome::Skipped
    };
    Ok(SetupReport { config, skill, mcp })
}

/// Keep an existing config unless `force`; a new one records the opt-outs so
/// re-running `passport setup` refreshes the same integrations.
fn write_config(path: PathBuf, opts: &SetupOptions) -> Result<(Config, ConfigOutcome)> {
    let existing = config::load(&path)?;
    if let Some(mut cfg) = existing.clone()
        && !opts.force
    {
        cfg.integrations.skill &= !opts.no_skill;
        cfg.integrations.mcp &= !opts.no_mcp;
        return Ok((cfg, ConfigOutcome::Kept { path }));
    }
    let mut cfg = Config::default();
    cfg.integrations.skill = !opts.no_skill;
    cfg.integrations.mcp = !opts.no_mcp;
    config::save(&path, &cfg)?;
    let outcome = if existing.is_some() {
        ConfigOutcome::Overwritten { path }
    } else {
        ConfigOutcome::Created { path }
    };
    Ok((cfg, outcome))
}

fn current_bin() -> String {
    std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "passport".into())
}

fn npx() -> &'static str {
    if cfg!(windows) { "npx.cmd" } else { "npx" }
}

fn has(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// `npx skills add` is the installer the skills.sh ecosystem uses; it places
/// the skill where each detected agent (Claude Code, Cursor, Codex, ...) reads
/// it. `-g` installs user-level so setup never drops `.agents/` or `.claude/`
/// into whatever directory it was run from.
fn install_skill() -> SkillOutcome {
    let retry = format!("npx -y skills add {SKILL_REPO} --skill {SKILL_NAME} -g -y");
    if !has(npx()) {
        return SkillOutcome::Failed {
            reason: "npx not found; install Node.js".into(),
            retry,
        };
    }
    let out = Command::new(npx())
        .args([
            "-y", "skills", "add", SKILL_REPO, "--skill", SKILL_NAME, "-g", "-y",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
    match out {
        Ok(out) if out.status.success() => SkillOutcome::Installed,
        Ok(out) => SkillOutcome::Failed {
            reason: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            retry,
        },
        Err(e) => SkillOutcome::Failed {
            reason: format!("failed to run npx: {e}"),
            retry,
        },
    }
}

/// An agent CLI that manages MCP servers with `<cli> mcp add|get`.
struct Agent {
    label: &'static str,
    bin: &'static str,
    /// Arguments placed between `mcp add` and the server name.
    add_flags: &'static [&'static str],
}

const AGENTS: &[Agent] = &[
    Agent {
        label: "Claude Code",
        bin: "claude",
        add_flags: &["--scope", "user"],
    },
    Agent {
        label: "Codex",
        bin: "codex",
        add_flags: &[],
    },
];

fn registered_with(agent: &Agent) -> bool {
    Command::new(agent.bin)
        .args(["mcp", "get", MCP_NAME])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Register `<bin> mcp` with every agent CLI on PATH, skipping the ones that
/// already have it.
fn register_mcp(bin: &str) -> McpOutcome {
    let found: Vec<&Agent> = AGENTS.iter().filter(|a| has(a.bin)).collect();
    if found.is_empty() {
        return McpOutcome::NoHarness {
            snippet: serde_json::json!({
                "mcpServers": { MCP_NAME: { "command": bin, "args": ["mcp"] } }
            }),
        };
    }
    let mut registered = Vec::new();
    let mut failed = Vec::new();
    for agent in found {
        if registered_with(agent) {
            registered.push(agent.label.to_string());
            continue;
        }
        let out = Command::new(agent.bin)
            .args(["mcp", "add"])
            .args(agent.add_flags)
            .args([MCP_NAME, "--", bin, "mcp"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output();
        match out {
            Ok(out) => {
                let msg = String::from_utf8_lossy(&out.stderr);
                if out.status.success() || msg.contains("already exists") {
                    registered.push(agent.label.to_string());
                } else {
                    failed.push(HarnessFailure {
                        harness: agent.label.to_string(),
                        reason: msg.trim().to_string(),
                    });
                }
            }
            Err(e) => failed.push(HarnessFailure {
                harness: agent.label.to_string(),
                reason: format!("failed to run {}: {e}", agent.bin),
            }),
        }
    }
    McpOutcome::Done { registered, failed }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(no_skill: bool, force: bool) -> SetupOptions {
        SetupOptions {
            no_skill,
            force,
            ..Default::default()
        }
    }

    #[test]
    fn new_config_records_opt_outs() {
        let dir = tempfile::tempdir().unwrap();
        let path = config::default_path(dir.path());
        let (cfg, outcome) = write_config(path.clone(), &opts(true, false)).unwrap();
        assert!(matches!(outcome, ConfigOutcome::Created { .. }));
        assert!(!cfg.integrations.skill);
        assert!(cfg.integrations.mcp);
        assert_eq!(config::load(&path).unwrap(), Some(cfg));
    }

    #[test]
    fn existing_config_is_kept_unless_forced() {
        let dir = tempfile::tempdir().unwrap();
        let path = config::default_path(dir.path());
        write_config(path.clone(), &opts(true, false)).unwrap();

        let (cfg, outcome) = write_config(path.clone(), &opts(false, false)).unwrap();
        assert!(matches!(outcome, ConfigOutcome::Kept { .. }));
        assert!(
            !cfg.integrations.skill,
            "the recorded opt-out still applies"
        );

        let (cfg, outcome) = write_config(path, &opts(false, true)).unwrap();
        assert!(matches!(outcome, ConfigOutcome::Overwritten { .. }));
        assert!(cfg.integrations.skill);
    }

    #[test]
    fn report_serializes_with_status_tags() {
        let report = SetupReport {
            config: ConfigOutcome::Kept {
                path: "/x/config.yaml".into(),
            },
            skill: SkillOutcome::Skipped,
            mcp: McpOutcome::Done {
                registered: vec!["Codex".into()],
                failed: vec![],
            },
        };
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["config"]["status"], "kept");
        assert_eq!(v["mcp"]["registered"][0], "Codex");
        assert!(!report.has_failures());
    }
}
