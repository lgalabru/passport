//! `passport setup`: write `~/.config/passport/config.yaml`, install the agent
//! skill and register the MCP server with Claude Code and Codex. The work
//! lives in `passport_core::setup`, shared with the MCP `setup` tool; this
//! renders its report.

use clap::Args;
use passport_core::{
    CoreError, Result,
    setup::{self, ConfigOutcome, McpOutcome, SetupOptions, SetupReport, SkillOutcome},
};

use crate::{components, style};

#[derive(Args, Debug, Default)]
pub struct SetupCommand {
    /// Skip installing the agent skill
    #[arg(long)]
    pub no_skill: bool,

    /// Skip registering `passport mcp` with Claude Code and Codex (user scope)
    #[arg(long)]
    pub no_mcp: bool,

    /// Rewrite an existing config with defaults
    #[arg(long)]
    pub force: bool,
}

impl SetupCommand {
    pub fn execute(&self) -> Result<()> {
        let opts = SetupOptions {
            no_skill: self.no_skill,
            no_mcp: self.no_mcp,
            force: self.force,
            bin: None,
        };
        let sp = style::spinner("Setting up passport...");
        let report = setup::run(&opts);
        sp.finish_and_clear();
        let report = report?;
        render(&report);
        if report.has_failures() {
            return Err(CoreError::message(""));
        }
        Ok(())
    }
}

fn render(report: &SetupReport) {
    let status = match &report.config {
        ConfigOutcome::Created { .. } => "created",
        ConfigOutcome::Kept { .. } => "kept",
        ConfigOutcome::Overwritten { .. } => "overwritten",
    };
    let skill = match &report.skill {
        SkillOutcome::Installed => "installed (user level)",
        SkillOutcome::Skipped => "skipped",
        SkillOutcome::Failed { .. } => "failed",
    };
    let mcp = match &report.mcp {
        McpOutcome::Skipped => "skipped".to_string(),
        McpOutcome::NoHarness { .. } => "no agent CLI found".to_string(),
        McpOutcome::Done { registered, .. } if registered.is_empty() => "failed".to_string(),
        McpOutcome::Done { registered, .. } => registered.join(", "),
    };
    let mut card = components::Card::new("passport", Some("setup"))
        .right(status)
        .text("config", tilde(report.config.path()))
        .text("skill", skill)
        .text("mcp", mcp);
    if matches!(&report.mcp, McpOutcome::Done { registered, .. } if !registered.is_empty()) {
        card = card.text("tools", passport_mcp::tool_names().join(", "));
    }
    eprintln!("{}", card.frame());

    if let SkillOutcome::Failed { reason, retry } = &report.skill {
        components::print_notice(
            components::NoticeLevel::Error,
            "Skill install failed",
            &format!("{reason}\nRetry with:\n  {retry}"),
        );
    }
    match &report.mcp {
        McpOutcome::NoHarness { snippet } => components::print_notice(
            components::NoticeLevel::Warning,
            "No agent CLI found (claude, codex); add the MCP server to your client yourself",
            &serde_json::to_string_pretty(snippet).unwrap_or_default(),
        ),
        McpOutcome::Done { failed, .. } => {
            for f in failed {
                components::print_notice(
                    components::NoticeLevel::Error,
                    &format!("{} mcp add failed", f.harness),
                    &f.reason,
                );
            }
        }
        McpOutcome::Skipped => {}
    }
}

/// `~/...` for paths under the home directory.
fn tilde(path: &std::path::Path) -> String {
    match dirs::home_dir().and_then(|h| path.strip_prefix(h).ok().map(|p| p.to_path_buf())) {
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}
