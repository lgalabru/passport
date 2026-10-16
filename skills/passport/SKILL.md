---
name: passport
description: |
  Set up and use passport from a coding agent: create the user config at ~/.config/passport/config.yaml and connect the passport MCP server.
  TRIGGERS: "passport", "passport setup", "set up passport", "~/.config/passport", "passport mcp"
  Use when the user mentions passport, asks to configure it, or a passport MCP tool is available.
---

# passport

<!-- What passport is, in two or three sentences, and why an agent should reach for it. -->

## Setup

Run `passport setup` once per machine. It:

1. writes `~/.config/passport/config.yaml` (kept if it exists; `--force` rewrites it,
   `PASSPORT_CONFIG` points elsewhere),
2. installs this skill user-level via skills.sh (`--no-skill` to skip),
3. registers `passport mcp` with Claude Code and Codex (`--no-mcp` to skip).

With the MCP server connected, call the `setup` tool instead; it returns what
each step did, and a retry command for any step that failed.

## Config

```yaml
version: 1
integrations:
  skill: true   # install the agent skill on `passport setup`
  mcp: true     # register the MCP server on `passport setup`
```

## MCP tools

| Tool    | Does                                                    |
| ------- | ------------------------------------------------------- |
| `setup` | Write the config, install the skill, register the MCP.  |

<!-- Add a row per tool, and a `references/` file per topic too long for this page. -->
