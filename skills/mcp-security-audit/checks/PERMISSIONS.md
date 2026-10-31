# Agent permissions and hooks

Claude Code reads `.claude/settings.json` (shared, committed), `.claude/settings.local.json`
(personal, usually git-ignored) and `~/.claude/settings.json` (user). Codex reads
`~/.codex/config.toml`. A committed settings file applies to **everyone who opens the repo**,
including people reviewing an untrusted pull request.

## Bypass modes

- `"permissions": { "defaultMode": "bypassPermissions" }`: no confirmation for any tool.
- `"allow": ["Bash"]` or `"Bash(*)"`: any shell command without confirmation.
- Codex `approval_policy = "never"` together with `sandbox_mode = "danger-full-access"`.

These belong in disposable containers or CI sandboxes, not in a repository's shared settings.
Use narrow rules instead:

```json
{
  "permissions": {
    "allow": ["Bash(npm test:*)", "Bash(git status)", "Bash(git diff:*)"],
    "deny": ["Read(./.env)", "Read(./.env.*)", "Read(./secrets/**)", "Bash(curl:*)"]
  }
}
```

## Auto-approved MCP servers

`"enableAllProjectMcpServers": true` starts every server from any repository's `.mcp.json`
without asking. Combined with unpinned packages it means cloning a repository is enough to run
its code on the next agent session. Approve per project with `enabledMcpjsonServers`.

## Hooks

Hooks run shell commands automatically on agent events (`SessionStart`, `PreToolUse`,
`PostToolUse`, `UserPromptSubmit`, `Stop`, …) with the developer's permissions, with no
confirmation. Review them like a `postinstall` script:

- a download piped into a shell → remote code execution on every session
- `curl -d`, `-F`, `-T`, `POST` → data (prompts, file contents, env) leaving the machine
- commands that read `$CLAUDE_PROJECT_DIR/.env`, `~/.ssh`, `~/.aws`

Formatters and linters (`npx prettier --write …`, `ruff format`) are normal; check that the
package they run is pinned in the project.

## Deny secrets

If the project has `.env`, key files or credential JSON, add `deny` rules so that a prompt
injection cannot simply ask the agent to read and summarise them. This is defence in depth, not
a boundary: tools such as shell commands can still read files unless they are denied too.

## Live checks the developer can run

```bash
cat ~/.claude/settings.json           # user-level hooks and permissions apply to every project
git log -p -- .claude/settings.json   # who added which permission and when
```

Inside a Claude Code session, `/permissions` shows the effective allow/deny rules and `/hooks`
the active hooks.
