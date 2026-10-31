# MCP client configuration

Where to look: `.mcp.json` (Claude Code, project scope), `~/.claude.json` (user and local scope,
under `mcpServers` and `projects.<path>.mcpServers`), `.cursor/mcp.json` and `~/.cursor/mcp.json`,
`.vscode/mcp.json` (`servers` + `inputs`), `claude_desktop_config.json`, `~/.codeium/windsurf/mcp_config.json`,
`.gemini/settings.json`, `~/.codex/config.toml` (`[mcp_servers.<name>]`), Cline/Roo `mcp_settings.json`.

Every entry is code that runs on the developer machine (stdio servers) or a remote party the
agent trusts (HTTP servers). Review each one as you would a new dependency **plus** a new
source of prompts.

## Hardcoded secrets

A literal token in `env`, `headers`, `args` or the URL. Project configs get committed; user
configs get pasted into issues, screenshots and dotfile repos.

```jsonc
// bad
"env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_…" }
// good: reference the environment
"env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_PERSONAL_ACCESS_TOKEN}" }
```

Use the client's variable syntax: `${VAR}` / `${VAR:-default}` in Claude Code's `.mcp.json`,
`${env:VAR}` in Cursor and VS Code, or a VS Code `inputs` prompt with `"password": true`.

Confirming: is the file tracked (`git ls-files`), and was it ever committed
(`git log --all -p -- <file>`)? If yes, the key is burned: **rotate first**, then clean history.
Also check scope: a GitHub token with access to all repositories turns any prompt injection
into an org-wide incident. Prefer fine-grained tokens limited to the repos the agent needs.

## Unpinned packages

`npx -y some-mcp-server`, `uvx some-server`, `pnpm dlx`, `bunx`, or a Docker image without a
tag/digest run **the newest version at every launch**. MCP servers have the agent's reach:
files, tokens, shell. A compromised maintainer account, a typosquat or a sold package ("rug
pull") reaches every developer on the next restart, and tool descriptions can change after you
approved them.

- npm: `@scope/server@1.4.2` (exact version, not `@latest`, `^`, `~`)
- uv: `package==1.4.2` or `package@1.4.2`
- Docker: `image@sha256:<digest>` (a tag can be moved)

Confirming: check the package name against the official source the README links to
(typosquats differ by one character or scope), its weekly downloads, repository link and
recent maintainer changes.

## Plain HTTP

`http://` to anything other than `localhost` / `127.0.0.1` sends tokens in clear text and lets
anyone on the path rewrite tool lists and results, which is prompt injection with a network
position. Use `https://`. Local `http://localhost` servers are fine for transport, but see
`SERVERS.md#network-exposure` for DNS rebinding.

## Shell launchers

```json
"command": "bash", "args": ["-c", "<download install.sh> | sh && server"]
```

What runs is decided at launch time by a remote file. `bash -c "source ~/.nvm/nvm.sh && npx …"`
is a common workaround for PATH problems; it is not malicious, but it hides the real command
from reviews and from the client's approval dialog. Prefer an absolute path to the binary and
an argument array.

`cmd /c npx …` on Windows is the documented way to start npx-based servers in some clients;
the scanner does not flag it, but it still checks the package after `npx` for pinning.

## Docker escapes

Containers are a good boundary **unless** the config removes it:

| Flag | Why it matters |
|---|---|
| `--privileged` | full device access, trivial host escape |
| `-v /var/run/docker.sock:…` | the server can start a privileged container: host root |
| `-v /:/host`, `-v $HOME:…` | the whole disk or home directory (SSH keys, cloud credentials) |
| `--network host`, `--pid host` | host network services and processes |
| `--cap-add SYS_ADMIN` / `ALL` | most of `--privileged` |

Mount only the project folder, read-only when possible (`:ro`).

## Broad filesystem roots

The filesystem server's positional arguments are the directories it may touch. `/`, `~`,
`C:\` or `/Users/<name>` give it SSH keys, browser profiles, password-manager exports and every
other project. Pass the project folder (or a subfolder like `./docs`).

## mcp-remote CVE-2025-6514

`mcp-remote` bridges stdio clients to remote servers. Versions **0.0.5 to 0.1.15** passed the
`authorization_endpoint` returned by the remote server to the OS URL opener, so a malicious or
compromised server could run commands on the developer machine (CVSS 9.6). Fixed in **0.1.16**.
Pin `mcp-remote@0.1.16` or later, and only connect to servers you trust.

## Secrets in args

`["--api-key", "${KEY}"]` expands to a literal key on the process command line, visible to
other local users and processes (`ps`, `/proc/<pid>/cmdline`) and often copied into logs and
crash reports. Use `env`.

## Live checks the developer can run

```bash
# which servers will actually start (Claude Code)
claude mcp list
# tracked config files and their history
git ls-files | grep -Ei '(^|/)(\.mcp\.json|mcp\.json|mcp_config\.json|settings\.json|config\.toml)$'
git log --all --oneline -- .mcp.json .cursor/mcp.json .vscode/mcp.json
```
