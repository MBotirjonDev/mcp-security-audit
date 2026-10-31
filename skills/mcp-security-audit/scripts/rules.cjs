'use strict';
/**
 * Rule catalogue for mcp-security-audit. Detection logic lives in scan.cjs;
 * this file holds what each rule means, how bad it usually is, and how to fix it.
 *
 *   id        <FAMILY>-<AREA>-<NNN>
 *             MCP-CFG  MCP client configuration (.mcp.json, Cursor, VS Code, Claude Desktop, Codex)
 *             MCP-SRV  MCP server source code (tools you build and ship)
 *             AGT-INJ  agent instruction files (CLAUDE.md, AGENTS.md, .cursorrules, SKILL.md …)
 *             AGT-PERM agent permissions and hooks (.claude/settings.json …)
 *   severity  critical | high | medium | low | info   (triage guess; the skill confirms it)
 *   guide     checks/<FILE>.md#anchor
 */
module.exports = {
  // ── MCP client configuration ────────────────────────────────────────────────
  'MCP-CFG-001': {
    title: 'Hardcoded secret in an MCP server config',
    severity: 'critical',
    cwe: 'CWE-798',
    guide: 'CONFIGS.md#hardcoded-secrets',
    message: 'An API key or token is written literally into the MCP config (env, args, headers or URL). Project configs get committed and shared; global configs get synced and pasted into issues.',
    fix: 'Rotate the key. Reference it from the environment instead: "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"} (Claude Code, Cursor) or an "inputs" prompt (VS Code), and keep .mcp.json free of literals.',
  },
  'MCP-CFG-002': {
    title: 'MCP server package is not pinned to a version',
    severity: 'medium',
    cwe: 'CWE-1357',
    guide: 'CONFIGS.md#unpinned-packages',
    message: 'npx / uvx / bunx / pnpm dlx runs whatever version is newest at launch time. A compromised or sold package ("rug pull") lands on every developer machine on the next restart, with the agent\'s permissions.',
    fix: 'Pin an exact version you reviewed: "args": ["-y", "@scope/server@1.4.2"]; for uvx use "package==1.4.2". Update deliberately.',
  },
  'MCP-CFG-003': {
    title: 'Remote MCP server over plain HTTP',
    severity: 'high',
    cwe: 'CWE-319',
    guide: 'CONFIGS.md#plain-http',
    message: 'The client talks to a non-local MCP server over http://. Anyone on the network path can read the tokens and rewrite tool descriptions and results, which is prompt injection with a network position.',
    fix: 'Use https:// for every non-localhost server.',
  },
  'MCP-CFG-004': {
    title: 'MCP server launched through a shell or a download pipe',
    severity: 'high',
    cwe: 'CWE-78',
    guide: 'CONFIGS.md#shell-launchers',
    message: 'The server command is bash -c / sh -c / powershell -Command, or pipes a download into a shell. What runs is decided at launch time by a string or a remote file, not by a reviewed package.',
    fix: 'Launch the binary or package directly with an argument array and a pinned version. Never curl | sh in an MCP config.',
  },
  'MCP-CFG-005': {
    title: 'Docker-based MCP server with host-level access',
    severity: 'high',
    cwe: 'CWE-250',
    guide: 'CONFIGS.md#docker-escapes',
    message: 'docker run with --privileged, the Docker socket, the host root or home directory mounted, or --network host gives the server (and any prompt injection that steers it) control of the host.',
    fix: 'Drop --privileged, mount only the project folder (read-only when possible), never mount /var/run/docker.sock, and pin the image by digest.',
  },
  'MCP-CFG-006': {
    title: 'Filesystem MCP server with a very broad root',
    severity: 'medium',
    cwe: 'CWE-732',
    guide: 'CONFIGS.md#broad-filesystem-roots',
    message: 'The filesystem server is allowed to read and write /, the home directory or a whole drive: SSH keys, browser profiles, cloud credentials and other projects become one prompt injection away.',
    fix: 'Pass only the project directories the agent needs.',
  },
  'MCP-CFG-007': {
    title: 'mcp-remote version affected by CVE-2025-6514',
    severity: 'critical',
    cwe: 'CWE-78',
    guide: 'CONFIGS.md#mcp-remote-cve-2025-6514',
    message: 'mcp-remote 0.0.5–0.1.15 passes the authorization_endpoint from the remote server to the OS opener, which a malicious or compromised MCP server can turn into command execution on the developer machine.',
    fix: 'Use mcp-remote 0.1.16 or later (pin it), and connect only to servers you trust.',
  },
  'MCP-CFG-008': {
    title: 'Secret passed on the command line',
    severity: 'medium',
    cwe: 'CWE-214',
    guide: 'CONFIGS.md#secrets-in-args',
    message: 'A token or key is passed as a command-line argument. Arguments are visible to every local process (ps, /proc) and end up in logs and crash reports.',
    fix: 'Pass secrets through env, not args.',
  },

  // ── MCP server source code ──────────────────────────────────────────────────
  'MCP-SRV-001': {
    title: 'Shell command built from tool input',
    severity: 'high',
    cwe: 'CWE-78',
    guide: 'SERVERS.md#command-injection',
    message: 'The MCP server runs a shell command assembled with string interpolation or shell=True. Tool arguments are chosen by the model, and the model can be steered by any document, web page or issue it reads.',
    fix: 'Use execFile/spawn (Node) or subprocess.run([...], shell=False) (Python) with an argument array, validate arguments against an allowlist, and put "--" before user-supplied paths.',
  },
  'MCP-SRV-002': {
    title: 'Tool description contains instructions aimed at the model',
    severity: 'high',
    cwe: 'CWE-1427',
    guide: 'SERVERS.md#tool-poisoning',
    message: 'A tool description or prompt contains hidden-instruction markers (<IMPORTANT>, "ignore previous instructions", "do not tell the user", reading ~/.ssh or .env). Descriptions go straight into the model context and the user rarely sees them: this is the tool-poisoning pattern.',
    fix: 'Descriptions should only describe what the tool does and its parameters. Remove instructions about other tools, secrets or hiding behaviour from the user.',
  },
  'MCP-SRV-003': {
    title: 'File path from tool input without a containment check',
    severity: 'medium',
    cwe: 'CWE-22',
    guide: 'SERVERS.md#path-traversal',
    message: 'The server reads or writes a file using a path from tool arguments and the file has no resolve-and-compare check. ../../.ssh/id_rsa, symlinks and absolute paths can escape the intended folder.',
    fix: 'Resolve the real path (fs.realpath / os.path.realpath) and require it to start with the allowed root plus a separator; reject everything else.',
  },
  'MCP-SRV-004': {
    title: 'Outbound request to a URL from tool input',
    severity: 'medium',
    cwe: 'CWE-918',
    guide: 'SERVERS.md#ssrf',
    message: 'The server fetches a URL taken from tool arguments. A steered model can make it call cloud metadata endpoints (169.254.169.254), internal services or localhost admin panels, and return the response into the chat.',
    fix: 'Allow only http(s), resolve the host and block private, loopback and link-local ranges (re-check after redirects), or restrict to an allowlist of domains.',
  },
  'MCP-SRV-005': {
    title: 'Dynamic code execution in an MCP server',
    severity: 'high',
    cwe: 'CWE-95',
    guide: 'SERVERS.md#dynamic-code',
    message: 'eval / new Function / exec / pickle.loads / unsafe yaml.load in a server whose inputs come from the model. One injected document is enough to run code with the server\'s permissions.',
    fix: 'Remove dynamic evaluation. Parse data with JSON / yaml.safe_load, and use a real sandbox if code execution is the product.',
  },
  'MCP-SRV-006': {
    title: 'HTTP MCP server listening on all interfaces',
    severity: 'medium',
    cwe: 'CWE-1327',
    guide: 'SERVERS.md#network-exposure',
    message: 'The server binds 0.0.0.0, so anyone on the same network (café Wi-Fi, office LAN) can call its tools. Local HTTP/SSE servers without Origin checks are also reachable from web pages through DNS rebinding.',
    fix: 'Bind 127.0.0.1 for local servers, require authentication for remote ones, and validate the Origin header.',
  },
  'MCP-SRV-007': {
    title: 'Token passthrough to a downstream API',
    severity: 'medium',
    cwe: 'CWE-863',
    guide: 'SERVERS.md#token-passthrough',
    message: 'The server forwards the client\'s Authorization header straight to another API. The MCP spec forbids token passthrough: the server cannot check audience or scope, and a stolen token works everywhere.',
    fix: 'Validate tokens issued for this server (audience), and call downstream APIs with the server\'s own credentials or a token exchange.',
  },

  // ── Agent instruction files ─────────────────────────────────────────────────
  'AGT-INJ-001': {
    title: 'Invisible Unicode tag characters (hidden text)',
    severity: 'critical',
    cwe: 'CWE-1427',
    guide: 'INSTRUCTIONS.md#invisible-unicode',
    message: 'The file contains Unicode tag characters (U+E0000–U+E007F). They render as nothing in editors and on GitHub but models read them as text: a known way to hide instructions in rules files ("rules file backdoor").',
    fix: 'Delete the characters (reveal them with scripts/reveal.cjs), find out how they got in, and review the commit that added them.',
  },
  'AGT-INJ-002': {
    title: 'Bidirectional or zero-width control characters',
    severity: 'high',
    cwe: 'CWE-1007',
    guide: 'INSTRUCTIONS.md#bidi-and-zero-width',
    message: 'Bidi overrides (U+202A–U+202E, U+2066–U+2069) and zero-width characters make the text a reviewer sees differ from what the model reads (Trojan Source).',
    fix: 'Remove them. Instruction files and skills should be plain text.',
  },
  'AGT-INJ-003': {
    title: 'Instruction file tells the agent to hide or override',
    severity: 'high',
    cwe: 'CWE-1427',
    guide: 'INSTRUCTIONS.md#override-and-concealment',
    message: 'Text such as "ignore previous instructions", "do not tell the user" or "without asking the user" in a file the agent loads automatically. Legitimate rules files rarely need to hide anything from the developer.',
    fix: 'Read the surrounding text. If nobody on the team wrote it on purpose, remove it and check how it entered the repo (PR, dependency, template).',
  },
  'AGT-INJ-004': {
    title: 'Instruction file sends data or runs remote code',
    severity: 'high',
    cwe: 'CWE-200',
    guide: 'INSTRUCTIONS.md#exfiltration-and-remote-code',
    message: 'An instruction file or skill tells the agent to send secrets/env/files to a URL, or to download and run a script. Agents follow these files with the developer\'s permissions.',
    fix: 'Remove the instruction. Secrets never leave the machine through agent instructions; installers belong in reviewed scripts, not in prompts.',
  },
  'AGT-INJ-005': {
    title: 'Instructions hidden in an HTML comment',
    severity: 'low',
    cwe: 'CWE-1427',
    guide: 'INSTRUCTIONS.md#hidden-comments',
    message: 'An HTML comment in an instruction file contains imperative text aimed at the agent. Comments are invisible on GitHub and in Markdown previews, but the model reads them.',
    fix: 'Move real guidance into visible text; delete comments you did not write.',
  },

  // ── Agent permissions and hooks ─────────────────────────────────────────────
  'AGT-PERM-001': {
    title: 'Agent permission checks bypassed',
    severity: 'high',
    cwe: 'CWE-276',
    guide: 'PERMISSIONS.md#bypass-modes',
    message: 'A committed settings file sets bypassPermissions / --dangerously-skip-permissions style modes, or allows every shell command (Bash, Bash(*)). Anyone who opens the repo with an agent runs with no confirmation step.',
    fix: 'Allow specific commands (Bash(npm test:*), Bash(git status)) and keep broad modes for disposable containers only.',
  },
  'AGT-PERM-002': {
    title: 'All project MCP servers auto-approved',
    severity: 'medium',
    cwe: 'CWE-276',
    guide: 'PERMISSIONS.md#auto-approved-mcp-servers',
    message: 'enableAllProjectMcpServers: true makes the agent start every MCP server defined in any repository\'s .mcp.json without asking. Cloning a repo becomes enough to run its servers.',
    fix: 'Remove it and approve servers per project (enabledMcpjsonServers).',
  },
  'AGT-PERM-003': {
    title: 'Hook downloads or sends data over the network',
    severity: 'high',
    cwe: 'CWE-494',
    guide: 'PERMISSIONS.md#hooks',
    message: 'A hook in a committed settings file runs curl/wget/Invoke-WebRequest, pipes a download into a shell, or posts data. Hooks run automatically on the developer machine for every session that opens the repo.',
    fix: 'Keep hooks local and reviewable: call a script in the repo, never a remote one, and never send prompts, files or env to third parties.',
  },
  'AGT-PERM-004': {
    title: 'Sensitive files not denied to the agent',
    severity: 'info',
    cwe: 'CWE-552',
    guide: 'PERMISSIONS.md#deny-secrets',
    message: 'The project has .env or key files but the agent settings do not deny reading them. Any prompt injection that reaches the agent can ask it to read and summarise them.',
    fix: 'Add deny rules: "deny": ["Read(./.env)", "Read(./.env.*)", "Read(./secrets/**)"].',
  },
};
