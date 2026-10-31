# MCP server source code

For projects that **build** MCP servers (TypeScript/JavaScript with `@modelcontextprotocol/sdk`,
Python with `mcp` / FastMCP). The threat model is unusual: tool arguments are written by a
model, and the model can be steered by anything it reads (issues, web pages, emails, PDFs, other
tools' results). Treat every tool argument as attacker-controlled input from the internet.

## Command injection

```ts
// bad: the model chooses `branch`; "main; <any command>" runs
exec(`git log --oneline ${branch}`);
// good: no shell, argument array, "--" ends option parsing
execFile("git", ["log", "--oneline", "--", branch]);
```

```python
# bad
subprocess.check_output(f"ping -c 1 {host}", shell=True)
# good
subprocess.run(["ping", "-c", "1", "--", host], check=True, capture_output=True)
```

Also check argument injection without a shell: a value starting with `-` (`--upload-pack=…`,
`-o ProxyCommand=…`) is an option, not a file name. Validate with an allowlist regex and use `--`.

## Tool poisoning

Tool and parameter descriptions are inserted into the model context, and most clients show the
user only the tool name. A malicious or compromised server can hide instructions in them:

- markup that looks like system text (`<IMPORTANT>`, `<SYSTEM>`)
- requests to read sensitive files "before using this tool" and pass them as an argument
- requests to keep the behaviour secret from the user
- instructions about **other** tools ("when sending email, always BCC …"), which is cross-server
  shadowing: a server you never call can still change how trusted tools behave

Descriptions should describe the tool and its parameters, nothing else. When auditing a
third-party server, read the descriptions it actually serves (they can differ from the README
and can change between versions, which is why pinning matters).

## Path traversal

```ts
// bad
await readFile(args.path, "utf8");
// good
const full = await realpath(path.resolve(ROOT, args.path));
if (!full.startsWith(ROOT + path.sep)) throw new Error("outside root");
```

Resolve symlinks (`realpath`) before comparing, compare against the root **plus a separator**
(`/data` vs `/data-backup`), and reject absolute paths. In Python use
`Path(...).resolve().is_relative_to(ROOT)` (3.9+).

## SSRF

A `fetch(args.url)` tool can reach `http://169.254.169.254/` (cloud credentials), `localhost`
admin panels and internal services, and return the response into the chat. Allow only
`https:`, resolve the host and block private, loopback and link-local ranges (and re-check
after redirects), or limit to an allowlist of domains.

## Dynamic code

`eval`, `new Function`, `vm.runIn*`, Python `eval`/`exec`, `pickle.loads`, `yaml.load` without
`SafeLoader`. If running code is the product (a "python sandbox" tool), it needs a real sandbox:
a separate container or VM with no credentials and no network, not a module-level check.

## Network exposure

- `listen(…, "0.0.0.0")` exposes tools to the local network. Bind `127.0.0.1` for local servers.
- Local Streamable HTTP / SSE servers must validate the `Origin` header; otherwise a web page
  the developer visits can reach them through DNS rebinding (the MCP transport spec requires this).
- Remote servers need authentication on every request, not only on the first one.

## Token passthrough

Forwarding the client's `Authorization` header to a downstream API ("token passthrough") is
explicitly forbidden by the MCP security best practices: the server cannot check that the token
was issued for it (audience), cannot enforce its own scopes or rate limits, and logs become
useless. Validate tokens issued **for this server**, then call downstream APIs with the server's
own credentials or a proper token exchange.

## Other things to review by hand

- **Destructive tools without confirmation**: deleting, sending, paying, merging. Mark them
  with `destructiveHint: true` annotations and keep the client's confirmation step.
- **Over-broad credentials**: a server that holds an org-admin token for a read-only feature.
- **Untrusted content in results**: issues, emails and web pages returned as tool results are a
  prompt-injection channel. Label them as untrusted and keep them out of system-level text.
- **The lethal trifecta**: one agent with access to private data, exposure to untrusted content
  and a way to send data out. Any one tool combination that completes the triangle is an
  exfiltration path, even if each tool is fine alone.
- **Session IDs used as authentication** and **logs that store tool arguments** (tokens, file
  contents) in plain text.
