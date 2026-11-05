# State of MCP server security: 99 popular repos, November 2026

I scanned the 100 most-starred GitHub repositories tagged `mcp-server` with `mcp-audit`, then read
every critical and high finding by hand. This page has the totals and what they mean. It names
no repository: the few real issues are being reported privately to their maintainers first.

## The short version

- **No tool poisoning in 9,965 tool definitions.** Not one description, parameter name or schema
  string carried hidden orders for the model, invisible characters or encoded text. Popular
  servers are not where this attack lives today. The risk is the long tail: small servers
  installed from a README, with nobody reading their code.
- **Over-broad tools are normal.** 13 repos have tools that run commands, fetch any URL or touch
  any file, with nothing visible that limits them. Often that is the product (a shell tool is a
  shell tool), but it means one poisoned or prompt-injected conversation can do anything the
  user can.
- **Network mode is where real bugs are.** 6 repos can serve MCP over HTTP. 3 listen only on
  localhost by default. 3 listen on every network interface by default with no login: one only
  renders charts, one runs inside a container (so the port mapping decides who can reach it),
  and one has a tool that sends messages through the owner's configured channels. That last
  one is being reported.
- **No leaked credentials.** All 4 high-confidence secret matches were harmless on inspection: a
  key published on purpose, a sample URL from vendor docs, a fake test certificate.
- **Tools can change after you approve them.** 14 repos can tell clients their tool list changed
  (`tools/list_changed`), and 25 build tool descriptions at runtime. Nothing malicious, but
  approving a tool once does not mean it stays the same. This is what `--pin` is for.

## What was scanned

| | |
|---|---|
| Selection | GitHub search `topic:mcp-server`, sorted by stars, top 100, on 2026-11-05 |
| Scanned | 99 (one repo could not be checked out on Windows: it has a file named `nul.ts`) |
| Smallest repo | 3,779 stars |
| Files read | 140,898 |
| Repos where tools were found | 68 |
| Tools found | 9,965 (median 29 per repo) |
| Languages (repos with tools) | TypeScript 31, Python 20, Go 6, JavaScript 4, Rust 2, other 5 |
| Tool | `mcp-audit` 0.3.0, static scan only, default settings |

The tag is applied by repo owners, so the list is a mix: dedicated MCP servers, large apps that
ship an MCP server as one feature, SDKs, tutorials and curated lists. That is what people find
when they search, so it was kept as is.

For the 31 repos with no tools found, tools are registered through the project's own wrappers
(`registry.add(...)`, `registerTool(metadata.name, ...)`), which a static scan can't resolve.
`mcp-audit --stdio "<command>"` asks the running server instead.

## All findings

| Severity | Findings | Repos (worst finding) |
|---|---:|---:|
| critical | 8 | 3 |
| high | 58 | 25 |
| medium | 1,126 | 47 |
| low | 728 | 4 |
| none | | 20 |

By check:

| Check | Repos | critical | high | medium | low |
|---|---:|---:|---:|---:|---:|
| MCP001 tool poisoning | 36 | | 2 | 89 | 371 |
| MCP002 over-broad tools | 20 | | 4 | 130 | 95 |
| MCP003 hard-coded secrets | 39 | | 4 | 498 | |
| MCP004 unsafe execution | 48 | 6 | 37 | 331 | |
| MCP005 missing auth | 6 | 2 | 4 | 1 | |
| MCP006 rug-pull risk | 30 | | 7 | 77 | 262 |

Medium and low are leads, not verdicts. Most medium MCP003 hits are `password = "..."`-style
values in fixtures, demo configs and docs. Most low MCP001 hits are tools that tell the model
to call another tool (`call get_page_layout first`), which is normal guidance but also the shape
cross-tool hijacking takes.

## The 66 critical and high findings, checked by hand

| What it turned out to be | Count |
|---|---:|
| Real, being reported privately (HTTP server open to the network, tools with side effects) | 1 |
| Worth a note to maintainers, low impact (open HTTP server with harmless tools; HTTP server bound to all interfaces inside a container) | 2 |
| HTTP server without auth that only listens on localhost by default (2 repos) | 3 |
| By design: a code-runner tool that passes its input to `eval`/`exec` (that's its job) | 6 |
| Shell or `exec` on a function argument that is not a tool input: build scripts, CLIs, sandboxed code runners | 37 |
| Tool description built from local constants or passed through by a proxy, not fetched from a server | 7 |
| Secret look-alikes: a key published on purpose, a vendor sample URL, a fake test certificate | 4 |
| Over-broad tools in tutorial and test code | 4 |
| A stray bidi character in a data file (renders oddly, can't change code) | 2 |

The scanner improved along the way. The first pass over the same repos produced 158 critical and
high findings. Reading them showed six false-positive patterns, which are now fixed and have
tests:

- editor theme files (`"token": "keyword.control"`) and request IDs reported as secrets;
- a lone `-----BEGIN PRIVATE KEY-----` line, with no key after it, reported as a key;
- "never send credentials" read as a request to send credentials;
- emoji flags (which use Unicode tag characters) and code that *removes* bidi characters
  reported as Trojan Source;
- an ASGI bearer-token middleware not recognised as authentication;
- URL paths mistaken for base64.

The remaining 66 are all in the table above.

## What to do with this

If you install MCP servers:

- Read the tool list before approving a server. `mcp-audit --stdio "<command>"` prints problems
  in what the server actually returns.
- Pin it: `mcp-audit --stdio "<command>" --pin tools.lock.json` and re-run it on updates. A changed
  description fails the check.
- Never expose an HTTP MCP server beyond localhost without a token in front of it.

If you maintain one:

- Listen on `127.0.0.1` by default; make `0.0.0.0` an explicit choice that requires a token.
- Keep descriptions as literals in the code, so reviewers and scanners can see them.
- Give command, file and URL tools an allow-list, and say in the description what it is.
- Add the GitHub Action (see the README); it puts findings in the Security tab.

## Limits

This is a static scan of the default branch, plus hand review of the serious findings. It does not
run the servers, read tool output, or follow data across files in TypeScript or Go. Tools whose
names or descriptions are built at runtime are invisible to it unless you use `--stdio`. A repo
with no findings is not a safe repo.

## Reproduce it

```bash
pip install mcp-audit
git clone --depth 1 https://github.com/<owner>/<repo>
mcp-audit <repo> --format json --fail-on none -o <repo>.json
```

The repo list came from the GitHub search above. Per-repo results will be published once the
maintainers of the affected projects have had time to respond.
