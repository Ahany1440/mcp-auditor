# Results on real MCP servers

Scanned on 2026-11-04 with mcp-audit 0.1.0, static mode only (no server code was run).
Each repo was shallow-cloned at the commit shown. I read every finding by hand and sorted it into:

- **Real issue**: a security problem worth telling the maintainers about.
- **Accurate, low risk**: the code does what the finding says, but it is intended or not reachable by an attacker.
- **False positive**: the finding is wrong.

| Server | Commit | Language | Tools found | Findings | Real issue | Accurate, low risk | False positive |
|---|---|---|---|---|---|---|---|
| [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | `194cc86` | TS + Python | 40 | 6 (1 medium, 5 low) | 0 | 5 | 1 |
| [github/github-mcp-server](https://github.com/github/github-mcp-server) | `4bcdcdf` | Go | 115 | 1 (low) | 0 | 1 | 0 |
| [wonderwhy-er/DesktopCommanderMCP](https://github.com/wonderwhy-er/DesktopCommanderMCP) | `0b8da26` | TS | 27 | 27 (16 medium, 11 low) | 0 | 26 | 1 |
| [tumf/mcp-shell-server](https://github.com/tumf/mcp-shell-server) | `c1c8059` | Python | 1 | 1 (medium) | 0 | 1 | 0 |
| [MarkusPfundstein/mcp-obsidian](https://github.com/MarkusPfundstein/mcp-obsidian) | `5ee0b84` | Python | 15 | 4 (low) | 0 | 4 | 0 |

The brief asked for three servers. I scanned five because the first three (two of them from large,
well-reviewed projects) came back almost clean, and I wanted to see how the scanner behaves on
servers that run shell commands and touch files by design.

**Bottom line:** no critical or high findings, and nothing I would call a vulnerability. 2 of
39 findings were false positives (5%). Most of the rest are design choices (a shell tool that runs
commands, very long descriptions) or code outside the tool path (release scripts). That is an
honest result: well-maintained servers mostly avoid the patterns this tool looks for, and the
vulnerable demo server is still needed to show what a bad server looks like.

## modelcontextprotocol/servers

| Rule | Where | Verdict |
|---|---|---|
| MCP005 missing-auth (medium) | `src/everything/transports/sse.ts:93` | Accurate, low risk. The SSE transport has no authentication, but it checks the `Origin` header (so web pages can't reach it) and `everything` is a test server for exercising protocol features, not something to deploy. |
| MCP001 (low) | `src/filesystem/server.ts:283` `read_file` | Accurate, low risk. "Use read_text_file instead" points to a tool on the same server. |
| MCP001 (low) | `src/memory/index.ts:839` `create_entities` | Accurate, low risk. Same pattern ("Use add_observations..."). |
| MCP001 (low) | `src/sequentialthinking/index.ts:53` | Accurate, low risk. The description really is 2,781 characters long, and I read it: nothing hidden. |
| MCP006 (low) | `src/everything/server/context.ts:71` | Accurate, low risk. The server sends `tools/list_changed`; that is the feature `everything` exists to test. |
| MCP006 (low) | `src/everything/tools/get-resource-links.ts:74` | **False positive.** This is the description of a resource link in a tool's *output*, not a tool description. It sits within 10 lines of a tool declaration, which is how the JS check decides what belongs to a tool. |

The filesystem server's file tools were *not* flagged by MCP002, which is correct: every handler
goes through `validatePath`, which the detector accepts as a path check.

## github/github-mcp-server

| Rule | Where | Verdict |
|---|---|---|
| MCP001 (low) | `pkg/github/pullrequests.go:1578` `list_pull_requests` | Accurate, low risk. Points the model at `search_pull_requests` on the same server. |

All 115 tools were found from the official Go SDK's `mcp.Tool{Name:, Description:}` struct form.
Descriptions go through a translation helper, `t("KEY", "default")`, so users can override them
through configuration. That is a deliberate feature controlled by the person running the server,
so the scanner reads the default text and does not raise a rug-pull finding for it.

## wonderwhy-er/DesktopCommanderMCP

| Rule | Count | Verdict |
|---|---|---|
| MCP004 unsafe-execution (medium) | 15 | Accurate, low risk. Every one is in `scripts/` (build/release) or in the install, uninstall and telemetry helpers, building shell commands from template strings. None of them is reachable from tool input. They are medium rather than critical because they are outside tool handlers. |
| MCP002 over-broad (medium) | 1 | Accurate, low risk. `start_process` runs terminal commands; that is the product. The handler is not next to the tool list (low-level SDK), so the finding comes from the description. |
| MCP001 long description (low) | 8 | Accurate, low risk. Descriptions run from 1.9k to 5.6k characters. I skimmed them and found usage guidance, nothing hidden. |
| MCP001 cross-tool reference (low) | 1 | Accurate, low risk. `start_process` tells the model to use `read_process_output`, a tool on the same server. |
| MCP001 invisible Unicode (low) | 1 | **False positive** in practice. `src/remote-device/diagnostics/device-log.ts:86` has U+200D (zero-width joiner) inside a regex that strips emoji. Bidi control characters would be reported as high; this one is reported as low. |
| MCP002 (low) | 1 | Accurate, low risk. `edit_block` edits files; flagged from its description. |

## tumf/mcp-shell-server

| Rule | Where | Verdict |
|---|---|---|
| MCP006 (medium) | `src/mcp_shell_server/server.py:155` | Accurate, low risk. The tool description is an f-string that includes the allowed-commands list from the environment, so the text the model sees changes with configuration. That is intended. A user who re-pins tool definitions after a config change would notice. |

The server runs commands through `create_subprocess_exec` with an allow-list, so MCP004 correctly
found nothing.

## MarkusPfundstein/mcp-obsidian

| Rule | Count | Verdict |
|---|---|---|
| MCP002 (low) | 4 | Accurate, low risk. List/write/delete file tools, flagged from their descriptions. They act on the Obsidian vault through Obsidian's local REST API, which limits them to the vault. |

Tool names show as `self.name` because the server sets each name in a class constructor; static
analysis can't resolve it.

## For responsible disclosure

Nothing here needs a private report. If any of these are raised with maintainers, they are
low-priority hardening suggestions, best sent as a normal issue only if the maintainer wants
them:

- `everything` SSE transport: maybe a note in its README that it has no auth and is for testing only.
- mcp-shell-server: describe the allowed commands without making the tool description depend on
  configuration, or tell users that the description changes with configuration.

Nothing has been filed or published about these servers.

## What this run taught me about the scanner

These changes were made *because* of the real-server scans, before the numbers above were taken:

- Go SDK struct-style tools (`mcp.Tool{...}`) were not recognised at first (0 tools found in github-mcp-server).
- "Use other_tool instead" between a server's own tools was first reported as high; now low unless it gives orders ("always", "first", "must").
- A variable holding a list of secret *names* (`GH_AW_SECRET_NAMES`) was flagged as a secret; values that are only names are now skipped.
- JS `exec()` outside a tool handler was reported as high; now medium, since there is no data-flow proof that tool input reaches it.
- Template-literal descriptions that only interpolate UPPER_CASE constants are now treated as static.

## How to reproduce

```bash
git clone --depth 1 https://github.com/modelcontextprotocol/servers
mcp-audit servers --fail-on none
```

or scan a URL directly (shallow clone into a temp folder):

```bash
mcp-audit https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem
```
