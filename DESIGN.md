# Design

## The problem

An MCP server gives an AI agent a list of tools. For each tool the agent sees a name, a
description and a JSON schema, and it trusts that text the same way it trusts its own
instructions. The user usually never reads it. That creates a few specific risks:

- the description itself can carry instructions (tool poisoning),
- the tool can be far more powerful than its name suggests (a "notes" tool that reads any file),
- the server code can be unsafe in ordinary ways (shell injection, committed keys, no auth),
- the description the user approved can change later (rug pull).

`mcp-audit` looks for those in a server's source code and, optionally, in what a running server
actually returns from `tools/list`.

## Pipeline

```
target (folder | GitHub URL | --stdio command)
        |
        v
source.py   load files, skip tests/vendor/build output        live.py  initialize + tools/list
            find tools: Python AST, JS/TS/Go regexes                   (paginated, JSON-RPC over stdio)
        \__________________________ Target __________________________/
                                      |  files: [SourceFile]
                                      |  tools: [Tool(name, description, params, file, line, end_line)]
                                      v
detectors/  tool_poisoning  broad_capabilities  secrets  unsafe_exec  missing_auth  rug_pull
            each: RULE + detect(target) -> [Finding]
                                      |
                                      v
report.py   text | JSON | SARIF 2.1.0          cli.py  exit code from --fail-on
```

Everything a detector needs is in `Target`. Detectors don't call each other and don't share
state, so each one can be read, tested and changed alone. `models.py` holds the four data
types; `detectors/_python.py` holds the AST helpers that three detectors share.

## Finding tools

- **Python**: `ast`. A function with a decorator named `tool` (`@mcp.tool()`, `@server.tool`,
  `@tool`) is a tool; its description is the `description=` argument or the docstring; parameter
  descriptions come from `Field(description=...)` in annotations. Low-level `Tool(name=...,
  description=..., inputSchema=...)` calls are also read. Because the handler is a real AST
  node, detectors know exactly which lines belong to which tool.
- **JS/TS**: regexes for `server.tool("name", "desc", ...)`, `registerTool("name", {description})`,
  and `{ name: "...", description: "..." }` objects. String escapes such as `​` are decoded so
  hidden characters written as escapes are still seen.
- **Go**: regexes for `mcp.NewTool("name", mcp.WithDescription(...))` (mark3labs/mcp-go) and
  `mcp.Tool{Name: ..., Description: ...}` (the official go-sdk, including `t("KEY", "default")`).
- **Live**: `--stdio` starts the server, sends `initialize`, `notifications/initialized` and
  `tools/list` (following `nextCursor`), and turns the result into the same `Tool` objects. Live
  tools have no source location, so code-based checks can't apply to them; the description-based
  ones do.

Tool poisoning doesn't stop at the description. The model reads the whole tool definition, so
every string in it is checked: parameter names (split from `snake_case`/`camelCase` into words so
the phrase patterns still match), and every title, description, enum value, default and example in
the input schema, including nested objects and `$defs`. In Python this also covers string
defaults in the function signature and `Field(title=..., examples=...)`. In JS/TS it covers zod
parameter names. Live mode walks the full `inputSchema` and `outputSchema`.

For JS/TS/Go there is no AST, so a tool's "handler" is assumed to be the text from its
declaration to the next tool declaration, capped at 80 lines. That is a shortcut, marked in the
code.

## How each detector decides

| Detector | Method | Main signal |
|---|---|---|
| tool_poisoning | regexes over every tool text field, Unicode classes, base64 decode | phrases aimed at the model, invisible characters, encoded text |
| broad_capabilities | Python: AST taint from tool parameters to sink calls. JS/Go: sink regex inside the handler window. No handler: description wording | sink reached with no guard (allow-list / path containment / host check) in the handler |
| secrets | provider regexes (adapted from gitleaks) + generic assignment with entropy >= 3.5 | known token formats |
| unsafe_exec | Python: AST, non-constant argument to eval/exec/shell, taint from parameters. JS/Go: regexes | input-controlled code or shell execution |
| missing_auth | repo-wide: an HTTP/SSE transport is started and no inbound auth pattern exists anywhere | transport without credential check |
| rug_pull | Python: AST, is the description expression made only of literals and module-level constants? JS/Go: is the tool's own description a literal? | descriptions that can change after review |

The Python taint tracking is deliberately small: a function's parameters, plus local names
assigned from them (two rounds), plus `with ... as x` targets. It does not follow values into
other functions.

## Severity

- **critical**: tool input demonstrably reaches something dangerous (a tool parameter flows into
  `eval`/a shell), or an instruction is clearly aimed at deceiving the user.
- **high**: strong signal that should be fixed (hidden characters, credential paths in a
  description, a shell tool with no allow-list, a committed key).
- **medium**: likely a problem but needs a human (dynamic arguments with an unclear source, file or
  network access without a visible guard).
- **low**: informational (long descriptions, cross-references between a server's own tools,
  `tools/list_changed`).

SARIF maps critical/high to `error`, medium to `warning`, low to `note`, and sets
`security-severity` on each rule so GitHub sorts the alerts.

## Known limits

These are the cases I know it gets wrong. Most come from choosing patterns over a full
program analysis.

- **No cross-function data flow.** If a tool passes its input to a helper that calls
  `subprocess.run(..., shell=True)`, the helper's call is reported at "high" (any parameter), not
  "critical". In JS/TS/Go there is no data flow at all: a shell call outside a tool window is
  "medium" whether or not input reaches it.
- **Guards are recognised by name, not by meaning.** A handler that mentions `ALLOWED_` or calls
  `startsWith(` is treated as guarded, even if the check is wrong or bypassable (for example
  `startsWith(root)` without a trailing separator). A correct guard in a helper whose name doesn't
  match is missed, which gives a false positive.
- **JS/TS/Go tool windows are approximate.** A handler defined far away from its declaration,
  or a tool created by a factory function, may not be associated with the right code. Descriptions
  built by string concatenation are only partly read.
- **Tool names set at runtime** (for example in a class constructor) appear as the expression,
  such as `self.name`.
- **missing_auth is repo-wide.** Any inbound-auth pattern anywhere disables the check, even if it
  protects a different endpoint. Default binds are not checked: Node's `app.listen(port)` listens
  on all interfaces, but only an explicit `0.0.0.0` raises the severity.
- **Rug pulls over time are not tracked.** The tool flags descriptions that *can* change; it
  doesn't store a pinned copy of `tools/list` to compare against later. Pinning plus diffing would
  be the next feature.
- **Tool output is not checked.** A server can return instructions in a tool's *result* at
  runtime ("now call delete_files"), and no pre-install scan sees that. Catching it needs something
  that sits between the client and the server and inspects responses, which is a different tool.
  `--stdio` only calls `tools/list`. It never calls tools, because that would mean running their
  side effects.
- **JS/TS schemas are partly read.** Zod parameter names and `description`/`.describe()` strings
  are checked; zod `.enum([...])` values and defaults are not.
- **Tool poisoning is pattern-based.** Paraphrased or non-English instructions will get through.
  There is no model in the loop on purpose: results are deterministic and the scanner can't be
  prompt-injected by the server it is scanning.
- **Test, build and vendor folders are skipped**, so a secret committed under `tests/` is not
  reported.
- **`--stdio` runs the server.** It is as dangerous as installing the server. Use it in a
  container or VM for servers you don't trust.

## Why these choices

- **Python and the standard library only**: `pip install` brings in nothing else, the GitHub
  Action runs with the runner's `python3` and no install step, and there is no dependency
  supply chain to worry about in a security tool.
- **Regex for JS/TS/Go instead of real parsers**: real parsers would mean tree-sitter or a Node
  toolchain as a dependency. Most MCP servers use a handful of SDK call shapes, and regexes cover
  those. The cost is the window shortcut above.
- **One module per detector with fixture tests**: each detector has a `bad/` folder it must flag
  and a `good/` folder it must leave alone, so a change that adds false positives fails a test.
