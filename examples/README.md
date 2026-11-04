# Examples

- `vulnerable-server/`: a FastMCP server where every tool has a deliberate problem. It hits all six detectors. Don't run it.
- `clean-server/`: the same tools with each problem fixed. `mcp-audit` reports nothing.

```bash
mcp-audit examples/vulnerable-server   # exit code 1, 13 findings
mcp-audit examples/clean-server        # exit code 0
```

To audit the clean server's live `tools/list` (needs `pip install mcp`):

```bash
mcp-audit --stdio "python examples/clean-server/server.py"
```
