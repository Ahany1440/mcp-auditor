from pathlib import Path


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Write a file."""
    Path(path).write_text(content)
    return "ok"
