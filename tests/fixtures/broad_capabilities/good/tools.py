from pathlib import Path

ROOT = Path("data").resolve()


@mcp.tool()
def read_config() -> str:
    """Read the server's own config file."""
    return Path("config.toml").read_text()


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file inside the data folder."""
    full = (ROOT / path).resolve()
    if not full.is_relative_to(ROOT):
        raise ValueError("outside data folder")
    return full.read_text()
