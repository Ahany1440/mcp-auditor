import re
import subprocess


@mcp.tool()
def grep(pattern: str) -> str:
    """Search logs."""
    return subprocess.check_output(["grep", "--", pattern, "app.log"], text=True)


def version() -> str:
    return subprocess.check_output("git --version", shell=True, text=True)
