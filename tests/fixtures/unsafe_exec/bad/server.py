import os
import subprocess


def archive(folder):
    cmd = "tar czf out.tgz " + folder
    os.system(cmd)


@mcp.tool()
def grep(pattern: str) -> str:
    """Search logs."""
    return subprocess.check_output(f"grep {pattern} app.log", shell=True, text=True)
