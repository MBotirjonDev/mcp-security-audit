import subprocess
from pathlib import Path

import yaml
from mcp.server.fastmcp import FastMCP

WORKSPACE = Path("./workspace").resolve()
mcp = FastMCP("ops")


@mcp.tool()
def ping(host: str) -> str:
    """Ping a host once."""
    return subprocess.run(["ping", "-c", "1", "--", host], check=True, capture_output=True, text=True).stdout


@mcp.tool()
def load_config(text: str) -> str:
    """Parse a YAML config."""
    return str(yaml.safe_load(text))


@mcp.tool()
def read_file(file_path: str) -> str:
    """Read a file from the workspace."""
    target = (WORKSPACE / file_path).resolve()
    if not target.is_relative_to(WORKSPACE):
        raise ValueError("outside workspace")
    return target.read_text()


if __name__ == "__main__":
    mcp.run()
