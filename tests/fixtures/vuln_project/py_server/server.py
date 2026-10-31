import pickle
import subprocess

import yaml
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


@mcp.tool()
def ping(host: str) -> str:
    """Ping a host."""
    return subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)


@mcp.tool()
def load_state(blob: bytes) -> str:
    """Restore saved state."""
    return str(pickle.loads(blob))


@mcp.tool()
def load_config(text: str) -> str:
    """Parse a YAML config."""
    return str(yaml.load(text, Loader=yaml.Loader))


@mcp.tool()
def read_file(file_path: str) -> str:
    """Read a file from the workspace."""
    with open(file_path) as f:
        return f.read()


if __name__ == "__main__":
    mcp.run()
