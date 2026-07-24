"""Mini-project fixture sources for the scanner tests (written to tmp dirs)."""

from __future__ import annotations

import tempfile
from pathlib import Path

LANGCHAIN_AGENT = '''\
from langchain_core.tools import tool, StructuredTool, Tool


@tool
def search_web(query: str, max_results: int = 5) -> str:
    """Search the web for a query."""
    return "results"


@tool("send_email")
def _send(to: str, subject: str, body: str) -> bool:
    """Send an email to a recipient."""
    return True


def update_record(record_id: int, payload: dict) -> bool:
    """Update a CRM record."""
    return True


structured = StructuredTool.from_function(func=update_record, name="update_record")

legacy = Tool(name="mystery_gizmo", func=lambda x: x, description="Does something unspecified")
'''

MCP_SERVER = '''\
from mcp.server.fastmcp import FastMCP

app = FastMCP("demo")


@app.tool()
def read_file(path: str) -> str:
    """Read a file from disk."""
    return open(path).read()


@app.tool(name="post_slack_message")
def poster(channel: str, text: str) -> None:
    """Post a message to a Slack channel."""
'''

ANTHROPIC_REGISTRY = '''\
TOOLS = [
    {
        "name": "fetch_url",
        "description": "Fetch a web page over HTTP",
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "frobnicate",
        "description": "Adjusts the frobnicator",
        "input_schema": make_schema(),
    },
]
'''

SUBPROCESS_AGENT = '''\
import subprocess


def deploy(target: str) -> None:
    subprocess.run(["make", "deploy", target], check=True)
'''

NO_TOOLS = '''\
def helper(x: int) -> int:
    return x + 1
'''


def write_project(files: dict[str, str]) -> Path:
    """Write {relative_path: source} into a fresh temp dir; caller cleans up."""
    root = Path(tempfile.mkdtemp(prefix="axor_wrap_test_"))
    for rel, src in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(src, encoding="utf-8")
    return root


ALL_FIXTURES = {
    "agent_langchain.py": LANGCHAIN_AGENT,
    "mcp_server.py": MCP_SERVER,
    "registry.py": ANTHROPIC_REGISTRY,
    "runner.py": SUBPROCESS_AGENT,
    "plain.py": NO_TOOLS,
}
