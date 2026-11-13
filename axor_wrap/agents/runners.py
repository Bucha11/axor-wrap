"""Running a coding-agent CLI as one node of a tree.

:class:`CliAgent` is an axor-core executor (``Invokable``) that runs the agent
non-interactively — ``claude -p`` / ``codex exec`` — in the workspace, with the
node's identity in its environment. The agent's tool calls happen inside its
own process and are governed there, by its hooks and the workspace sidecar;
afterwards the executor reports to the kernel what the node ran and what it read
(``executed_calls`` / ``output_provenance``), which is how a reader's findings
are checked and how its answer carries the taint of what it fetched.

A read-only node is started read-only where the CLI allows it
(``codex --sandbox read-only``, ``claude --disallowedTools Write,Edit,…``), and the
sidecar refuses anything that is not a read on top of that (``AXOR_ACCESS=read``).
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
from collections.abc import AsyncIterator, Callable
from typing import Any

from axor_core.contracts.invokable import Invokable
from axor_core.contracts.result import ExecutorEvent, ExecutorEventKind

from axor_wrap.agents.install import EVENTS, hook_command

_READ_ONLY_CLAUDE_TOOLS = "Write,Edit,MultiEdit,NotebookEdit"


def _claude_hooks() -> str:
    """The axor hooks as a ``--settings`` JSON string, so a node is governed
    whether or not the workspace has them installed."""
    command = hook_command("claude-code")
    hooks: dict = {}
    for event in EVENTS:
        entry: dict = {"hooks": [{"type": "command", "command": command, "timeout": 30}]}
        if event in ("PreToolUse", "PostToolUse"):
            entry = {"matcher": "*", **entry}
        hooks[event] = [entry]
    return json.dumps({"hooks": hooks})


def _context_server(store: str) -> tuple[str, list[str]]:
    import sys

    return sys.executable, ["-m", "axor_wrap.agents.context_mcp", store]


def default_argv(agent: str, model: str, prompt: str, *, read_only: bool,
                 last_message_file: str = "",
                 permission_mode: str = "bypassPermissions",
                 context_store: str = "") -> list[str]:
    """The non-interactive command line for an agent. Approval prompts cannot
    be answered in a tree, so the CLI's own prompts are off; the axor hooks are
    the gate (Claude Code runs PreToolUse hooks in every permission mode)."""
    if agent == "claude-code":
        argv = ["claude", "-p", prompt, "--output-format", "json",
                "--settings", _claude_hooks(), "--permission-mode", permission_mode]
        if model:
            argv += ["--model", model]
        if read_only:
            argv += ["--disallowedTools", _READ_ONLY_CLAUDE_TOOLS]
        if context_store:
            command, args = _context_server(context_store)
            argv += ["--mcp-config", json.dumps({"mcpServers": {
                "axor_context": {"command": command, "args": args}}})]
        return argv
    if agent == "codex":
        argv = ["codex", "exec", "--json", "--skip-git-repo-check",
                "--sandbox", "read-only" if read_only else "workspace-write"]
        if model:
            argv += ["-m", model]
        if last_message_file:
            argv += ["--output-last-message", last_message_file]
        if context_store:
            command, args = _context_server(context_store)
            argv += ["-c", f"mcp_servers.axor_context.command={json.dumps(command)}",
                     "-c", f"mcp_servers.axor_context.args={json.dumps(args)}"]
        return argv + [prompt]
    raise ValueError(f"no default command for agent {agent!r}; give the node a command")


def parse_output(agent: str, stdout: str, last_message: str = "") -> tuple[str, dict]:
    """(final answer, usage) from the CLI's output."""
    usage: dict = {}
    if agent == "claude-code":
        try:
            data = json.loads(stdout)
        except ValueError:
            return stdout.strip(), usage
        u = data.get("usage") or {}
        usage = {"input_tokens": int(u.get("input_tokens", 0) or 0),
                 "output_tokens": int(u.get("output_tokens", 0) or 0)}
        return str(data.get("result", "")), usage
    text = last_message.strip()
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        u = event.get("usage")
        if isinstance(u, dict):
            usage = {"input_tokens": int(u.get("input_tokens", 0) or 0),
                     "output_tokens": int(u.get("output_tokens", 0) or 0)}
        item = event.get("item") or {}
        if not last_message and isinstance(item, dict) and item.get("type") in (
                "agent_message", "assistant_message") and item.get("text"):
            text = str(item["text"])
    return text, usage


class CliAgent(Invokable):
    """One tree node's agent: a CLI run once per child the kernel spawns."""

    def __init__(
        self,
        agent: str,
        model: str = "",
        *,
        workspace: str,
        tree_run: str,
        role: str,
        read_only: bool = False,
        command: list[str] | None = None,
        timeout: float = 1800.0,
        report: Callable[[str], dict] | None = None,
        env: dict | None = None,
        context_store: str = "",
    ) -> None:
        self.context_store = context_store
        self.agent, self.model = agent, model
        self.workspace, self.tree_run, self.role = workspace, tree_run, role
        self.read_only, self.command, self.timeout = read_only, command, timeout
        self._report_fn = report
        self._env = env
        self._reports: dict[str, dict] = {}

    @property
    def label(self) -> str:
        return f"{self.agent}/{self.model}" if self.model else self.agent

    def _argv(self, prompt: str, last_message_file: str) -> list[str]:
        if self.command:
            return [part.replace("{prompt}", prompt).replace("{model}", self.model)
                    for part in self.command]
        return default_argv(self.agent, self.model, prompt, read_only=self.read_only,
                            last_message_file=last_message_file,
                            context_store=self.context_store)

    async def stream(self, envelope: Any) -> AsyncIterator[ExecutorEvent]:
        lineage = getattr(envelope, "lineage", None)
        env = dict(self._env if self._env is not None else os.environ)
        env.update({
            "AXOR_NODE_ID": envelope.node_id,
            "AXOR_PARENT_NODE": (getattr(lineage, "parent_id", "") or ""),
            "AXOR_TREE_RUN": self.tree_run,
            "AXOR_ROLE": self.role,
            "AXOR_ACCESS": "read" if self.read_only else "write",
            "AXOR_CONTEXT_STORE": self.context_store,
        })
        # the context server imports this axor_wrap from wherever it was loaded
        package_parent = str(__import__("pathlib").Path(__file__).resolve().parents[2])
        env["PYTHONPATH"] = os.pathsep.join(
            p for p in (package_parent, env.get("PYTHONPATH", "")) if p)
        fd, last_file = tempfile.mkstemp(prefix="axor-last-", suffix=".txt")
        os.close(fd)
        try:
            proc = await asyncio.create_subprocess_exec(
                *self._argv(envelope.task, last_file), cwd=self.workspace, env=env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                out, err = await asyncio.wait_for(proc.communicate(), self.timeout)
            except TimeoutError:
                proc.kill()
                await proc.wait()
                text, usage = f"[{self.label} timed out after {self.timeout:.0f}s]", {}
            else:
                with open(last_file, encoding="utf-8", errors="replace") as fh:
                    last = fh.read()
                text, usage = parse_output(self.agent, out.decode(errors="replace"), last)
                if proc.returncode != 0 and not text:
                    tail = err.decode(errors="replace").strip()[-400:]
                    text = f"[{self.label} exited {proc.returncode}: {tail}]"
        except FileNotFoundError:
            text, usage = f"[{self.label}: the {self.agent} CLI is not installed here]", {}
        finally:
            os.unlink(last_file)
        yield ExecutorEvent(kind=ExecutorEventKind.TEXT, payload={"text": text},
                            node_id=envelope.node_id)
        yield ExecutorEvent(kind=ExecutorEventKind.STOP, payload={"usage": usage},
                            node_id=envelope.node_id)

    # ── what the node did, as its hooks saw it ───────────────────────────────

    def _report(self, node_id: str) -> dict:
        if node_id not in self._reports:
            self._reports[node_id] = (self._report_fn(node_id) if self._report_fn
                                      else {"known": False, "calls": [], "sources": []})
        return self._reports[node_id]

    def executed_calls(self, node_id: str) -> list[tuple[str, dict]]:
        return [(c[0], c[1]) for c in self._report(node_id).get("calls", [])]

    def output_provenance(self, node_id: str):  # noqa: ANN201 - CausalRoot | None
        """What the node's answer carries. A node its hooks never reported on
        ran ungoverned as far as anyone can tell: its answer is untrusted."""
        from axor_core.contracts.taint import TaintSource
        from axor_core.taint.causal_root import CausalRoot

        report = self._report(node_id)
        if not report.get("known"):
            return CausalRoot.cross_process_in()
        names = {"web": TaintSource.WEB, "mcp": TaintSource.MCP,
                 "child_agent": TaintSource.CHILD_AGENT}
        sources = frozenset(names.get(s, TaintSource.UNKNOWN_EXTERNAL)
                            for s in report.get("sources", []))
        return CausalRoot(sources=sources) if sources else None
