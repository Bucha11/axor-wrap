"""The workspace sidecar: what a hook invocation cannot hold on its own.

Each hook is a fresh process. Governing a SESSION needs memory across calls —
which values came from the web, what this run has done so far, the plane link
— so a hook hands its event to the sidecar for its workspace and relays the
answer. One sidecar per workspace (git root), shared by every agent working
there: one taint ledger for all of them, one governor and one recorder per
agent session, one Control-Plane node per session.

Run by the hook on first use (``python -m axor_wrap.agents.sidecar --root …``),
listening on a unix socket private to the user. Exits after
``AXOR_SIDECAR_IDLE`` seconds without an event (default 1800).
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import logging
import os
import socket
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from axor_wrap.agents import checks, rules, taxonomy, team_skills
from axor_wrap.agents.repo import repo_identity
from axor_wrap.agents.events import HookEvent

_log = logging.getLogger("axor.wrap.agents.sidecar")

ENV_SOCKET = "AXOR_SIDECAR_SOCKET"
ENV_IDLE = "AXOR_SIDECAR_IDLE"
# off = govern and record, deny nothing (verdicts become notes to the agent)
ENV_ENFORCE = "AXOR_ENFORCE"
# how often a sidecar re-asks the plane which skills are turned off
POLICY_TTL = float(os.environ.get("AXOR_POLICY_TTL", "30"))
# how often a session asks the plane for notes from a pair session
NOTES_TTL = float(os.environ.get("AXOR_NOTES_TTL", "3"))


def socket_path(root: str) -> str:
    """Per-user, per-workspace. Under XDG_RUNTIME_DIR when there is one; the
    directory is created 0700 so no other user can reach the socket."""
    explicit = os.environ.get(ENV_SOCKET)
    if explicit:
        return explicit
    base = os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
    directory = Path(base) / f"axor-{os.getuid()}"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    digest = hashlib.sha256(os.path.realpath(root).encode()).hexdigest()[:16]
    return str(directory / f"{digest}.sock")


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("output", "stdout", "content", "result", "text"):
            if isinstance(value.get(key), str):
                return value[key]
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def developer_id(root: str) -> str:
    """Who runs these agents, as an opaque id: the plane counts developers (a
    coding session is not a governed node) and must never be handed an
    address. ``AXOR_DEVELOPER`` if set, else the repository's git user.email,
    else user@host — hashed either way."""
    import getpass
    import subprocess

    who = os.environ.get("AXOR_DEVELOPER", "")
    if not who:
        try:
            out = subprocess.run(["git", "config", "user.email"], cwd=root or None,
                                 capture_output=True, text=True, timeout=2)
            who = out.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            who = ""
    if not who:
        try:
            who = f"{getpass.getuser()}@{socket.gethostname()}"
        except Exception:  # noqa: BLE001
            who = socket.gethostname()
    return "dev-" + hashlib.sha256(who.strip().lower().encode()).hexdigest()[:16]


def _mcp_text(value: Any) -> str:
    """The text of an MCP tool's answer, whatever envelope the CLI reports it
    in: a string, a list of content blocks, or ``{"content": [...]}``."""
    if isinstance(value, dict) and isinstance(value.get("content"), list):
        value = value["content"]
    if isinstance(value, list):
        return "".join(b.get("text", "") for b in value if isinstance(b, dict))
    return value if isinstance(value, str) else _text(value)


def context_provenance(response: Any) -> tuple[bool, list[str]]:
    """(untrusted, sources) an ``axor_context`` answer declares for itself —
    read from the TOP-LEVEL object the server wrote, never from item text
    nested inside it (an item cannot vouch for itself). Unreadable = untrusted."""
    try:
        body = json.loads(_mcp_text(response))
    except (ValueError, TypeError):
        return True, ["unknown_external"]
    prov = body.get("provenance") if isinstance(body, dict) else None
    if not isinstance(prov, dict):
        return True, ["unknown_external"]
    return bool(prov.get("untrusted")), [str(x) for x in prov.get("sources") or []]


def last_assistant_text(transcript_path: str) -> str:
    """The final assistant message in a Claude Code transcript (JSONL), for a
    Stop event that does not carry it."""
    try:
        lines = Path(transcript_path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    for line in reversed(lines):
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if entry.get("type") != "assistant":
            continue
        content = (entry.get("message") or {}).get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            text = "".join(b.get("text", "") for b in content
                           if isinstance(b, dict) and b.get("type") == "text")
            if text:
                return text
    return ""


@dataclass
class _Session:
    agent: str
    session_id: str
    node_id: str
    governor: Any
    recorder: Any
    link: Any = None
    pending: dict = field(default_factory=dict)   # tool_use_id → (decision, record)
    calls: int = 0
    # what actually ran, in the kernel's vocabulary (for a tree's findings
    # check), and the untrusted sources its results came from
    executed: list = field(default_factory=list)
    sources: set = field(default_factory=set)
    last_seen: float = field(default_factory=time.time)
    notes_asked: float = 0.0       # when the plane was last asked for pair notes
    memory_given: bool = False     # the team's memory was given to this session


class Sidecar:
    """Decides hook events for one workspace. Synchronous and transport-free —
    the socket server below and the tests drive the same :meth:`handle`."""

    def __init__(
        self,
        root: str,
        *,
        enforce: bool | None = None,
        plane_url: str | None = None,
        link_factory: Callable[[str], Any] | None = None,
    ) -> None:
        from axor_core.taint.engine import TaintEngine

        self.root = root
        if enforce is None:
            enforce = os.environ.get(ENV_ENFORCE, "1") not in ("0", "off", "false")
        self.enforce = enforce
        self.plane_url = plane_url if plane_url is not None else os.environ.get("AXOR_PLANE_URL")
        self._link_factory = link_factory
        # ONE ledger for every agent in the workspace
        self.taint = TaintEngine()
        self.developer = developer_id(root)
        self.repo, self.repo_label = repo_identity(root)
        self.sessions: dict[str, _Session] = {}
        self.by_node: dict[str, _Session] = {}
        self.last_event = time.time()
        self._lock = threading.Lock()
        # skills turned off from the plane: (fetched at, names); re-asked
        # every POLICY_TTL seconds, the last answer kept through an outage
        self._coding_policy: tuple[float, dict | None] = (0.0, None)

    # ── sessions ──────────────────────────────────────────────────────────────

    def _node_id(self, event: HookEvent) -> str:
        if event.node_id:
            return event.node_id
        return f"{event.agent}-{socket.gethostname()}-{event.session_id[:8]}"

    def _session(self, event: HookEvent) -> _Session:
        key = f"{event.agent}:{event.session_id}"
        found = self.sessions.get(key)
        if found is not None:
            found.last_seen = time.time()
            return found
        from axor_core.governor import ToolCallGovernor

        from axor_wrap.observe import RunRecorder

        node_id = self._node_id(event)
        roles = dict(
            untrusted_sources=taxonomy.UNTRUSTED_SOURCES,
            egress_sinks=taxonomy.EGRESS_SINKS,
            imperative_sinks=taxonomy.IMPERATIVE_SINKS,
            benign_tools=taxonomy.BENIGN_TOOLS,
            driving_args=taxonomy.DRIVING_ARGS,
            node_id=node_id,
        )
        try:
            governor = ToolCallGovernor(taint_engine=self.taint, **roles)
        except TypeError:
            # a kernel from before shared ledgers: each session keeps its own,
            # and what one agent fetched is not seen in another
            _log.warning("axor: this axor-core cannot share a taint ledger across "
                         "agents; upgrade it for cross-agent taint")
            governor = ToolCallGovernor(**roles)
        session = _Session(event.agent, event.session_id, node_id, governor,
                           RunRecorder(node_id))
        session.link = self._open_link(node_id)
        if session.link is not None and self._link_factory is None:
            link, agent, dev = session.link, event.agent, self.developer
            repo, label = self.repo, self.repo_label
            link.submit(lambda: link.connector.post_profile("coding", agent, dev, repo, label))
        self.sessions[key] = session
        self.by_node[node_id] = session
        return session

    def _open_link(self, node_id: str) -> Any:
        if self._link_factory is not None:
            return self._link_factory(node_id)
        if not self.plane_url:
            return None
        try:
            from axor_wrap.plane.link import PlaneLink

            return PlaneLink(self.plane_url, node_id)
        except Exception as exc:  # noqa: BLE001 - a plane outage must not stop the agent
            _log.warning("axor: no Control-Plane link for %s: %s", node_id, exc)
            return None

    def _policy(self, link: Any, *, force: bool = False) -> tuple[dict | None, bool]:
        """The organization's coding policy, asked of the plane at most every
        POLICY_TTL seconds through a session's link: (the answer, whether it
        was asked just now). An outage keeps the last answer."""
        fetched, policy = self._coding_policy
        if link is None or (not force and time.time() - fetched < POLICY_TTL):
            return policy, False
        deliver = getattr(link, "deliver", None)
        answer = None
        if deliver is not None:
            try:
                answer = deliver(lambda: link.connector.get_coding_policy(), 3.0)
            except Exception:  # noqa: BLE001 - an outage keeps the last answer
                answer = None
        if isinstance(answer, dict):
            policy = answer
        self._coding_policy = (time.time(), policy)
        return policy, True

    def skills_off(self, link: Any, agent: str = "") -> frozenset[str]:
        """The organization's turned-off skills. A fresh answer also brings the
        skills turned on for the team up to date on this machine."""
        policy, fresh = self._policy(link)
        if fresh and agent:
            self._team_sync(link, agent, policy, wait=False)
        names = policy.get("skills_off") if isinstance(policy, dict) else None
        return frozenset(str(x) for x in names) if isinstance(names, list) else frozenset()

    def _team_sync(self, link: Any, agent: str, policy: dict | None, *, wait: bool) -> None:
        """Install the skills turned on for the team, at the version the plane
        names, and remove the ones turned back off (team_skills)."""
        wanted = team_skills.wanted_from(policy)
        if link is None or wanted is None or not team_skills.enabled():
            return
        to_install, to_remove, _own = team_skills.plan(agent, wanted)
        for name in to_remove:
            team_skills.remove(agent, name)
        if not to_install:
            return

        async def fetch_and_install() -> None:
            for name in to_install:
                bundle = await link.connector.get_skill_bundle(name)
                if isinstance(bundle, dict) and bundle.get("version") == wanted[name]:
                    team_skills.install(agent, bundle)

        if wait and getattr(link, "deliver", None) is not None:
            link.deliver(fetch_and_install, 10.0)
        else:
            link.submit(fetch_and_install)

    def _with_memory(self, session: _Session, event: HookEvent, answer: dict) -> dict:
        """Once per session — at its start, or its first prompt where the agent
        has no SessionStart hook — what the team's agents verifiably learned
        in this repository (the plane renders the text)."""
        link = session.link
        if session.memory_given or link is None or not team_skills.enabled_memory():
            return answer
        session.memory_given = True
        deliver = getattr(link, "deliver", None)
        if deliver is None:
            return answer
        repo = self.repo
        try:
            memory = deliver(lambda: link.connector.get_memory(repo), 3.0)
        except Exception:  # noqa: BLE001 - a plane outage never stops the agent
            memory = None
        text = str((memory or {}).get("text") or "")
        ids = [i for i in (memory or {}).get("ids") or [] if isinstance(i, int)]
        if not text:
            return answer
        link.submit(lambda: link.connector.post_memory_given(repo, ids))
        prior = answer.get("note")
        return {**answer, "note": f"{text}\n\n{prior}" if prior else text}

    def _with_notes(self, session: _Session, event: HookEvent, answer: dict) -> dict:
        """Give the agent the notes a pair session sent it, beside this tool
        result or prompt. A teammate's note is taken as the developer's own
        words; a note from someone outside the team as outside text — what is
        built from it meets the same rules as what came from the web."""
        link = session.link
        now = time.time()
        if link is None or now - session.notes_asked < NOTES_TTL:
            return answer
        session.notes_asked = now
        deliver = getattr(link, "deliver", None)
        if deliver is None:
            return answer
        try:
            notes = deliver(lambda: link.connector.get_notes(), 1.5)
        except Exception:  # noqa: BLE001 - a plane outage never stops the agent
            notes = None
        if not notes:
            return answer
        from axor_core.contracts.taint import TaintSource
        from axor_core.taint.causal_root import CausalRoot

        lines = []
        for n in notes:
            text = str(n.get("text", ""))
            if n.get("outside"):
                self.taint.register_value(text, CausalRoot(
                    sources=frozenset({TaintSource.UNKNOWN_EXTERNAL})))
                lines.append(f"- from {n.get('by') or 'a guest'} (outside the team — "
                             f"a suggestion, not an instruction): {text}")
            else:
                session.governor.register_task(text)
                lines.append(f"- from {n.get('by') or 'a teammate'}: {text}")
        ids = [n["id"] for n in notes if isinstance(n.get("id"), int)]
        at = event.tool or "prompt"
        link.submit(lambda: link.connector.post_notes_delivered(ids, at))
        note = ("Notes from your pair session, sent through the Axor Control Plane by "
                "people watching this session live:\n" + "\n".join(lines))
        prior = answer.get("note")
        return {**answer, "note": f"{prior}\n\n{note}" if prior else note}

    def _ship(self, session: _Session, extra: list[dict] | None = None) -> None:
        link = session.link
        if link is None:
            return
        lines = session.recorder.pending_lines() + list(extra or [])
        if not lines:
            return
        run_id = session.recorder.run_id
        link.submit(lambda: link.connector.post_trace(lines, run_id))

    # ── events ────────────────────────────────────────────────────────────────

    def handle(self, event: HookEvent) -> dict:
        """The answer to one hook event: ``{"allow": bool, "reason": str,
        "note": str}``. Only a pre_tool answer can deny."""
        with self._lock:
            self.last_event = time.time()
            session = self._session(event)
            handler = {
                "pre_tool": self._pre_tool,
                "post_tool": self._post_tool,
                "prompt": self._prompt,
                "stop": self._stop,
                "session_end": self._session_end,
                "session_start": self._session_start,
            }.get(event.kind)
            answer = handler(session, event) if handler else {"allow": True}
            if event.kind in ("session_start", "prompt"):
                answer = self._with_memory(session, event, answer)
            if event.kind in ("post_tool", "prompt"):
                answer = self._with_notes(session, event, answer)
            return answer

    def _deny(self, session: _Session, event: HookEvent, reason: str, gate: str) -> dict:
        record = session.recorder.begin_tool(event.tool_use_id, event.tool, event.tool_input)
        record.gate = gate
        record.reason = reason
        session.recorder.end_tool(record, "", status="denied")
        self._ship(session)
        return {"allow": False, "reason": f"axor: {reason}"}

    def _pre_tool(self, session: _Session, event: HookEvent) -> dict:
        link = session.link
        if link is not None:
            posture = link.posture()
            if posture == "stopped":
                return self._deny(session, event, "this agent was stopped from the "
                                  "Control Plane", "capability")
            if posture == "paused":
                return self._deny(session, event, "this agent is paused from the "
                                  "Control Plane — wait until it is resumed", "capability")
            cap = link.budget_cap_calls()
            if cap is not None and session.calls >= cap:
                return self._deny(session, event,
                                  f"the call budget set from the Control Plane ({cap}) "
                                  "is spent", "budget")
        tool, args = taxonomy.canonical(event.agent, event.tool, event.tool_input)
        off = self.skills_off(link, session.agent) | rules.local_skills_off(self.root)
        skill = rules.skill_refusal(tool, args, off)
        if skill is not None and self.enforce:
            return self._deny(session, event, skill, "capability")
        if event.access == "read":
            refusal = taxonomy.read_only_refusal(tool, args)
            if refusal is not None:
                return self._deny(session, event, refusal, "capability")
        # what is refused whoever asked: a skill's curl | sh, a read of
        # ~/.aws/credentials, a force push (axor_wrap.agents.rules)
        rule = rules.check_call(tool, args, self.root, rules.allowed_rules(self.root))
        if rule is not None and self.enforce:
            return self._deny(session, event, rules.refusal(rule), "consequence")
        decision = session.governor.evaluate(tool, args)
        if skill is not None:
            note = f"axor (observe only) would deny this call: {skill}"
            would: dict | None = {"gate": "capability", "reason": skill}
        elif rule is not None:
            note = f"axor (observe only) would deny this call: {rules.refusal(rule)}"
            would = {"gate": "consequence", "rule": rule.id,
                                  "reason": rules.refusal(rule)}
        elif not decision.allowed:
            from axor_core.governor import gate_of

            try:
                gate = gate_of(decision.category)
            except ValueError:
                gate = "capability"
            if self.enforce:
                return self._deny(session, event, decision.reason, gate)
            note = f"axor (observe only) would deny this call: {decision.reason}"
            would = {"gate": gate, "reason": str(decision.reason)}
        else:
            note, would = "", None
        session.calls += 1
        record = session.recorder.begin_tool(event.tool_use_id, event.tool, event.tool_input)
        record.started = True
        record.would_deny = would
        try:
            carried = self.taint.derive_carried(args)
            record.carries = sorted(getattr(s, "value", str(s)) for s in carried.sources)
        except Exception:  # noqa: BLE001 - provenance is best-effort, never a refusal
            record.carries = []
        session.pending[event.tool_use_id or f"{event.tool}:{len(session.pending)}"] = (
            decision, record, tool, args)
        self._ship(session)
        return {"allow": True, "note": note}

    def _post_tool(self, session: _Session, event: HookEvent) -> dict:
        key = event.tool_use_id
        if key not in session.pending:
            # an agent that sends no tool_use_id: the oldest open call of this tool
            key = next((k for k, entry in session.pending.items()
                        if entry[1].tool == event.tool), None)
        if key is None:
            return {"allow": True}
        decision, record, tool, args = session.pending.pop(key)
        output = _text(event.tool_response)
        status = "error" if isinstance(event.tool_response, dict) and (
            event.tool_response.get("is_error") or event.tool_response.get("error")) else "ok"
        if status == "ok" and tool == taxonomy.CONTEXT_SERVER:
            untrusted, sources = context_provenance(event.tool_response)
            if untrusted:
                # pulled context that came from an untrusted node: the puller
                # has now read untrusted content, by its own act
                from axor_core.contracts.taint import TaintSource
                from axor_core.taint.causal_root import CausalRoot

                names = {"web": TaintSource.WEB, "mcp": TaintSource.MCP}
                roots = frozenset(names.get(x, TaintSource.CHILD_AGENT) for x in sources) \
                    or frozenset({TaintSource.CHILD_AGENT})
                self.taint.register_value(output, CausalRoot(sources=roots))
                session.sources.update(x if x in names else "child_agent"
                                       for x in (sources or ["child_agent"]))
            else:
                session.governor.register_output(decision, output)
            session.executed.append((tool, args))
        elif status == "ok":
            session.governor.register_output(decision, output)
            session.executed.append((tool, args))
            if tool in taxonomy.UNTRUSTED_SOURCES:
                session.sources.add("mcp" if tool == "mcp_tool" else "web")
        if tool == "bash":
            # read the whole output here — only 120 characters of it ship
            response = event.tool_response if isinstance(event.tool_response, dict) else {}
            code = response.get("exit_code", response.get("exitCode"))
            # the runner's own text, unescaped: Claude Code's stdout/stderr on
            # success, its `error` string on a failure; the raw output else
            raw = "\n".join(str(response[k]) for k in ("stdout", "stderr", "error", "output")
                            if isinstance(response.get(k), str)) or output
            record.check = checks.check_of(
                str(args.get("command", "")), raw,
                failed=status == "error" or (isinstance(code, int) and code != 0),
                interrupted=bool(response.get("interrupted")))
        session.recorder.end_tool(record, output, status=status)
        self._ship(session)
        return {"allow": True}

    def _prompt(self, session: _Session, event: HookEvent) -> dict:
        if session.recorder.active:
            self._finish(session, "")
        if event.prompt:
            # the user's own words: a destination they named is not tainted
            session.governor.register_task(event.prompt)
        return {"allow": True}

    def _stop(self, session: _Session, event: HookEvent) -> dict:
        answer = event.last_message or (
            last_assistant_text(event.transcript_path) if event.transcript_path else "")
        self._finish(session, answer)
        return {"allow": True}

    def _session_start(self, session: _Session, event: HookEvent) -> dict:
        """A new session: bring the team's skills up to date before it starts
        (the team's memory is added by :meth:`_with_memory`)."""
        policy, _ = self._policy(session.link, force=True)
        self._team_sync(session.link, session.agent, policy, wait=True)
        return {"allow": True}

    def _session_end(self, session: _Session, event: HookEvent) -> dict:
        self._finish(session, event.last_message)
        self.sessions.pop(f"{event.agent}:{event.session_id}", None)
        if session.link is not None:
            with contextlib.suppress(Exception):
                session.link.close()
        return {"allow": True}

    def _finish(self, session: _Session, answer: str) -> None:
        """A turn ended: its answer closes the run on the plane, and the next
        prompt starts a new one."""
        if not session.recorder.active:
            return
        claim = [{"kind": "claim", "payload": {"text": answer, "structured": False}}] \
            if answer else []
        self._ship(session, claim)
        session.pending.clear()
        session.recorder.reset()

    def node_report(self, node_id: str) -> dict:
        """What one node did, for the orchestrator that spawned it: the calls
        that ran (to check its findings) and the untrusted sources it read (to
        taint what it returns)."""
        with self._lock:
            session = self.by_node.get(node_id)
            if session is None:
                return {"known": False, "calls": [], "sources": []}
            return {"known": True, "calls": [list(c) for c in session.executed],
                    "sources": sorted(session.sources)}

    def close(self) -> None:
        for session in list(self.sessions.values()):
            if session.link is not None:
                with contextlib.suppress(Exception):
                    session.link.close()
        self.sessions.clear()


# ── the socket server ─────────────────────────────────────────────────────────

async def serve(root: str, path: str, *, idle: float | None = None) -> None:
    sidecar = Sidecar(root)
    idle = float(os.environ.get(ENV_IDLE, "1800")) if idle is None else idle

    async def on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            message = json.loads(await reader.readline())
            if message.get("op") == "node_report":
                answer = sidecar.node_report(str(message.get("node_id", "")))
            else:
                answer = await asyncio.to_thread(sidecar.handle, HookEvent.from_wire(message))
        except Exception as exc:  # noqa: BLE001 - answer, never hang the agent
            _log.exception("axor sidecar: event failed")
            answer = {"allow": True, "error": f"{type(exc).__name__}: {exc}"}
        writer.write((json.dumps(answer) + "\n").encode())
        with contextlib.suppress(Exception):
            await writer.drain()
            writer.close()

    if os.path.exists(path):
        if _alive(path):
            return  # another sidecar already serves this workspace
        os.unlink(path)
    server = await asyncio.start_unix_server(on_client, path=path)
    os.chmod(path, 0o600)
    async with server:
        while time.time() - sidecar.last_event < idle:
            await asyncio.sleep(min(5.0, idle))
    sidecar.close()
    with contextlib.suppress(OSError):
        os.unlink(path)


def _alive(path: str) -> bool:
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(0.5)
    try:
        probe.connect(path)
        return True
    except OSError:
        return False
    finally:
        probe.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="axor-wrap-sidecar")
    parser.add_argument("--root", required=True)
    parser.add_argument("--socket", default=None)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    asyncio.run(serve(args.root, args.socket or socket_path(args.root)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
