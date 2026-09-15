from __future__ import annotations

import contextlib
import sys
import types
import unittest
from dataclasses import dataclass, field

from axor_wrap.errors import KernelNotInstalledError, ToolDenied, UnknownToolError
from axor_wrap.runtime import WrappedToolset, wrap_callables

MANIFESTS: list[dict[str, object]] = [
    {
        "schema_version": "tool-manifest/v1", "id": "search_web",
        "args_schema": {"type": "object"},
        "effect": {"default_class": "READ", "driving_args": []},
        "side_effecting": False, "untrusted_fields": ["result.*"],
    },
    {
        "schema_version": "tool-manifest/v1", "id": "send_email",
        "args_schema": {"type": "object"},
        "effect": {"default_class": "EXPORT", "driving_args": ["to"]},
        "side_effecting": True,
    },
]


@dataclass
class FakeDecision:
    allowed: bool
    reason: str = "approved"
    category: str = "approved"


@dataclass
class FakeGovernor:
    """Mimics ToolCallGovernor's evaluate/register_output surface."""

    deny: set[str] = field(default_factory=set)
    evaluated: list[tuple[str, dict]] = field(default_factory=list)
    registered: list[tuple[FakeDecision, object]] = field(default_factory=list)
    trace_events: list = field(default_factory=list)

    def evaluate(self, tool_name: str, args: dict) -> FakeDecision:
        self.evaluated.append((tool_name, args))
        if tool_name in self.deny:
            return FakeDecision(False, "untrusted-derived value at egress", "taint_enforcement")
        return FakeDecision(True)

    def register_output(self, decision: FakeDecision, output: object) -> None:
        self.registered.append((decision, output))


def make_tools() -> dict[str, object]:
    calls: list[str] = []

    def search_web(query: str) -> str:
        calls.append(f"search:{query}")
        return f"results for {query}"

    def send_email(to: str, body: str) -> str:
        calls.append(f"send:{to}")
        return "sent"

    tools = {"search_web": search_web, "send_email": send_email}
    tools["_calls"] = calls  # type: ignore[assignment]
    return tools


class WrappedToolsetTest(unittest.TestCase):
    def test_allowed_call_runs_and_registers_output(self) -> None:
        tools = make_tools()
        calls = tools.pop("_calls")
        governor = FakeGovernor()
        toolset = WrappedToolset(tools, MANIFESTS, governor=governor)  # type: ignore[arg-type]
        result = toolset.call("search_web", {"query": "axor"})
        self.assertEqual(result, "results for axor")
        self.assertEqual(calls, ["search:axor"])
        self.assertEqual(governor.evaluated, [("search_web", {"query": "axor"})])
        self.assertEqual(len(governor.registered), 1)
        self.assertEqual(governor.registered[0][1], "results for axor")

    def test_denied_call_raises_tool_denied_and_never_executes(self) -> None:
        tools = make_tools()
        calls = tools.pop("_calls")
        governor = FakeGovernor(deny={"send_email"})
        toolset = WrappedToolset(tools, MANIFESTS, governor=governor)  # type: ignore[arg-type]
        with self.assertRaises(ToolDenied) as ctx:
            toolset.call("send_email", {"to": "evil@x.com", "body": "hi"})
        self.assertEqual(ctx.exception.category, "taint_enforcement")
        self.assertIn("untrusted-derived", ctx.exception.reason)
        self.assertEqual(calls, [])  # the callable never ran
        self.assertEqual(governor.registered, [])  # no output to register

    def test_unknown_tool_raises(self) -> None:
        tools = make_tools()
        tools.pop("_calls")
        toolset = WrappedToolset(tools, MANIFESTS, governor=FakeGovernor())  # type: ignore[arg-type]
        with self.assertRaises(UnknownToolError):
            toolset.call("nope", {})

    def test_config_is_compiled_from_manifests(self) -> None:
        tools = make_tools()
        tools.pop("_calls")
        toolset = WrappedToolset(tools, MANIFESTS, governor=FakeGovernor())  # type: ignore[arg-type]
        self.assertEqual(toolset.config["egress_sinks"], {"send_email"})
        self.assertEqual(toolset.config["untrusted_sources"], {"search_web"})

    def test_wrap_callables_share_one_governor_session(self) -> None:
        tools = make_tools()
        tools.pop("_calls")
        governor = FakeGovernor(deny={"send_email"})
        wrapped = wrap_callables(tools, MANIFESTS, governor=governor)  # type: ignore[arg-type]
        self.assertEqual(set(wrapped), {"search_web", "send_email"})
        self.assertEqual(wrapped["search_web"](query="x"), "results for x")
        with self.assertRaises(ToolDenied):
            wrapped["send_email"](to="a@b.c", body="hi")
        self.assertEqual([name for name, _ in governor.evaluated], ["search_web", "send_email"])


class _BlockAxorCore:
    """A meta-path finder that makes ``axor_core`` unimportable."""

    def find_spec(self, fullname: str, path=None, target=None):  # noqa: ANN001, ANN202
        if fullname == "axor_core" or fullname.startswith("axor_core."):
            raise ImportError("axor_core blocked for this test")
        return None


@contextlib.contextmanager
def axor_core_unimportable():
    """Simulate an environment without axor-core, whether or not it is actually
    installed. The finder only covers *new* imports, so anything already in
    sys.modules is pulled out for the duration and restored afterwards."""
    saved = {
        name: mod for name, mod in sys.modules.items()
        if name == "axor_core" or name.startswith("axor_core.")
    }
    for name in saved:
        del sys.modules[name]
    blocker = _BlockAxorCore()
    sys.meta_path.insert(0, blocker)
    try:
        yield
    finally:
        sys.meta_path.remove(blocker)
        sys.modules.update(saved)


class LazyKernelImportTest(unittest.TestCase):
    """The kernel import is lazy, so a broken environment must fail with an
    actionable error rather than an ImportError traceback from inside a call."""

    def test_unimportable_kernel_raises_actionable_error(self) -> None:
        # axor-core is a REQUIRED dependency now, so this is a broken install
        # rather than a missing opt-in — there is no extra to suggest. Blocked
        # explicitly rather than asserting axor-core is absent: it is present in
        # every supported environment, so "not installed" is not a property the
        # test run can assume.
        with axor_core_unimportable():
            tools = make_tools()
            tools.pop("_calls")
            with self.assertRaises(KernelNotInstalledError) as ctx:
                WrappedToolset(tools, MANIFESTS)  # type: ignore[arg-type]
        message = str(ctx.exception)
        self.assertIn("required dependency", message)
        self.assertNotIn("[kernel]", message, "the kernel extra no longer exists")

    def test_monkeypatched_axor_core_module_is_used(self) -> None:
        """Inject a fake axor_core.governor module: the lazy import must pick it up
        and the wrapped runtime must drive evaluate/register_output through it."""
        constructed: list[dict] = []

        class ToolCallGovernor(FakeGovernor):
            def __init__(self, **kwargs: object) -> None:
                super().__init__(deny={"send_email"})
                constructed.append(dict(kwargs))

        governor_mod = types.ModuleType("axor_core.governor")
        governor_mod.ToolCallGovernor = ToolCallGovernor  # type: ignore[attr-defined]
        axor_core_mod = types.ModuleType("axor_core")
        axor_core_mod.governor = governor_mod  # type: ignore[attr-defined]
        sys.modules["axor_core"] = axor_core_mod
        sys.modules["axor_core.governor"] = governor_mod
        try:
            tools = make_tools()
            tools.pop("_calls")
            toolset = WrappedToolset(tools, MANIFESTS)  # type: ignore[arg-type]
            # the governor was built with the compiled kwargs
            self.assertEqual(constructed[0]["egress_sinks"], {"send_email"})
            self.assertEqual(toolset.call("search_web", {"query": "q"}), "results for q")
            with self.assertRaises(ToolDenied):
                toolset.call("send_email", {"to": "x@y.z", "body": "hi"})
        finally:
            sys.modules.pop("axor_core", None)
            sys.modules.pop("axor_core.governor", None)


if __name__ == "__main__":
    unittest.main()


class TestTheDropInSurfaceIsTheSameWrap(unittest.TestCase):
    """``callables()`` and ``call()`` are two surfaces of ONE toolset.

    A harness that hands an agent a ``{name: fn}`` dict — an eval runner, an MCP
    server, a LangChain executor — used to be unable to ask for observe-only or
    for recording, because ``wrap_callables`` hardcoded both. So it reimplemented
    the gate. These tests pin that it no longer has to.
    """

    def test_callables_go_through_the_same_governor_and_recorder(self) -> None:
        tools = make_tools()
        tools.pop("_calls")
        governor = FakeGovernor()
        toolset = WrappedToolset(tools, MANIFESTS, governor=governor, record=True)  # type: ignore[arg-type]
        wrapped = toolset.callables()
        wrapped["search_web"](query="x")
        toolset.call("send_email", {"to": "a@b.c", "body": "hi"})
        # one governor, one ordered ledger — not two paths that happen to agree
        self.assertEqual([n for n, _ in governor.evaluated], ["search_web", "send_email"])
        self.assertEqual(
            [(c.tool, c.executed) for c in toolset._recorder.calls],  # noqa: SLF001
            [("search_web", True), ("send_email", True)],
        )

    def test_observe_only_records_the_denial_and_still_executes(self) -> None:
        tools = make_tools()
        tools.pop("_calls")
        governor = FakeGovernor(deny={"send_email"})
        wrapped = wrap_callables(
            tools, MANIFESTS, governor=governor, enforcement="off",  # type: ignore[arg-type]
        )
        # the UNGOVERNED arm: the verdict is reached, the call is not blocked
        self.assertEqual(wrapped["send_email"](to="a@b.c", body="hi"), "sent")
        self.assertEqual([n for n, _ in governor.evaluated], ["send_email"])
        self.assertEqual(len(governor.registered), 1)

    def test_enforcement_on_is_still_the_default(self) -> None:
        tools = make_tools()
        tools.pop("_calls")
        wrapped = wrap_callables(
            tools, MANIFESTS, governor=FakeGovernor(deny={"send_email"}),  # type: ignore[arg-type]
        )
        with self.assertRaises(ToolDenied):
            wrapped["send_email"](to="a@b.c", body="hi")

    def test_a_recorded_drop_in_run_can_produce_its_trace(self) -> None:
        tools = make_tools()
        tools.pop("_calls")
        # the REAL kernel here: the point of the test is that the drop-in
        # surface produces a trace whose verdicts came from axor-core, and a
        # fake governor emits no verdicts to pair the recorded calls with.
        toolset = WrappedToolset(tools, MANIFESTS, enforcement="off", record=True)
        wrapped = toolset.callables()
        wrapped["search_web"](query="x")
        wrapped["send_email"](to="a@b.c", body="hi")
        trace = toolset.trace({"trial_id": "t1", "arm": "ungoverned"})
        intents = [e for e in trace["events"] if e["type"] == "tool_call_intent"]
        gates = [e for e in trace["events"] if e["type"] == "gate_decision"]
        self.assertEqual([e["tool"] for e in intents], ["search_web", "send_email"])
        # the arm is recorded as observed-not-enforced on every verdict, which
        # is what makes an UNGOVERNED trace distinguishable from a governed one
        self.assertEqual([g["decision"]["enforced"] for g in gates], [False, False])

    def test_node_id_stamps_the_kernels_own_events(self) -> None:
        tools = make_tools()
        tools.pop("_calls")
        toolset = WrappedToolset(tools, MANIFESTS, node_id="scenario-7")
        toolset.callables()["search_web"](query="x")
        self.assertEqual(toolset.node_id, "scenario-7")
        self.assertTrue(toolset.trace_events)
        self.assertEqual(
            {getattr(e, "node_id", None) for e in toolset.trace_events}, {"scenario-7"}
        )
