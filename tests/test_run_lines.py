"""WrappedToolset.run_lines: a run as the plane audits it, in one call."""
from __future__ import annotations

import unittest

from axor_wrap.runtime import WrappedToolset


def _m(tid: str, klass: str, *, side: bool = False) -> dict:
    return {"schema_version": "tool-manifest/v1", "id": tid, "args_schema": {"type": "object"},
            "effect": {"default_class": klass, "driving_args": []}, "side_effecting": side}


class RunLinesTest(unittest.TestCase):
    def setUp(self) -> None:
        try:
            import axor_core  # noqa: F401
        except ImportError:  # pragma: no cover
            self.skipTest("axor-core not installed")

    def test_every_executed_call_has_a_result_and_the_answer_a_claim(self) -> None:
        tools = {"lookup_order": lambda **a: {"amount": 49},
                 "issue_refund": lambda **a: {"error": "payments down"}}
        ts = WrappedToolset(tools, [_m("lookup_order", "READ"), _m("issue_refund", "WRITE", side=True)],
                            node_id="n")
        ts.call("lookup_order", {"order_id": "A-1"})
        ts.call("issue_refund", {"order_id": "A-1", "amount": 49})
        lines = ts.run_lines("Refund of $49 issued.")
        results = [ln["payload"] for ln in lines if ln["kind"] == "tool_result"]
        self.assertEqual(sorted((r["tool"], r["status"]) for r in results),
                         [("issue_refund", "error"), ("lookup_order", "ok")])
        self.assertEqual(sum(ln["kind"] == "tool_call" for ln in lines), 2)
        claim = lines[-1]
        self.assertEqual(claim["kind"], "claim")
        self.assertEqual(claim["payload"]["claims"]["tools_succeeded"], ["lookup_order", "issue_refund"])

    def test_no_answer_no_claim(self) -> None:
        ts = WrappedToolset({"t": lambda **a: 1}, [_m("t", "READ")], node_id="n")
        ts.call("t", {})
        self.assertNotIn("claim", [ln["kind"] for ln in ts.run_lines()])


if __name__ == "__main__":
    unittest.main()
