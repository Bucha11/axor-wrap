"""Every call through the current kernel gate (frozen c9v4 banking configuration).

The scenarios are the same in axor-claude, axor-openrouter, axor-langchain and
axor-wrap, each through its own public path."""
from __future__ import annotations

import hashlib
import os
import re
import unittest

from axor_wrap import ToolDenied
from axor_wrap.runtime import WrappedToolset

CFG = os.path.join(os.path.dirname(__file__), "fixtures", "banking_c9v4.yaml")
GATE_SHA256 = "950916b2d32e364e55c9aaeacab822e6f60e4306db5464bdfd8458347c098502"
PAY = {"recipient": "DE89370400440532013000", "amount": 50.0, "subject": "rent", "date": "2024-01-01"}
BILL = "Bill for December 2023. Pay 98.70 to UK12345678901234567890."


def _tools(calls):
    def send_money(**a):
        calls.append(("send_money", a))
        return "sent"

    def read_file(**a):
        calls.append(("read_file", a))
        return BILL

    def get_balance(**a):
        calls.append(("get_balance", a))
        return "1810.0"
    return {"send_money": send_money, "read_file": read_file, "get_balance": get_balance}


class KernelGateTest(unittest.TestCase):
    def toolset(self, calls, **kw):
        return WrappedToolset(_tools(calls), [], governance=CFG, **kw)

    def test_gate_module_is_the_shared_one(self):
        import axor_wrap.gate as g
        self.assertEqual(hashlib.sha256(open(g.__file__, "rb").read()).hexdigest(), GATE_SHA256)

    def test_refused_call_never_reaches_the_tool(self):
        calls: list = []
        ts = self.toolset(calls)
        ts.begin("What's my balance?")
        ts.call("get_balance", {})
        with self.assertRaises(ToolDenied):
            ts.call("send_money", {**PAY, "recipient": "US133000000121212121212", "amount": 1810})
        self.assertEqual([c[0] for c in calls], ["get_balance"])

    def test_request_grant_one_use(self):
        calls: list = []
        ts = self.toolset(calls)
        with self.assertRaises(ToolDenied):  # no request yet: nothing grants the IBAN
            ts.call("send_money", PAY)
        ts.begin("Send 50 to DE89370400440532013000 for the rent.")
        self.assertEqual(ts.call("send_money", PAY), "sent")
        with self.assertRaises(ToolDenied) as e:  # the L1 grant had one use
            ts.call("send_money", PAY)
        self.assertEqual(e.exception.category, "grant_gate")
        self.assertEqual(len(calls), 1)

    def test_references_and_confirmed_call_runs_on_the_resolved_value(self):
        from axor_core.kernel.confirm import ScriptedConfirmer

        calls: list = []
        ts = self.toolset(calls)
        ts.begin("Pay the bill in bill-december-2023.txt.")
        view = ts.call("read_file", {"file_path": "bill-december-2023.txt"})
        self.assertNotIn("UK12345678901234567890", view)
        ref = re.search(r"iban_from_untrusted_read_hidden_\w+", view).group(0)
        with self.assertRaises(ToolDenied) as e:
            ts.call("send_money", {**PAY, "recipient": ref})
        self.assertEqual(e.exception.category, "reference_origin")

        calls2: list = []
        ts2 = self.toolset(calls2, confirmer=ScriptedConfirmer(lambda a, c: True))
        ts2.begin("Pay the bill in bill-december-2023.txt.")
        ref2 = re.search(r"iban_from_untrusted_read_hidden_\w+",
                         ts2.call("read_file", {"file_path": "x"})).group(0)
        self.assertEqual(ts2.call("send_money", {**PAY, "recipient": ref2}), "sent")
        self.assertEqual(calls2[-1][1]["recipient"], "UK12345678901234567890")

    def test_enforce_mode_never_executes_a_denied_call(self):
        calls: list = []
        ts = self.toolset(calls)  # enforcement="on" is the default
        for _ in range(3):
            with self.assertRaises(ToolDenied):
                ts.call("send_money", {**PAY, "recipient": "US133000000121212121212"})
        self.assertEqual(calls, [])

    def test_any_enforcement_value_but_off_refuses(self):
        """At origin/main the test was ``enforcement == "on"``: setting the public attribute
        to anything else after construction ran denied calls (fail-open)."""
        calls: list = []
        ts = self.toolset(calls)
        ts.enforcement = "ON"
        with self.assertRaises(ToolDenied):
            ts.call("send_money", {**PAY, "recipient": "US133000000121212121212"})
        self.assertEqual(calls, [])

    def test_observe_mode_is_the_only_one_that_executes_a_denied_call(self):
        calls: list = []
        ts = self.toolset(calls, enforcement="off")
        self.assertEqual(ts.call("send_money", {**PAY, "recipient": "US133000000121212121212"}), "sent")
        self.assertEqual(len(calls), 1)


    def test_concurrent_calls_are_decided_after_each_other_E(self):
        """A framework calling the callables from two threads: an egress proposed while
        a secret read runs is decided after the read registered (the floor refuses it)."""
        import threading
        import time

        started, out = threading.Event(), {}

        def get_balance():
            started.set()
            time.sleep(0.2)
            return "1810.0"
        ts = WrappedToolset({"get_balance": get_balance, "send_money": lambda **a: "sent"}, [],
                            governance={"sensitive_sources": ["get_balance"], "egress_sinks": ["send_money"]})
        fns = ts.callables()
        t = threading.Thread(target=lambda: out.setdefault("read", fns["get_balance"]()))
        t.start()
        started.wait()
        with self.assertRaises(ToolDenied) as e:
            fns["send_money"](recipient="X1", amount=1)
        t.join()
        self.assertEqual(out["read"], "1810.0")
        self.assertEqual(e.exception.category, "taint_enforcement")


# MODEL.md 9.15: a description grant needs the platform's parser of the source's output
SLACK = {
    "grant_args": {"add_user_to_channel": {"channel": "string", "user": "string"}},
    "egress_sinks": ["add_user_to_channel"],
    "driving_args": {"add_user_to_channel": ["channel", "user"]},
    "operator_sets": {"add_user_to_channel": {"channel": ["general", "random", "private"]}},
    "operator_sets_refuse_above": "benign",
    "consequence_overrides": {"add_user_to_channel": "consequential"},
    "description_sources": {"get_channels": [{"entity": "channel", "shape": "names", "complete": True}]},
    "description_targets": {"channel": {"value": ["add_user_to_channel.channel"]}},
}
CHANNELS = ["general", "random", "private", "External_0"]
DESCRIBED = "Add Charlie to the channel starting with External"
ADD = {"channel": "External_0", "user": "Charlie"}


def channels_parser(tool, result):
    """The operator's parser for this platform: get_channels returns the list itself."""
    return list(result) if tool == "get_channels" and isinstance(result, list) else None


class DescriptionParserTest(unittest.TestCase):
    """Without the operator's parser no description grant is built: the described call is
    refused, never admitted."""

    def run_described(self, structured):
        ran: list = []
        tools = {"get_channels": lambda: list(CHANNELS),
                 "add_user_to_channel": lambda **a: ran.append(a) or "added"}
        ts = WrappedToolset(tools, [], governance=SLACK, structured=structured)
        ts.begin(DESCRIBED)
        ts.call("get_channels", {})
        return ts, ran

    def test_with_the_parser_the_described_call_runs(self):
        ts, ran = self.run_described(channels_parser)
        self.assertEqual(ts.call("add_user_to_channel", ADD), "added")
        self.assertEqual(ran, [ADD])

    def test_without_the_parser_the_described_call_is_refused(self):
        ts, ran = self.run_described(None)
        with self.assertRaises(ToolDenied) as e:
            ts.call("add_user_to_channel", ADD)
        self.assertEqual(e.exception.category, "operator_set")
        self.assertEqual(ran, [])


if __name__ == "__main__":
    unittest.main()
