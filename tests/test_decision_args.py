"""The callable runs with the arguments the kernel judged — ``decision.args``.

With a consumption contract (``axor_core.kernel.consumption``) the kernel prepares
each call before any gate: declared defaults filled in, declared conversions
applied, undeclared fields refused. The gate verdict is about THAT set. A wrap
that then invoked the callable with the model's raw proposal would execute a
value no gate saw — the check and the effect would part exactly where the
contract exists to join them. These tests drive the real kernel and read the
callable's own ledger.
"""
from __future__ import annotations

import unittest

from axor_core.kernel.consumption import FieldContract, FieldKind, SinkContract

from axor_wrap.errors import KernelIncompatibleError, ToolDenied
from axor_wrap.runtime import ENFORCEMENT_OFF, WrappedToolset, wrap_callables

ALLOWED = "GB29NWBK60161331926819"
ATTACKER = "US133000000121212121212"

MANIFESTS: list[dict[str, object]] = [{
    "schema_version": "tool-manifest/v1", "id": "send_money",
    "args_schema": {"type": "object"},
    "effect": {"default_class": "EXPORT", "driving_args": ["recipient"]},
    "side_effecting": True,
}]
POLICY = {"allowlist": [ALLOWED], "criticality_overrides": {"send_money": "consequential"}}
CONTRACTS = {"send_money": SinkContract(fields={
    "recipient": FieldContract(FieldKind.IDENTIFIER),
    "amount": FieldContract(FieldKind.NUMBER, decimal_string=True),
    "subject": FieldContract(FieldKind.TEXT, default=""),
})}


class Bank:
    def __init__(self) -> None:
        self.balance = 50_000.0
        self.transfers: list[tuple[str, object]] = []

    def send_money(self, recipient=None, amount=None, subject="", iban=None):
        to = iban if iban is not None else recipient          # legacy alias
        amt = self.balance if amount is None else amount       # absent → sweep
        self.transfers.append((to, amt))
        return "sent"


def _toolset(bank: Bank, **kw) -> WrappedToolset:
    return WrappedToolset({"send_money": bank.send_money}, MANIFESTS, policy=POLICY, **kw)


class TestTheCallableReceivesThePreparedSet(unittest.TestCase):
    def test_declared_conversion_and_default_reach_the_callable(self) -> None:
        bank = Bank()
        _toolset(bank, field_contracts=CONTRACTS).call(
            "send_money", {"recipient": ALLOWED, "amount": "250"})
        self.assertEqual(bank.transfers, [(ALLOWED, 250)])

    def test_out_of_contract_proposals_never_reach_the_callable(self) -> None:
        bank = Bank()
        toolset = _toolset(bank, field_contracts=CONTRACTS)
        for args in ({"recipient": ALLOWED},                                  # sweep
                     {"recipient": ALLOWED, "amount": 5, "iban": ATTACKER}):  # alias
            with self.assertRaises(ToolDenied) as ctx:
                toolset.call("send_money", args)
            self.assertEqual(ctx.exception.category, "consumption_contract")
        self.assertEqual(bank.transfers, [])

    def test_without_a_contract_the_same_proposals_execute(self) -> None:
        """Negative control: same wrap, same allowlist, no contract."""
        bank = Bank()
        toolset = _toolset(bank)
        toolset.call("send_money", {"recipient": ALLOWED})
        toolset.call("send_money", {"recipient": ALLOWED, "amount": 5, "iban": ATTACKER})
        self.assertEqual(bank.transfers, [(ALLOWED, 50_000.0), (ATTACKER, 5)])

    def test_drop_in_callables_share_the_wiring(self) -> None:
        bank = Bank()
        send = wrap_callables({"send_money": bank.send_money}, MANIFESTS, policy=POLICY,
                              field_contracts=CONTRACTS)["send_money"]
        send(recipient=ALLOWED, amount="7")
        self.assertEqual(bank.transfers, [(ALLOWED, 7)])

    def test_observe_only_runs_what_the_agent_proposed_and_records_it_apart(self) -> None:
        """The ungoverned arm measures what an unwrapped agent does: a DENY runs
        the raw proposal. The record keeps the checked set, what ran, and the
        fact that enforcement was bypassed — three different things."""
        bank = Bank()
        toolset = _toolset(bank, field_contracts=CONTRACTS, enforcement=ENFORCEMENT_OFF,
                           record=True)
        # value-policy deny AFTER preparation: checked {amount: 7, subject: ""},
        # executed the raw {amount: "7"} to a non-allowlisted account
        toolset.call("send_money", {"recipient": ATTACKER, "amount": "7"})
        self.assertEqual(bank.transfers, [(ATTACKER, "7")])
        rec = toolset._recorder.calls[0]  # type: ignore[union-attr]
        self.assertEqual(rec.checked_args, {"recipient": ATTACKER, "amount": 7, "subject": ""})
        self.assertEqual(rec.executed_args, {"recipient": ATTACKER, "amount": "7"})
        self.assertTrue(rec.enforcement_bypassed)

    def test_an_allowed_call_records_identical_checked_and_executed_sets(self) -> None:
        bank = Bank()
        toolset = _toolset(bank, field_contracts=CONTRACTS, record=True)
        toolset.call("send_money", {"recipient": ALLOWED, "amount": "7"})
        rec = toolset._recorder.calls[0]  # type: ignore[union-attr]
        self.assertEqual(rec.executed_args, rec.checked_args)
        self.assertFalse(rec.enforcement_bypassed)

    def test_the_trace_binds_the_executed_arguments_of_a_bypassed_deny(self) -> None:
        import json
        from pathlib import Path

        import axor_core
        from axor_wrap.trace import build_trace

        bank = Bank()
        toolset = _toolset(bank, field_contracts=CONTRACTS, enforcement=ENFORCEMENT_OFF,
                           record=True)
        toolset.call("send_money", {"recipient": ATTACKER, "amount": "7"})
        trace = build_trace(
            calls=toolset._recorder.calls,  # type: ignore[union-attr]
            trace_events=toolset._governor.trace_events,  # type: ignore[attr-defined]
            manifests=MANIFESTS, enforcement=ENFORCEMENT_OFF,
            trial={"trial_id": "t1"}, inputs_digest="sha256:0",
        )
        by_type = {e["type"]: e for e in trace["events"]}
        intent, result = by_type["tool_call_intent"], by_type["tool_result"]
        self.assertEqual(result["call_id"], intent["call_id"])
        self.assertEqual(set(intent["arg_bindings"]), {"recipient", "amount", "subject"})
        self.assertEqual(set(result["arg_bindings"]), {"recipient", "amount"})
        self.assertFalse(by_type["gate_decision"]["decision"]["enforced"])
        # still a valid trace/v1 event (the fields are the schema's own)
        schema = json.loads((Path(axor_core.__file__).parent / "contracts" / "schemas"
                             / "trace.schema.json").read_text())
        allowed = set(schema["$defs"]["event"]["properties"])
        self.assertLessEqual(set(result), allowed)

    def test_the_recorded_arguments_are_the_judged_ones(self) -> None:
        bank = Bank()
        toolset = _toolset(bank, field_contracts=CONTRACTS, record=True)
        toolset.call("send_money", {"recipient": ALLOWED, "amount": "3"})
        recorded = toolset._recorder.calls[0]  # type: ignore[union-attr]
        self.assertEqual(recorded.args, {"recipient": ALLOWED, "amount": 3, "subject": ""})
        kernel_args = toolset._governor.trace_events[0].payload["args"]  # type: ignore[attr-defined]
        self.assertEqual(kernel_args, recorded.args)


class TestNoUnsafeFallback(unittest.TestCase):
    def test_contracts_cannot_be_handed_to_an_injected_governor(self) -> None:
        with self.assertRaises(ValueError):
            WrappedToolset({"send_money": Bank().send_money}, MANIFESTS, policy=POLICY,
                           governor=object(), field_contracts=CONTRACTS)

    def test_a_kernel_that_returns_no_prepared_args_is_refused_at_call_time(self) -> None:
        from unittest import mock

        class _OldDecision:
            allowed, reason, category = True, "approved", "approved"

        class _OldGovernor:
            trace_events: list = []

            def evaluate(self, name, args):
                return _OldDecision()

            def register_output(self, decision, output):
                pass

        bank = Bank()
        with mock.patch("axor_wrap.runtime._build_governor", return_value=_OldGovernor()):
            toolset = _toolset(bank, field_contracts=CONTRACTS)
        with self.assertRaises(KernelIncompatibleError):
            toolset.call("send_money", {"recipient": ALLOWED, "amount": "7"})
        self.assertEqual(bank.transfers, [])

    def test_a_kernel_without_contract_support_is_refused_at_construction(self) -> None:
        from unittest import mock

        class _OldToolCallGovernor:
            def __init__(self, *, value_policies=None):
                pass

        with mock.patch("axor_core.governor.ToolCallGovernor", _OldToolCallGovernor):
            with self.assertRaises(KernelIncompatibleError):
                _toolset(Bank(), field_contracts=CONTRACTS)

    def test_without_contracts_an_old_kernel_still_works(self) -> None:
        from unittest import mock

        class _OldDecision:
            allowed, reason, category = True, "approved", "approved"

        class _OldGovernor:
            def evaluate(self, name, args):
                return _OldDecision()

            def register_output(self, decision, output):
                pass

        bank = Bank()
        toolset = WrappedToolset({"send_money": bank.send_money}, MANIFESTS, policy=POLICY,
                                 governor=_OldGovernor())
        toolset.call("send_money", {"recipient": ALLOWED, "amount": 5})
        self.assertEqual(bank.transfers, [(ALLOWED, 5)])


if __name__ == "__main__":
    unittest.main()
