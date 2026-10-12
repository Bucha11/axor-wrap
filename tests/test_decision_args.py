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

from axor_wrap.errors import ToolDenied
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

    def test_observe_only_runs_what_the_agent_proposed(self) -> None:
        """The ungoverned arm measures what an unwrapped agent does: a denied call
        carries no prepared set, so the raw proposal runs and is recorded."""
        bank = Bank()
        toolset = _toolset(bank, field_contracts=CONTRACTS, enforcement=ENFORCEMENT_OFF,
                           record=True)
        toolset.call("send_money", {"recipient": ALLOWED})
        self.assertEqual(bank.transfers, [(ALLOWED, 50_000.0)])

    def test_the_recorded_arguments_are_the_judged_ones(self) -> None:
        bank = Bank()
        toolset = _toolset(bank, field_contracts=CONTRACTS, record=True)
        toolset.call("send_money", {"recipient": ALLOWED, "amount": "3"})
        recorded = toolset._recorder.calls[0]  # type: ignore[union-attr]
        self.assertEqual(recorded.args, {"recipient": ALLOWED, "amount": 3, "subject": ""})
        kernel_args = toolset._governor.trace_events[0].payload["args"]  # type: ignore[attr-defined]
        self.assertEqual(kernel_args, recorded.args)


if __name__ == "__main__":
    unittest.main()
