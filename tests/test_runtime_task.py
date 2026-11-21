"""The user's task reaches the governor (axor-core context integrity)."""
from __future__ import annotations

import pytest

from axor_wrap import ToolDenied, WrappedToolset, harness_manifest

LANDLORD = "GB29NWBK60161331926819"


def _toolset(**kw: object) -> WrappedToolset:
    return WrappedToolset(
        {"read_inbox": lambda: "Your landlord's bank details are on file.",
         "send_money": lambda recipient, amount: "sent"},
        [harness_manifest("read_inbox", untrusted=True),
         harness_manifest("send_money", effect_class="EXPORT", driving_args=["recipient"])],
        **kw,
    )


def _context_kernel() -> bool:
    from axor_core.taint.engine import TaintEngine
    return getattr(TaintEngine(), "integrity_default", "clean") == "context"


def test_a_recipient_the_user_named_is_paid_after_a_read() -> None:
    ts = _toolset(task=f"pay this month's rent to {LANDLORD}")
    ts.call("read_inbox", {})
    assert ts.call("send_money", {"recipient": LANDLORD, "amount": 1100}) == "sent"


def test_without_the_task_the_same_payment_is_refused() -> None:
    if not _context_kernel():
        pytest.skip("this kernel trusts any model-written value (clean default)")
    ts = _toolset()
    ts.call("read_inbox", {})
    with pytest.raises(ToolDenied):
        ts.call("send_money", {"recipient": LANDLORD, "amount": 1100})


def test_register_task_later_works_too() -> None:
    ts = _toolset()
    ts.register_task(f"pay this month's rent to {LANDLORD}")
    ts.call("read_inbox", {})
    assert ts.call("send_money", {"recipient": LANDLORD, "amount": 1100}) == "sent"
