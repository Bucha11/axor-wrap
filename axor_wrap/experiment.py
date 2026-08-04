"""Reading an experiment assignment — the runtime obeys the arm, it does not choose it.

axor-lab assigns; the runtime executes. Part of what it assigns is the ARM each
trial runs under, and an arm carries `enforcement`: `off` for ungoverned
(observe, never block) and `on` for governed. Both run through the kernel — that
is the difference between ungoverned and unwrapped.

Before this, nothing carried that flag from the assignment into the wrapped
runtime, so a runtime had to decide for itself which mode to run in. An
experiment whose ungoverned and governed arms were chosen by the client is not
an experiment: the whole comparison rests on the arms differing by exactly one
declared flag.

So this module is deliberately the ONLY place that reads it, and it refuses an
arm it does not understand rather than falling back to a default. Defaulting
would silently turn a governed arm into an ungoverned one — measured as
governance failing to contain anything, when in truth nothing was enforcing.
"""

from __future__ import annotations

from typing import Callable

from axor_wrap.errors import AxorWrapError
from axor_wrap.runtime import ENFORCEMENT_OFF, ENFORCEMENT_ON, WrappedToolset


class AssignmentError(AxorWrapError):
    """The assignment does not describe what the runtime needs to execute it."""


def arms(assignment: dict[str, object]) -> dict[str, dict[str, object]]:
    """The conditions this assignment plans, by id."""
    declared = assignment.get("conditions") or []
    return {str(arm["id"]): dict(arm) for arm in declared}  # type: ignore[index,union-attr]


def enforcement_of(arm: dict[str, object]) -> str:
    """`on` or `off`, exactly as the arm declares it.

    An absent or unrecognised value raises. It must not default: an arm silently
    read as `off` would record governance permitting an action it was never
    asked to judge, and one read as `on` would block calls the experiment meant
    to observe.
    """
    value = arm.get("enforcement")
    if value not in (ENFORCEMENT_ON, ENFORCEMENT_OFF):
        raise AssignmentError(
            f"arm {arm.get('id')!r} declares enforcement {value!r}; expected "
            f"{ENFORCEMENT_ON!r} or {ENFORCEMENT_OFF!r}. Refusing to guess — the "
            f"comparison rests on this flag being the only difference between arms"
        )
    return str(value)


def arm_for(assignment: dict[str, object], trial_unit: str) -> dict[str, object]:
    """The arm a planned trial unit (`scenario:arm:repeat`) belongs to."""
    try:
        _, arm_id, _ = str(trial_unit).rsplit(":", 2)
    except ValueError as exc:
        raise AssignmentError(f"malformed trial unit {trial_unit!r}") from exc
    declared = arms(assignment)
    if arm_id not in declared:
        raise AssignmentError(
            f"trial {trial_unit!r} names arm {arm_id!r}, which the assignment does "
            f"not describe (it declares {sorted(declared)}). The runtime cannot know "
            f"which kernel to wrap under or whether to enforce"
        )
    return declared[arm_id]


def toolset_for_arm(
    tools: dict[str, Callable[..., object]],
    assignment: dict[str, object],
    trial_unit: str,
    *,
    policy: dict[str, object] | None = None,
    governor: object | None = None,
    admission: Callable[[], bool] | None = None,
) -> WrappedToolset:
    """A wrapped toolset configured for the arm this trial belongs to.

    The tool manifests come from the assignment, so the runtime governs against
    the same contract Lab planned against — not against whatever its local scan
    happens to produce today.

    One instance per trial: the governor carries the per-value taint ledger
    across a session's calls, so reusing it across trials would leak one trial's
    taint into the next.
    """
    manifests = assignment.get("tool_manifests")
    if not isinstance(manifests, list) or not manifests:
        raise AssignmentError(
            "assignment carries no tool_manifests — the runtime would have to govern "
            "against a contract Lab never planned against"
        )
    arm = arm_for(assignment, trial_unit)
    return WrappedToolset(
        tools, list(manifests), policy=policy, governor=governor,
        admission=admission, enforcement=enforcement_of(arm),
        # a trial exists to produce a trace; recording is not optional here
        record=True,
    )


def planned_trials(assignment: dict[str, object]) -> list[str]:
    units = assignment.get("planned_trials")
    if not isinstance(units, list):
        raise AssignmentError("assignment carries no planned_trials")
    return [str(unit) for unit in units]
