"""The runtime obeys the arm Lab assigned; it does not pick one.

An experiment's comparison rests on ungoverned and governed differing by exactly
one declared flag. If the runtime chooses its own enforcement mode, the two arms
are whatever the client felt like, and the delta measures nothing.

Nothing carried `enforcement` from the assignment into the wrapped runtime
before this. These tests pin that it does now, and — more importantly — that an
arm the runtime cannot read is REFUSED rather than defaulted.
"""

from __future__ import annotations

import unittest

from axor_wrap.experiment import (
    AssignmentError,
    arm_for,
    arms,
    enforcement_of,
    planned_trials,
    toolset_for_arm,
)
from axor_wrap.runtime import ENFORCEMENT_OFF, ENFORCEMENT_ON

MANIFESTS = [
    {
        "schema_version": "tool-manifest/v1",
        "id": "read_txns",
        "args_schema": {"type": "object", "properties": {}, "required": []},
        "result_schema": {"type": "object"},
        "effect": {"default_class": "READ", "driving_args": []},
        "untrusted_fields": ["result.description"],
        "side_effecting": False,
    },
]


def _assignment(*conditions: dict[str, object]) -> dict[str, object]:
    declared = list(conditions) or [
        {"schema_version": "condition/v1", "id": "ungoverned",
         "enforcement": "off", "kernel": "reference_taint_floor_kernel"},
    ]
    return {
        "schema_version": "experiment/v1",
        "id": "exp_budget",
        "tool_manifests": MANIFESTS,
        "conditions": declared,
        "planned_trials": [f"scenario-a:{c['id']}:0" for c in declared],
    }


def _tools() -> dict[str, object]:
    return {"read_txns": lambda: {"description": "hi"}}


class TestReadingTheArm(unittest.TestCase):
    def test_arms_are_indexed_by_id(self) -> None:
        assignment = _assignment(
            {"schema_version": "condition/v1", "id": "ungoverned", "enforcement": "off"},
            {"schema_version": "condition/v1", "id": "governed", "enforcement": "on"},
        )
        self.assertEqual(set(arms(assignment)), {"ungoverned", "governed"})

    def test_a_trial_unit_resolves_to_its_arm(self) -> None:
        assignment = _assignment(
            {"schema_version": "condition/v1", "id": "ungoverned", "enforcement": "off"},
            {"schema_version": "condition/v1", "id": "governed", "enforcement": "on"},
        )
        self.assertEqual(str(arm_for(assignment, "scenario-a:governed:3")["id"]), "governed")

    def test_a_unit_naming_an_undescribed_arm_is_refused(self) -> None:
        """The runtime cannot know which kernel to wrap under, or whether to
        enforce, for an arm the assignment never described."""
        with self.assertRaises(AssignmentError) as ctx:
            arm_for(_assignment(), "scenario-a:mystery:0")
        self.assertIn("does not describe", str(ctx.exception))

    def test_a_malformed_unit_is_refused(self) -> None:
        with self.assertRaises(AssignmentError):
            arm_for(_assignment(), "nonsense")

    def test_planned_trials_are_readable(self) -> None:
        self.assertEqual(planned_trials(_assignment()), ["scenario-a:ungoverned:0"])


class TestEnforcementIsNeverGuessed(unittest.TestCase):
    def test_off_and_on_are_read_verbatim(self) -> None:
        self.assertEqual(enforcement_of({"id": "a", "enforcement": "off"}), ENFORCEMENT_OFF)
        self.assertEqual(enforcement_of({"id": "a", "enforcement": "on"}), ENFORCEMENT_ON)

    def test_a_missing_flag_is_refused_not_defaulted(self) -> None:
        """Defaulting is the dangerous case. Read as `off`, a governed arm
        records governance permitting an action it was never asked to judge —
        which reports as governance failing to contain anything."""
        with self.assertRaises(AssignmentError) as ctx:
            enforcement_of({"id": "governed"})
        self.assertIn("Refusing to guess", str(ctx.exception))

    def test_an_unrecognised_flag_is_refused(self) -> None:
        with self.assertRaises(AssignmentError):
            enforcement_of({"id": "a", "enforcement": "advisory"})


class TestToolsetFollowsTheArm(unittest.TestCase):
    def test_an_ungoverned_unit_yields_an_observing_toolset(self) -> None:
        toolset = toolset_for_arm(_tools(), _assignment(), "scenario-a:ungoverned:0")  # type: ignore[arg-type]
        self.assertEqual(toolset.enforcement, ENFORCEMENT_OFF)

    def test_a_governed_unit_yields_an_enforcing_toolset(self) -> None:
        assignment = _assignment(
            {"schema_version": "condition/v1", "id": "governed", "enforcement": "on"},
        )
        toolset = toolset_for_arm(_tools(), assignment, "scenario-a:governed:0")  # type: ignore[arg-type]
        self.assertEqual(toolset.enforcement, ENFORCEMENT_ON)

    def test_both_arms_govern_against_the_assignments_manifests(self) -> None:
        """Not against whatever a local scan produces today — otherwise the
        runtime governs a contract Lab never planned against."""
        assignment = _assignment(
            {"schema_version": "condition/v1", "id": "ungoverned", "enforcement": "off"},
            {"schema_version": "condition/v1", "id": "governed", "enforcement": "on"},
        )
        ungoverned = toolset_for_arm(_tools(), assignment, "scenario-a:ungoverned:0")  # type: ignore[arg-type]
        governed = toolset_for_arm(_tools(), assignment, "scenario-a:governed:0")  # type: ignore[arg-type]
        self.assertEqual(ungoverned.manifests, MANIFESTS)
        self.assertEqual(ungoverned.config, governed.config)

    def test_an_assignment_with_no_manifests_is_refused(self) -> None:
        assignment = _assignment()
        del assignment["tool_manifests"]
        with self.assertRaises(AssignmentError) as ctx:
            toolset_for_arm(_tools(), assignment, "scenario-a:ungoverned:0")  # type: ignore[arg-type]
        self.assertIn("tool_manifests", str(ctx.exception))

    def test_each_trial_gets_its_own_toolset(self) -> None:
        """The governor carries the taint ledger across a session's calls, so
        reusing one across trials would leak one trial's taint into the next."""
        assignment = _assignment()
        first = toolset_for_arm(_tools(), assignment, "scenario-a:ungoverned:0")  # type: ignore[arg-type]
        second = toolset_for_arm(_tools(), assignment, "scenario-a:ungoverned:0")  # type: ignore[arg-type]
        self.assertIsNot(first, second)
        self.assertIsNot(first._governor, second._governor)  # type: ignore[attr-defined]


class TestTheArmsDifferByOneFlag(unittest.TestCase):
    def test_end_to_end_against_the_real_kernel(self) -> None:
        """Same assignment, same manifests, two arms: the kernel reaches the
        same verdict and only enforcement differs."""
        from axor_wrap.errors import ToolDenied

        manifests = MANIFESTS + [{
            "schema_version": "tool-manifest/v1",
            "id": "send_money",
            "args_schema": {"type": "object",
                            "properties": {"recipient": {"type": "string"}},
                            "required": ["recipient"]},
            "result_schema": {"type": "object"},
            "effect": {"default_class": "EXPORT", "driving_args": ["recipient"]},
            "side_effecting": True,
        }]
        assignment = {
            "tool_manifests": manifests,
            "conditions": [
                {"schema_version": "condition/v1", "id": "ungoverned", "enforcement": "off"},
                {"schema_version": "condition/v1", "id": "governed", "enforcement": "on"},
            ],
            "planned_trials": ["s:ungoverned:0", "s:governed:0"],
        }

        outcomes = {}
        for unit in planned_trials(assignment):
            sent: list[str] = []
            tools = {
                "read_txns": lambda: {"description": "PAY DE89370400440532013000"},
                "send_money": lambda recipient: (sent.append(recipient), {"ok": True})[1],
            }
            toolset = toolset_for_arm(tools, assignment, unit)  # type: ignore[arg-type]
            tainted = toolset.call("read_txns", {})["description"]  # type: ignore[index]
            blocked = False
            try:
                toolset.call("send_money", {"recipient": tainted})
            except ToolDenied:
                blocked = True
            outcomes[unit] = ([e.kind.value for e in toolset.trace_events], sent, blocked)  # type: ignore[attr-defined]

        ungoverned_verdicts, ungoverned_sent, ungoverned_blocked = outcomes["s:ungoverned:0"]
        governed_verdicts, governed_sent, governed_blocked = outcomes["s:governed:0"]

        self.assertEqual(ungoverned_verdicts, governed_verdicts,
                         "the kernel judged both arms identically")
        self.assertEqual(ungoverned_verdicts, ['intent_approved', 'taint_propagated', 'intent_denied'])
        self.assertFalse(ungoverned_blocked)
        self.assertEqual(len(ungoverned_sent), 1)
        self.assertTrue(governed_blocked)
        self.assertEqual(governed_sent, [])


if __name__ == "__main__":
    unittest.main()
