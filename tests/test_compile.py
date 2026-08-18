from __future__ import annotations

import unittest

from axor_wrap.compile import compile_manifests, governance_yaml, governor_kwargs


def manifest(tool_id: str, default_class: str, *, driving: list[str] | None = None,
             untrusted: list[str] | None = None, resolve: list[dict] | None = None,
             sensitive: list[str] | None = None) -> dict[str, object]:
    m: dict[str, object] = {
        "schema_version": "tool-manifest/v1",
        "id": tool_id,
        "args_schema": {"type": "object"},
        "effect": {"default_class": default_class, "driving_args": driving or []},
        "side_effecting": default_class != "READ",
    }
    if resolve:
        m["effect"]["resolve"] = resolve  # type: ignore[index]
    if untrusted:
        m["untrusted_fields"] = untrusted
    if sensitive:
        m["sensitive_fields"] = sensitive
    return m


MANIFESTS = [
    manifest("send_email", "EXPORT", driving=["to"]),
    manifest("run_shell", "EXEC", driving=["command"]),
    manifest("search_web", "READ", untrusted=["result.*"]),
    manifest("read_secrets", "READ", sensitive=["result.value"]),
    manifest("update_crm", "WRITE", driving=["record_id"]),
]


class CompileTest(unittest.TestCase):
    """The mapping semantics must match lab_contracts.compiled_governor_config."""

    def test_export_and_exec_become_egress_sinks(self) -> None:
        canon = compile_manifests(MANIFESTS)
        self.assertEqual(canon["egress_sinks"], ["run_shell", "send_email"])  # sorted

    def test_write_and_read_are_not_egress(self) -> None:
        canon = compile_manifests(MANIFESTS)
        self.assertNotIn("update_crm", canon["egress_sinks"])
        self.assertNotIn("search_web", canon["egress_sinks"])

    def test_resolve_rules_count_toward_egress(self) -> None:
        # same semantics as lab: ANY resolvable class in EGRESS_CLASSES → egress sink
        m = manifest("send_or_draft", "WRITE",
                     resolve=[{"when": {"recipient": {"not_in": "$company"}}, "class": "EXPORT"}])
        canon = compile_manifests([m])
        self.assertEqual(canon["egress_sinks"], ["send_or_draft"])

    def test_untrusted_fields_make_untrusted_sources(self) -> None:
        canon = compile_manifests(MANIFESTS)
        self.assertEqual(canon["untrusted_sources"], ["search_web"])
        self.assertEqual(canon["untrusted_fields"], {"search_web": ["result.*"]})

    def test_sensitive_fields_make_sensitive_sources(self) -> None:
        canon = compile_manifests(MANIFESTS)
        self.assertEqual(canon["sensitive_sources"], ["read_secrets"])

    def test_driving_args_mapping(self) -> None:
        canon = compile_manifests(MANIFESTS)
        self.assertEqual(canon["driving_args"], {
            "send_email": ["to"], "run_shell": ["command"], "update_crm": ["record_id"],
        })

    def test_allowlist_becomes_enum_value_policy_on_first_driving_arg(self) -> None:
        canon = compile_manifests(MANIFESTS, policy={"allowlist": ["alice@corp.com"]})
        self.assertEqual(canon["value_policies"], {
            "send_email": {"to": {"enum": ["alice@corp.com"]}},
            "run_shell": {"command": {"enum": ["alice@corp.com"]}},
        })
        # a sink with no driving args falls back to "recipient" (lab semantics)
        canon = compile_manifests([manifest("send_raw", "EXPORT")],
                                  policy={"allowlist": ["x"]})
        self.assertEqual(canon["value_policies"], {"send_raw": {"recipient": {"enum": ["x"]}}})

    def test_governor_kwargs_shape(self) -> None:
        kwargs = governor_kwargs(MANIFESTS, policy={"allowlist": ["a@b.c"]})
        self.assertEqual(kwargs["egress_sinks"], {"send_email", "run_shell"})
        self.assertEqual(kwargs["untrusted_sources"], {"search_web"})
        self.assertEqual(kwargs["sensitive_sources"], {"read_secrets"})
        self.assertIn("send_email", kwargs["value_policies"])
        self.assertNotIn("untrusted_fields", kwargs)  # not a ToolCallGovernor kwarg

    def test_governor_kwargs_omit_empty_optionals(self) -> None:
        kwargs = governor_kwargs([manifest("send_email", "EXPORT", driving=["to"])])
        self.assertNotIn("value_policies", kwargs)
        self.assertNotIn("sensitive_sources", kwargs)

    def test_governance_yaml_structure(self) -> None:
        text = governance_yaml(MANIFESTS, policy={"allowlist": ["alice@corp.com"]})
        self.assertIn('egress_sinks:\n  - "run_shell"\n  - "send_email"', text)
        self.assertIn('untrusted_sources:\n  - "search_web"', text)
        self.assertIn('sensitive_sources:\n  - "read_secrets"', text)
        self.assertIn('"send_email":\n    - "to"', text)  # driving_args block
        self.assertIn("kind: enum", text)
        self.assertIn('- "alice@corp.com"', text)

    def test_governance_yaml_parses_and_matches_governance_config_keys(self) -> None:
        # stdlib-only structural check: every top-level key is a GovernanceConfig field
        text = governance_yaml(MANIFESTS, policy={"allowlist": ["a@b.c"]})
        known = {"untrusted_sources", "sensitive_sources", "egress_sinks", "positional_sinks",
                 "imperative_sinks", "benign_tools", "value_policies", "driving_args",
                 "consequence_overrides", "mode", "workspace", "profile", "federation"}
        for line in text.splitlines():
            if line and not line.startswith((" ", "#")):
                self.assertIn(line.rstrip(":"), known, line)


if __name__ == "__main__":
    unittest.main()


class TestTheCompiledConfigIsACTUALLYUsableByTheKernel(unittest.TestCase):
    """The tests above check the SHAPE of what we compile. That is not enough:
    every one of them passed while `value_policies` was a shape the governor
    could not consume at all.

    axor-core wants `dict[str, list[ValuePredicate]]` — objects with `.check()`.
    We handed it the nested `{sink: {arg: {"enum": [...]}}}`, so
    `check_value_policies` iterated a dict, got its KEYS, and died on
    `'str' object has no attribute 'check'`. Every policy carrying an allowlist
    crashed the governor, including the enum-supersession path this module
    describes as the sound, paraphrase-proof control.

    So these construct a real `ToolCallGovernor` and call it. A config that only
    LOOKS right is not a config.
    """

    ALLOWED = "alice@corp.com"
    ATTACKER = "attacker@evil.example"

    def _governor(self, policy: dict[str, object] | None = None):
        from axor_core.governor import ToolCallGovernor

        return ToolCallGovernor(**governor_kwargs(MANIFESTS, policy))  # type: ignore[arg-type]

    def test_the_governor_accepts_every_compiled_field(self) -> None:
        self._governor({"allowlist": [self.ALLOWED],
                        "criticality_overrides": {"send_email": "REVERSIBLE"}})

    def test_a_value_policy_actually_denies_an_unlisted_destination(self) -> None:
        decision = self._governor({"allowlist": [self.ALLOWED]}).evaluate(
            "send_email", {"to": self.ATTACKER},
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.category, "value_policy")

    def test_it_allows_a_listed_destination(self) -> None:
        self.assertTrue(
            self._governor({"allowlist": [self.ALLOWED]})
            .evaluate("send_email", {"to": self.ALLOWED}).allowed,
        )

    def test_enum_supersession_lets_a_tainted_but_listed_value_through(self) -> None:
        """The point of an allowlist: an operator-declared destination survives
        the taint floor, because the destination set is attacker-inaccessible."""
        governor = self._governor({"allowlist": [self.ALLOWED]})
        read = governor.evaluate("search_web", {})
        governor.register_output(read, f"contact {self.ALLOWED} urgently")
        self.assertTrue(governor.evaluate("send_email", {"to": self.ALLOWED}).allowed)

    def test_without_the_allowlist_the_same_tainted_value_is_denied(self) -> None:
        """The control has to be what makes the difference, not the taint engine
        happening to miss it."""
        governor = self._governor()
        read = governor.evaluate("search_web", {})
        governor.register_output(read, f"contact {self.ALLOWED} urgently")
        decision = governor.evaluate("send_email", {"to": self.ALLOWED})
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.category, "taint_enforcement")

    def test_a_criticality_override_actually_denies(self) -> None:
        decision = self._governor(
            {"criticality_overrides": {"send_email": "CATASTROPHIC"}},
        ).evaluate("send_email", {"to": self.ALLOWED})
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.category, "consequence_gate")
