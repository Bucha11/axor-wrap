from __future__ import annotations

import unittest

from axor_wrap.detect import DetectedTool
from axor_wrap.roles import infer_effect


def make_tool(tool_id: str, description: str = "", args: tuple[str, ...] = (),
              framework: str = "langchain") -> DetectedTool:
    return DetectedTool(
        id=tool_id, source="x.py:1 test", description=description,
        args_schema={"type": "object", "properties": {a: {"type": "string"} for a in args},
                     "required": list(args)},
        framework=framework,
    )


class RolesTest(unittest.TestCase):
    def test_read_verbs(self) -> None:
        for name in ("read_file", "get_weather", "search_docs", "list_users", "fetch_page"):
            guess = infer_effect(make_tool(name))
            self.assertEqual(guess.default_class, "READ", name)
            self.assertEqual(guess.confidence, "high")

    def test_write_verbs(self) -> None:
        for name in ("write_file", "update_record", "create_ticket", "insert_row"):
            self.assertEqual(infer_effect(make_tool(name)).default_class, "WRITE", name)

    def test_export_verbs(self) -> None:
        for name in ("send_email", "post_message", "publish_article", "upload_report",
                     "slack_notify"):
            self.assertEqual(infer_effect(make_tool(name)).default_class, "EXPORT", name)

    def test_export_confidence_raised_by_carrier_args(self) -> None:
        bare = infer_effect(make_tool("send_email"))
        with_to = infer_effect(make_tool("send_email", args=("to", "subject", "body")))
        self.assertEqual(bare.confidence, "medium")
        self.assertEqual(with_to.confidence, "high")

    def test_exec_verbs(self) -> None:
        for name in ("shell", "exec_command", "run_script", "eval_expr", "bash"):
            guess = infer_effect(make_tool(name))
            self.assertEqual(guess.default_class, "EXEC", name)

    def test_sql_with_write_verbs_is_exec(self) -> None:
        guess = infer_effect(make_tool("sql_tool", description="Execute INSERT and UPDATE on the DB"))
        self.assertEqual(guess.default_class, "EXEC")

    def test_read_email_is_read_not_export(self) -> None:
        self.assertEqual(infer_effect(make_tool("read_email")).default_class, "READ")

    def test_unknown_is_a_normal_outcome(self) -> None:
        guess = infer_effect(make_tool("frobnicate"))
        self.assertEqual(guess.default_class, "UNKNOWN")
        self.assertEqual(guess.confidence, "low")
        self.assertIn("classify manually", guess.reason)

    def test_description_only_match_lowers_confidence(self) -> None:
        guess = infer_effect(make_tool("gizmo", description="send the report to a channel"))
        self.assertEqual(guess.default_class, "EXPORT")
        self.assertIn(guess.confidence, ("medium", "low"))

    def test_driving_args_guess(self) -> None:
        guess = infer_effect(make_tool("send_email", args=("subject", "to", "body")))
        self.assertEqual(guess.driving_args, ("to",))
        guess = infer_effect(make_tool("post_message", args=("channel", "url", "text")))
        self.assertEqual(guess.driving_args, ("url", "channel"))

    def test_untrusted_candidates_for_external_reads(self) -> None:
        self.assertEqual(infer_effect(make_tool("search_web")).untrusted_fields, ("result.*",))
        self.assertEqual(infer_effect(make_tool("fetch_page")).untrusted_fields, ("result.*",))
        self.assertEqual(infer_effect(make_tool("read_inbox")).untrusted_fields, ("result.*",))
        # a local read is not an untrusted source
        self.assertEqual(infer_effect(make_tool("read_config")).untrusted_fields, ())

    def test_implicit_shell_is_exec(self) -> None:
        guess = infer_effect(make_tool("shell", framework="implicit"))
        self.assertEqual(guess.default_class, "EXEC")
        self.assertEqual(guess.confidence, "high")
        self.assertEqual(guess.driving_args, ("command",))

    def test_reason_is_always_populated(self) -> None:
        for name in ("read_file", "send_email", "frobnicate"):
            self.assertTrue(infer_effect(make_tool(name)).reason)


if __name__ == "__main__":
    unittest.main()
