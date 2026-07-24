from __future__ import annotations

import shutil
import unittest
from pathlib import Path

from axor_wrap.detect import DetectedTool, scan_project

from tests import fixtures


class DetectTest(unittest.TestCase):
    root: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.root = fixtures.write_project(fixtures.ALL_FIXTURES)
        cls.tools = scan_project(cls.root)
        cls.by_id = {t.id: t for t in cls.tools}

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.root, ignore_errors=True)

    def tool(self, tool_id: str) -> DetectedTool:
        self.assertIn(tool_id, self.by_id, f"{tool_id} not detected; got {sorted(self.by_id)}")
        return self.by_id[tool_id]

    # ── langchain ────────────────────────────────────────────────────────────

    def test_langchain_tool_decorator(self) -> None:
        tool = self.tool("search_web")
        self.assertEqual(tool.framework, "langchain")
        self.assertIn("langchain:@tool", tool.source)
        self.assertEqual(tool.description, "Search the web for a query.")
        props = tool.args_schema["properties"]
        self.assertEqual(props["query"], {"type": "string"})
        self.assertEqual(props["max_results"], {"type": "integer"})
        self.assertEqual(tool.args_schema["required"], ["query"])  # default → optional
        self.assertEqual(tool.schema_confidence, "high")

    def test_langchain_tool_decorator_with_name_override(self) -> None:
        tool = self.tool("send_email")
        self.assertEqual(tool.framework, "langchain")
        props = tool.args_schema["properties"]
        self.assertEqual(set(props), {"to", "subject", "body"})
        self.assertEqual(tool.args_schema["required"], ["to", "subject", "body"])

    def test_structured_tool_from_function(self) -> None:
        tool = self.tool("update_record")
        self.assertIn("StructuredTool.from_function", tool.source)
        self.assertEqual(tool.description, "Update a CRM record.")
        props = tool.args_schema["properties"]
        self.assertEqual(props["record_id"], {"type": "integer"})
        self.assertEqual(props["payload"], {"type": "object"})

    def test_tool_constructor_with_unresolvable_func_is_honest(self) -> None:
        tool = self.tool("mystery_gizmo")
        self.assertIn("langchain:Tool()", tool.source)
        # lambda cannot be introspected → bare object schema + low confidence
        self.assertEqual(tool.args_schema, {"type": "object"})
        self.assertEqual(tool.schema_confidence, "low")
        self.assertEqual(tool.description, "Does something unspecified")

    # ── mcp ──────────────────────────────────────────────────────────────────

    def test_mcp_tool_decorator(self) -> None:
        tool = self.tool("read_file")
        self.assertEqual(tool.framework, "mcp")
        self.assertIn("mcp:@app.tool", tool.source)
        self.assertEqual(tool.args_schema["properties"]["path"], {"type": "string"})

    def test_mcp_tool_decorator_name_kwarg(self) -> None:
        tool = self.tool("post_slack_message")
        self.assertEqual(tool.framework, "mcp")
        self.assertEqual(set(tool.args_schema["properties"]), {"channel", "text"})

    # ── anthropic registry ───────────────────────────────────────────────────

    def test_anthropic_registry_literal_schema(self) -> None:
        tool = self.tool("fetch_url")
        self.assertEqual(tool.framework, "anthropic")
        self.assertIn("anthropic:registry", tool.source)
        self.assertEqual(tool.description, "Fetch a web page over HTTP")
        self.assertEqual(tool.args_schema["properties"], {"url": {"type": "string"}})
        self.assertEqual(tool.schema_confidence, "high")

    def test_anthropic_registry_dynamic_schema_is_low_confidence(self) -> None:
        tool = self.tool("frobnicate")
        self.assertEqual(tool.args_schema, {"type": "object"})
        self.assertEqual(tool.schema_confidence, "low")

    # ── implicit subprocess ──────────────────────────────────────────────────

    def test_implicit_shell_candidate(self) -> None:
        tool = self.tool("shell")
        self.assertEqual(tool.framework, "implicit")
        self.assertIn("implicit:subprocess.run", tool.source)
        self.assertEqual(tool.schema_confidence, "low")

    # ── general behavior ─────────────────────────────────────────────────────

    def test_plain_module_yields_nothing(self) -> None:
        sources = " ".join(t.source for t in self.tools)
        self.assertNotIn("plain.py", sources)

    def test_source_carries_file_and_line(self) -> None:
        tool = self.tool("search_web")
        self.assertRegex(tool.source, r"^agent_langchain\.py:\d+ ")

    def test_scan_single_file(self) -> None:
        tools = scan_project(self.root / "mcp_server.py")
        self.assertEqual({t.id for t in tools}, {"read_file", "post_slack_message"})

    def test_syntax_error_file_is_skipped(self) -> None:
        root = fixtures.write_project({"broken.py": "def broken(:\n", "ok.py": fixtures.MCP_SERVER})
        try:
            tools = scan_project(root)
            self.assertEqual({t.id for t in tools}, {"read_file", "post_slack_message"})
        finally:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
