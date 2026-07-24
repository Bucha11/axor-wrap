"""Static tool scanner — stdlib ``ast``, no imports of the scanned code.

``scan_project(root)`` walks a project's ``.py`` files and detects tool
definitions without executing anything:

- **LangChain**: functions decorated with ``@tool`` (any alias imported from
  ``langchain_core.tools`` / ``langchain.tools``), ``StructuredTool.from_function(...)``
  calls, and ``Tool(name=..., func=...)`` constructor calls;
- **MCP (FastMCP)**: ``@mcp.tool()`` / ``@server.tool()`` decorators — including any
  name bound via ``x = FastMCP(...)``;
- **Anthropic-style registries**: dict literals with the ``{name, description,
  input_schema}`` key triple;
- **implicit shell**: ``subprocess.run/Popen/...`` or ``os.system`` calls inside an
  agent module → one implicit ``shell`` candidate tool per file.

Argument schemas are inferred from signatures and type hints (str→string,
int→integer, float→number, bool→boolean; default present → optional). Honesty
rule: anything the scanner cannot infer stays a bare ``{"type": "object"}`` with
``schema_confidence: "low"`` — it never invents types.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

FRAMEWORK_LANGCHAIN = "langchain"
FRAMEWORK_MCP = "mcp"
FRAMEWORK_ANTHROPIC = "anthropic"
FRAMEWORK_IMPLICIT = "implicit"

CONFIDENCE_HIGH = "high"
CONFIDENCE_LOW = "low"

_SKIP_DIRS = frozenset({
    ".git", "__pycache__", ".venv", "venv", "node_modules", ".tox", ".mypy_cache",
    ".ruff_cache", "dist", "build", ".eggs",
})

_LANGCHAIN_TOOL_MODULES = ("langchain_core.tools", "langchain.tools", "langchain.agents")
_HINT_TO_JSON = {"str": "string", "int": "integer", "float": "number", "bool": "boolean"}
_CONTAINER_HINTS = {"list": "array", "tuple": "array", "set": "array", "dict": "object"}
_SUBPROCESS_FUNCS = frozenset({"run", "Popen", "call", "check_call", "check_output"})
_MCP_DEFAULT_OBJECTS = frozenset({"mcp", "server", "app"})
_ANTHROPIC_KEYS = frozenset({"name", "description", "input_schema"})


@dataclass(frozen=True)
class DetectedTool:
    """One statically detected tool candidate."""

    id: str
    source: str  # "<file>:<line> <detector kind>"
    description: str
    args_schema: dict[str, object] = field(default_factory=dict)
    framework: str = FRAMEWORK_LANGCHAIN
    schema_confidence: str = CONFIDENCE_HIGH


def scan_project(root: Path) -> list[DetectedTool]:
    """Scan every ``.py`` file under ``root`` (or a single file) for tools."""
    root = Path(root)
    if root.is_file():
        files = [root]
        base = root.parent
    else:
        files = sorted(p for p in root.rglob("*.py") if not (_SKIP_DIRS & set(p.parts)))
        base = root
    tools: list[DetectedTool] = []
    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue  # honest skip: a file we cannot parse yields no guesses
        rel = str(path.relative_to(base)) if path.is_relative_to(base) else str(path)
        tools.extend(_scan_module(tree, rel))
    return tools


# ── per-module scan ──────────────────────────────────────────────────────────────


def _scan_module(tree: ast.Module, rel: str) -> list[DetectedTool]:
    ctx = _ModuleContext.collect(tree)
    out: list[DetectedTool] = []
    subprocess_hit: tuple[int, str] | None = None

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            tool = _from_decorated_function(node, ctx, rel)
            if tool is not None:
                out.append(tool)
        elif isinstance(node, ast.Call):
            tool = _from_call(node, ctx, rel)
            if tool is not None:
                out.append(tool)
            elif subprocess_hit is None:
                kind = _subprocess_kind(node, ctx)
                if kind is not None:
                    subprocess_hit = (node.lineno, kind)
        elif isinstance(node, ast.Dict):
            tool = _from_registry_dict(node, rel)
            if tool is not None:
                out.append(tool)

    if subprocess_hit is not None:
        line, kind = subprocess_hit
        out.append(DetectedTool(
            id="shell",
            source=f"{rel}:{line} implicit:{kind}",
            description=f"Implicit shell capability: module calls {kind} directly "
                        "(candidate tool, review before wrapping)",
            args_schema={"type": "object"},
            framework=FRAMEWORK_IMPLICIT,
            schema_confidence=CONFIDENCE_LOW,
        ))
    out.sort(key=_source_line)
    return out


def _source_line(tool: DetectedTool) -> int:
    location = tool.source.split(" ", 1)[0]  # "<file>:<line>"
    try:
        return int(location.rsplit(":", 1)[-1])
    except ValueError:
        return 0


@dataclass
class _ModuleContext:
    """Import aliases + module-level function defs a detector needs to resolve names."""

    tool_decorators: set[str] = field(default_factory=set)       # aliases of langchain `tool`
    structured_tool_names: set[str] = field(default_factory=set)  # aliases of StructuredTool
    tool_class_names: set[str] = field(default_factory=set)       # aliases of Tool
    mcp_objects: set[str] = field(default_factory=lambda: set(_MCP_DEFAULT_OBJECTS))
    subprocess_aliases: set[str] = field(default_factory=set)     # `from subprocess import run as r`
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = field(default_factory=dict)

    @classmethod
    def collect(cls, tree: ast.Module) -> "_ModuleContext":
        ctx = cls()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module in _LANGCHAIN_TOOL_MODULES or node.module.startswith("langchain"):
                    for alias in node.names:
                        bound = alias.asname or alias.name
                        if alias.name == "tool":
                            ctx.tool_decorators.add(bound)
                        elif alias.name == "StructuredTool":
                            ctx.structured_tool_names.add(bound)
                        elif alias.name == "Tool":
                            ctx.tool_class_names.add(bound)
                elif node.module == "subprocess":
                    for alias in node.names:
                        if alias.name in _SUBPROCESS_FUNCS:
                            ctx.subprocess_aliases.add(alias.asname or alias.name)
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                func = node.value.func
                ctor = func.id if isinstance(func, ast.Name) else (
                    func.attr if isinstance(func, ast.Attribute) else "")
                if ctor == "FastMCP":
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            ctx.mcp_objects.add(target.id)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                ctx.functions.setdefault(node.name, node)
        # lenient defaults: StructuredTool.from_function is distinctive even unimported
        ctx.structured_tool_names.add("StructuredTool")
        return ctx


# ── decorated functions (langchain @tool, mcp @x.tool()) ────────────────────────


def _from_decorated_function(
    fn: ast.FunctionDef | ast.AsyncFunctionDef, ctx: _ModuleContext, rel: str,
) -> DetectedTool | None:
    for dec in fn.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        # langchain: @tool / @tool("name") / @tool(parse_docstring=True)
        if isinstance(target, ast.Name) and target.id in ctx.tool_decorators:
            name = fn.name
            if isinstance(dec, ast.Call) and dec.args and isinstance(dec.args[0], ast.Constant) \
                    and isinstance(dec.args[0].value, str):
                name = dec.args[0].value
            schema, confidence = _schema_from_function(fn)
            return DetectedTool(
                id=name, source=f"{rel}:{fn.lineno} langchain:@tool",
                description=_docstring_summary(fn), args_schema=schema,
                framework=FRAMEWORK_LANGCHAIN, schema_confidence=confidence,
            )
        # mcp: @mcp.tool() / @server.tool() / @mcp.tool
        if isinstance(target, ast.Attribute) and target.attr == "tool" \
                and isinstance(target.value, ast.Name) and target.value.id in ctx.mcp_objects:
            name = fn.name
            if isinstance(dec, ast.Call):
                kw_name = _kwarg_str(dec, "name")
                if kw_name:
                    name = kw_name
            schema, confidence = _schema_from_function(fn)
            return DetectedTool(
                id=name, source=f"{rel}:{fn.lineno} mcp:@{target.value.id}.tool",
                description=_docstring_summary(fn), args_schema=schema,
                framework=FRAMEWORK_MCP, schema_confidence=confidence,
            )
    return None


# ── constructor calls (StructuredTool.from_function, Tool(...)) ──────────────────


def _from_call(call: ast.Call, ctx: _ModuleContext, rel: str) -> DetectedTool | None:
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr == "from_function" \
            and isinstance(func.value, ast.Name) and func.value.id in ctx.structured_tool_names:
        return _tool_from_ctor(call, ctx, rel, "langchain:StructuredTool.from_function")
    if isinstance(func, ast.Name) and (
        func.id in ctx.tool_class_names
        or (func.id == "Tool" and _kwarg(call, "name") is not None and _kwarg(call, "func") is not None)
    ):
        return _tool_from_ctor(call, ctx, rel, "langchain:Tool()")
    return None


def _tool_from_ctor(call: ast.Call, ctx: _ModuleContext, rel: str, kind: str) -> DetectedTool | None:
    name = _kwarg_str(call, "name")
    func_ref = _kwarg(call, "func")
    resolved = ctx.functions.get(func_ref.id) if isinstance(func_ref, ast.Name) else None
    if name is None:
        if resolved is None:
            return None  # nothing identifiable — not a detection
        name = resolved.name
    description = _kwarg_str(call, "description") or ""
    if resolved is not None:
        schema, confidence = _schema_from_function(resolved)
        description = description or _docstring_summary(resolved)
    else:
        # honest fallback: the callable is a lambda/import we cannot follow
        schema, confidence = {"type": "object"}, CONFIDENCE_LOW
    return DetectedTool(
        id=name, source=f"{rel}:{call.lineno} {kind}", description=description,
        args_schema=schema, framework=FRAMEWORK_LANGCHAIN, schema_confidence=confidence,
    )


# ── anthropic-style registry dicts ───────────────────────────────────────────────


def _from_registry_dict(node: ast.Dict, rel: str) -> DetectedTool | None:
    keys = {k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    if not _ANTHROPIC_KEYS <= keys:
        return None
    entries: dict[str, ast.expr] = {
        k.value: v for k, v in zip(node.keys, node.values)
        if isinstance(k, ast.Constant) and isinstance(k.value, str)
    }
    name_node = entries["name"]
    if not (isinstance(name_node, ast.Constant) and isinstance(name_node.value, str)):
        return None
    desc_node = entries["description"]
    description = desc_node.value if isinstance(desc_node, ast.Constant) \
        and isinstance(desc_node.value, str) else ""
    try:
        raw_schema = ast.literal_eval(entries["input_schema"])
    except (ValueError, SyntaxError):
        raw_schema = None
    if isinstance(raw_schema, dict):
        schema: dict[str, object] = raw_schema
        confidence = CONFIDENCE_HIGH if raw_schema.get("properties") else CONFIDENCE_LOW
    else:
        schema, confidence = {"type": "object"}, CONFIDENCE_LOW
    return DetectedTool(
        id=name_node.value, source=f"{rel}:{node.lineno} anthropic:registry",
        description=description, args_schema=schema,
        framework=FRAMEWORK_ANTHROPIC, schema_confidence=confidence,
    )


# ── subprocess heuristic ─────────────────────────────────────────────────────────


def _subprocess_kind(call: ast.Call, ctx: _ModuleContext) -> str | None:
    func = call.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        if func.value.id == "subprocess" and func.attr in _SUBPROCESS_FUNCS:
            return f"subprocess.{func.attr}"
        if func.value.id == "os" and func.attr == "system":
            return "os.system"
    if isinstance(func, ast.Name) and func.id in ctx.subprocess_aliases:
        return f"subprocess.{func.id}"
    return None


# ── signature → JSON-schema inference ────────────────────────────────────────────


def _schema_from_function(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[dict[str, object], str]:
    args = fn.args
    params = [a for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)
              if a.arg not in ("self", "cls")]
    properties: dict[str, object] = {}
    confidence = CONFIDENCE_HIGH
    for param in params:
        prop: dict[str, object] = {}
        json_type = _annotation_type(param.annotation)
        if json_type is None:
            confidence = CONFIDENCE_LOW  # honest: we could not infer this arg's type
        else:
            prop["type"] = json_type
        properties[param.arg] = prop
    if args.vararg is not None or args.kwarg is not None:
        confidence = CONFIDENCE_LOW  # *args/**kwargs escape static inference
    n_pos = len(args.posonlyargs) + len(args.args)
    defaults_start = n_pos - len(args.defaults)
    optional = {a.arg for a in (*args.posonlyargs, *args.args)[defaults_start:]}
    optional.update(a.arg for a, d in zip(args.kwonlyargs, args.kw_defaults) if d is not None)
    required = [p.arg for p in params if p.arg not in optional]
    schema: dict[str, object] = {"type": "object", "properties": properties, "required": required}
    if not properties:
        schema = {"type": "object", "properties": {}, "required": []}
    return schema, confidence


def _annotation_type(annotation: ast.expr | None) -> str | None:
    if annotation is None:
        return None
    if isinstance(annotation, ast.Name):
        return _HINT_TO_JSON.get(annotation.id) or _CONTAINER_HINTS.get(annotation.id)
    if isinstance(annotation, ast.Subscript) and isinstance(annotation.value, ast.Name):
        base = annotation.value.id
        if base in ("Optional",):
            inner = annotation.slice
            return _annotation_type(inner if isinstance(inner, ast.expr) else None)
        return _CONTAINER_HINTS.get(base)
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        # `str | None` → the non-None side
        for side in (annotation.left, annotation.right):
            if not (isinstance(side, ast.Constant) and side.value is None):
                return _annotation_type(side)
    return None


# ── small helpers ────────────────────────────────────────────────────────────────


def _docstring_summary(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    doc = ast.get_docstring(fn) or ""
    for line in doc.splitlines():
        if line.strip():
            return line.strip()
    return ""


def _kwarg(call: ast.Call, name: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _kwarg_str(call: ast.Call, name: str) -> str | None:
    node = _kwarg(call, name)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None
