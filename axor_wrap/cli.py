"""axor-wrap CLI.

    axor-wrap scan <path>                     table of detected tools + effect guesses
    axor-wrap manifest <path> -o <dir>        one manifest per tool + wrap.json sidecar
    axor-wrap config <manifests-dir>          governance YAML to stdout
    axor-wrap connect-lab --base-url ... --model ...   register a Lab runtime

Exit codes: 0 ok; 2 nothing found / bad input.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from axor_wrap import __version__
from axor_wrap.compile import governance_yaml
from axor_wrap.connect import LabRuntimeConnector
from axor_wrap.detect import DetectedTool, scan_project
from axor_wrap.errors import ConnectorError, ManifestValidationError
from axor_wrap.manifest import SCHEMA_VERSION, build_manifest, ensure_valid
from axor_wrap.roles import EffectGuess, infer_effect

EXIT_OK = 0
EXIT_EMPTY = 2


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    handler = {
        "scan": _cmd_scan,
        "manifest": _cmd_manifest,
        "config": _cmd_config,
        "connect-lab": _cmd_connect_lab,
    }[args.command]
    return handler(args)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="axor-wrap",
        description="Wrap engine: scan agent code, emit tool manifests, compile governance",
    )
    parser.add_argument("--version", action="version", version=f"axor-wrap {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="detect tools in a project")
    p_scan.add_argument("path", type=Path)

    p_manifest = sub.add_parser("manifest", help="write tool-manifest/v1 files + wrap.json")
    p_manifest.add_argument("path", type=Path)
    p_manifest.add_argument("-o", "--out", type=Path, required=True, metavar="DIR")

    p_config = sub.add_parser("config", help="print governance YAML for a manifests dir")
    p_config.add_argument("manifests_dir", type=Path)

    p_lab = sub.add_parser("connect-lab", help="register this runtime with an axor-lab server")
    p_lab.add_argument("--base-url", required=True)
    p_lab.add_argument("--model", required=True)
    p_lab.add_argument("--agent-ref", default=None)
    p_lab.add_argument("--control-token", default=None)
    return parser


def _scan_or_fail(path: Path) -> list[tuple[DetectedTool, EffectGuess]] | None:
    if not path.exists():
        print(f"error: path does not exist: {path}", file=sys.stderr)
        return None
    tools = scan_project(path)
    if not tools:
        print(f"no tools detected under {path}", file=sys.stderr)
        return None
    return [(tool, infer_effect(tool)) for tool in tools]


def _cmd_scan(args: argparse.Namespace) -> int:
    detected = _scan_or_fail(args.path)
    if detected is None:
        return EXIT_EMPTY
    rows = [("TOOL", "FRAMEWORK", "EFFECT", "CONF", "SCHEMA", "SOURCE")]
    rows.extend(
        (tool.id, tool.framework, guess.default_class, guess.confidence,
         tool.schema_confidence, tool.source)
        for tool, guess in detected
    )
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]) - 1)]
    for row in rows:
        head = "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row[:-1]))
        print(f"{head}  {row[-1]}")
    print(f"\n{len(detected)} tool(s) detected")
    return EXIT_OK


def _cmd_manifest(args: argparse.Namespace) -> int:
    detected = _scan_or_fail(args.path)
    if detected is None:
        return EXIT_EMPTY
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    sidecar: list[dict[str, object]] = []
    used: set[str] = set()
    for tool, guess in detected:
        try:  # should be unreachable; fail loudly, never write an invalid file
            manifest = ensure_valid(build_manifest(tool, guess))
        except ManifestValidationError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_EMPTY
        stem = tool.id
        n = 1
        while stem in used:
            n += 1
            stem = f"{tool.id}-{n}"
        used.add(stem)
        path = out / f"{stem}.manifest.json"
        path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        sidecar.append({
            "id": tool.id,
            "manifest": path.name,
            "framework": tool.framework,
            "source": tool.source,
            "schema_confidence": tool.schema_confidence,
            "effect_guess": {
                "class": guess.default_class,  # UNKNOWN survives here, honest
                "confidence": guess.confidence,
                "reason": guess.reason,
            },
        })
        print(f"wrote {path}")
    wrap = out / "wrap.json"
    wrap.write_text(json.dumps({
        "generated_by": f"axor-wrap {__version__}",
        "manifest_schema": SCHEMA_VERSION,
        "tools": sidecar,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {wrap}")
    return EXIT_OK


def _cmd_config(args: argparse.Namespace) -> int:
    directory: Path = args.manifests_dir
    if not directory.is_dir():
        print(f"error: not a directory: {directory}", file=sys.stderr)
        return EXIT_EMPTY
    manifests: list[dict[str, object]] = []
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            continue
        if isinstance(data, dict) and data.get("schema_version") == SCHEMA_VERSION:
            manifests.append(data)
    if not manifests:
        print(f"no {SCHEMA_VERSION} manifests in {directory}", file=sys.stderr)
        return EXIT_EMPTY
    print(governance_yaml(manifests), end="")
    return EXIT_OK


def _cmd_connect_lab(args: argparse.Namespace) -> int:
    connector = LabRuntimeConnector(args.base_url, control_token=args.control_token)
    try:
        payload = connector.connect(model=args.model, agent_ref=args.agent_ref)
    except ConnectorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_EMPTY
    print(json.dumps({
        "runtime_ref": payload["runtime_ref"],
        "ingest_key": payload["ingest_key"],
    }, indent=2))
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
