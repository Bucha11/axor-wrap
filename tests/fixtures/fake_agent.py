"""A stand-in coding-agent CLI for tree tests: it fires the same hooks a real
Claude Code / Codex would (through `axor-wrap hook`), then prints its answer in
that CLI's output format. Its behaviour is picked by AXOR_ROLE."""
import json
import os
import subprocess
import sys

prompt = sys.argv[1]
role = os.environ["AXOR_ROLE"]
agent = "claude-code" if role in ("plan", "impl") else "codex"
session = os.environ["AXOR_NODE_ID"]


def hook(name, **fields):
    event = {"session_id": session, "cwd": os.getcwd(), "hook_event_name": name, **fields}
    out = subprocess.run([sys.executable, "-m", "axor_wrap.cli", "hook", agent],
                         input=json.dumps(event), capture_output=True, text=True)
    return json.loads(out.stdout) if out.stdout.strip() else {}


def tool(name, args, response, tid):
    answer = hook("PreToolUse", tool_name=name, tool_input=args, tool_use_id=tid)
    denied = answer.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
    if not denied:
        hook("PostToolUse", tool_name=name, tool_input=args, tool_use_id=tid,
             tool_response=response)
    return not denied


hook("UserPromptSubmit", prompt=prompt)
if role == "plan":
    answer = json.dumps({"steps": ["add a limiter", "wire it into login"],
                         "questions": [f"q{i}" for i in range(5)]})
elif role == "read":
    mine = [line[2:] for line in prompt.splitlines() if line.startswith("- q")]
    tool("Bash", {"command": "sed -n 1,40p src/auth.py"}, "def login(): ...", "r1")
    wrote = tool("apply_patch", {"command": "*** Begin Patch\n*** Update File: src/auth.py\n"
                                            "+x\n*** End Patch"}, "ok", "w1")
    answer = json.dumps({"mine": mine, "wrote": wrote, "findings": [
        {"claim": "login has no limiter", "file": "src/auth.py", "line": 3},
        {"claim": "sessions never expire", "file": "src/ghost.py", "line": 9}]})
else:
    answer = json.dumps({"saw_verified": "[verified] src/auth.py:3" in prompt,
                         "saw_unverified": "UNVERIFIED" in prompt and "src/ghost.py" in prompt,
                         "saw_plan": "1. add a limiter" in prompt})
hook("Stop", last_assistant_message=answer)
if agent == "claude-code":
    print(json.dumps({"type": "result", "result": answer,
                      "usage": {"input_tokens": 10, "output_tokens": 5}}))
else:
    print(json.dumps({"type": "item.completed",
                      "item": {"type": "agent_message", "text": answer}}))
