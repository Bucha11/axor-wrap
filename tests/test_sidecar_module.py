"""The sidecar runs as ``python -m axor_wrap.agents.sidecar``: there the module
is ``__main__`` and ``main()`` starts serving the moment its guard is reached,
so anything defined below the guard does not exist yet. 0.3.1 defined a helper
there; every tool result raised NameError and none reached the plane."""
from __future__ import annotations

import ast
from pathlib import Path

import axor_wrap.agents.sidecar as sidecar


def test_the_main_guard_is_the_last_statement() -> None:
    tree = ast.parse(Path(sidecar.__file__).read_text())
    last = tree.body[-1]
    assert isinstance(last, ast.If) and "__main__" in ast.unparse(last.test), \
        "nothing may follow `if __name__ == '__main__'` in the sidecar module"
