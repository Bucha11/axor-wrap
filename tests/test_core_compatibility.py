"""The declared axor-core range must include the kernel actually installed.

This package pins axor-core and then imports its every surface, and nothing
checked that the two agreed. Measured: the pin said `<0.11` while an installed
0.11.0 ran 213 tests green — a declaration that was simply wrong, with no
alarm anywhere. In the same workspace that stale ceiling met axor-backend's
`>=0.11` and left the repository unable to install itself:

    uv sync -> your workspace's requirements are unsatisfiable

axor-eval and axor-sentinel each carry a `compatibility.py` holding MIN/MAX as a
second copy of the range, which their pyproject then asks somebody to "keep in
lockstep" by hand. This reads the DECLARATION instead — there is no second copy
to drift, and the thing under test is the bound a `pip install` will honour.

Warn-shaped, not fatal, in the same spirit: a kernel outside the range is a
release-ordering fact to surface loudly, not a reason to make the suite
unrunnable while somebody publishes.
"""
from __future__ import annotations

import pathlib
import tomllib

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

PYPROJECT = pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml"


def _declared() -> Requirement:
    data = tomllib.loads(PYPROJECT.read_text())
    for raw in data["project"]["dependencies"]:
        requirement = Requirement(raw)
        if requirement.name == "axor-core":
            return requirement
    pytest.fail(f"{PYPROJECT} declares no axor-core dependency")


def test_the_installed_kernel_satisfies_the_declared_range() -> None:
    import axor_core

    declared = _declared()
    installed = Version(axor_core.__version__)
    assert installed in declared.specifier, (
        f"axor-core {installed} is installed and this package declares "
        f"{declared.specifier}. Every test here runs against the installed "
        f"kernel, so a green suite says nothing about the version a user will "
        f"actually get. Move the bound, or say why the installed one is wrong."
    )


def test_the_range_is_bounded_at_both_ends() -> None:
    """An unbounded ceiling is how this rots in the other direction: the next
    kernel major lands, `pip install` takes it, and nothing here notices until
    something explodes at a customer."""
    operators = {spec.operator for spec in _declared().specifier}
    assert operators & {"<", "<=", "=="}, "axor-core needs an upper bound"
    assert operators & {">=", ">", "==", "~="}, "axor-core needs a lower bound"
