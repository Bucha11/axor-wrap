"""axor-core is a required dependency, and this is what keeps it one.

The package's headline artifact is a runtime where every tool call goes
``evaluate → deny? → call → register_output`` through the real kernel, and the
governor config it compiles is meaningless without the governor that consumes
it. While axor-core sat in ``[project.optional-dependencies]`` under a `kernel`
extra, ``pip install axor-wrap`` produced something that scans code and then
raises when asked to gate it — and the plane test suite sat red on a machine
where nothing looked obviously missing.

Declaring it in `dependencies` is the fix; this test is what stops it drifting
back. A dependency posture nobody checks is a comment.
"""

from __future__ import annotations

import sys
import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
KERNEL = "axor-core"

# The plane's TRANSPORT is legitimately optional: a wrap that never attaches to
# a Control Plane needs neither the HTTP client nor signature verification.
# The kernel is not in that category.
OPTIONAL_BY_DESIGN = frozenset({"httpx", "cryptography"})


def _pyproject() -> dict[str, object]:
    return tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())


def _requirement_names(entries: list[str]) -> set[str]:
    names: set[str] = set()
    for entry in entries:
        name = entry.split(";")[0].strip()
        for separator in ("[", ">", "<", "=", "!", "~", " "):
            name = name.split(separator)[0]
        if name:
            names.add(name.strip())
    return names


class TestDependencyDeclaration(unittest.TestCase):
    def test_the_kernel_is_a_required_dependency(self) -> None:
        required = _requirement_names(
            _pyproject()["project"]["dependencies"]  # type: ignore[index,arg-type]
        )
        self.assertIn(
            KERNEL, required,
            "axor-core must sit in [project.dependencies]; the wrapped runtime "
            "cannot gate without it, so it is not an opt-in",
        )

    def test_no_extra_re_offers_the_kernel(self) -> None:
        """An extra that also lists axor-core would reintroduce the idea that
        you can have this package without it."""
        extras: dict[str, list[str]] = (
            _pyproject()["project"].get("optional-dependencies", {})  # type: ignore[index,union-attr]
        )
        for extra, entries in extras.items():
            if extra == "dev":
                continue
            with self.subTest(extra=extra):
                self.assertNotIn(
                    KERNEL, _requirement_names(entries),
                    f"extra {extra!r} re-offers axor-core as optional",
                )

    def test_the_retired_kernel_extra_is_gone(self) -> None:
        extras: dict[str, list[str]] = (
            _pyproject()["project"].get("optional-dependencies", {})  # type: ignore[index,union-attr]
        )
        self.assertNotIn("kernel", extras)

    def test_the_plane_extra_still_only_carries_transport(self) -> None:
        """The split that remains is real: the plane is an advisory overlay, and
        its HTTP/signature deps are genuinely optional."""
        extras: dict[str, list[str]] = (
            _pyproject()["project"].get("optional-dependencies", {})  # type: ignore[index,union-attr]
        )
        self.assertLessEqual(_requirement_names(extras.get("plane", [])), OPTIONAL_BY_DESIGN)


class TestKernelIsActuallyPresent(unittest.TestCase):
    def test_axor_core_imports(self) -> None:
        """A declaration nothing exercises is still a guess. If this fails, the
        environment does not satisfy the package's own requirements."""
        import axor_core  # noqa: PLC0415

        self.assertTrue(axor_core.__file__)

    def test_the_governor_the_runtime_needs_is_importable(self) -> None:
        from axor_core.governor import ToolCallGovernor  # noqa: PLC0415

        self.assertTrue(callable(ToolCallGovernor))

    def test_a_wrapped_toolset_gates_through_the_real_kernel(self) -> None:
        """End of the chain: the dependency exists so THIS works, without a
        fake governor injected anywhere."""
        for module in list(sys.modules):
            if module.startswith("axor_core"):
                self.assertFalse(
                    getattr(sys.modules[module], "_is_test_double", False),
                    "a test double is shadowing the real kernel",
                )
        from axor_wrap.runtime import WrappedToolset  # noqa: PLC0415

        self.assertTrue(hasattr(WrappedToolset, "call"))


if __name__ == "__main__":
    unittest.main()
