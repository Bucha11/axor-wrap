"""axor-wrap error hierarchy. Every library-raised error roots at AxorWrapError."""

from __future__ import annotations


class AxorWrapError(Exception):
    """Base class for every axor-wrap error."""


class ScanError(AxorWrapError):
    """The scan root does not exist or contains nothing scannable."""


class ManifestValidationError(AxorWrapError):
    """A built manifest failed validation against the embedded tool-manifest/v1 schema."""

    def __init__(self, tool_id: str, errors: list[str]) -> None:
        super().__init__(f"manifest {tool_id!r} is invalid: " + "; ".join(errors))
        self.tool_id = tool_id
        self.errors = tuple(errors)


class KernelNotInstalledError(AxorWrapError, ImportError):
    """axor-core is required for runtime wrapping but is not installed."""

    def __init__(self) -> None:
        super().__init__(
            "axor-core is not installed — the wrapped runtime needs the real kernel. "
            "Install the extra: pip install 'axor-wrap[kernel]'"
        )


class UnknownToolError(AxorWrapError, KeyError):
    """A call named a tool the wrapped toolset does not hold."""

    def __init__(self, name: str, known: tuple[str, ...]) -> None:
        super().__init__(f"unknown tool {name!r}; wrapped tools: {sorted(known)}")
        self.name = name


class ToolDenied(AxorWrapError):
    """The governor denied a tool call. Carries the kernel's reason and gate category."""

    def __init__(self, reason: str, category: str = "denied") -> None:
        super().__init__(f"[{category}] {reason}")
        self.reason = reason
        self.category = category


class ConnectorError(AxorWrapError):
    """A Lab runtime-jobs request failed; carries the HTTP status (0 = transport)."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"HTTP {status}: {message}" if status else message)
        self.status = status
        self.message = message


class PlaneExtraNotInstalledError(AxorWrapError, ImportError):
    """Control-Plane attachment needs the ``plane`` extra (axor-core for the
    kernel primitives, httpx + cryptography for the transport), which is not
    installed."""

    def __init__(self) -> None:
        super().__init__(
            "Control-Plane attachment needs the plane transport — install the extra: "
            "pip install 'axor-wrap[plane]'  (axor-core + httpx + cryptography)"
        )


class AdmissionHeld(AxorWrapError):
    """A tool call was held at the intent boundary because an operator paused or
    stopped this node from the Control Plane. Carries the current posture so the
    caller can distinguish a resumable pause from a terminal stop."""

    def __init__(self, posture: str) -> None:
        super().__init__(f"node admission held: {posture}")
        self.posture = posture
