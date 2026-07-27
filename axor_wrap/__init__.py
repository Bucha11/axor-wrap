"""axor-wrap — wrap engine for the Axor ecosystem.

Scan agent code (Python / LangChain / MCP), detect its tools, and emit
(a) tool-manifest/v1 files, (b) governance config, (c) a wrapped runtime
compatible with both the Control Plane and axor-lab.
"""

from axor_wrap._version import get_version
from axor_wrap.compile import compile_manifests, governance_yaml, governor_kwargs
from axor_wrap.connect import LabRuntimeConnector, PlaneConnector
from axor_wrap.detect import DetectedTool, scan_project
from axor_wrap.errors import (
    AdmissionHeld,
    AxorWrapError,
    ConnectorError,
    KernelNotInstalledError,
    ManifestValidationError,
    PlaneExtraNotInstalledError,
    ToolDenied,
    UnknownToolError,
)
from axor_wrap.manifest import build_manifest, ensure_valid, validate_manifest
from axor_wrap.roles import EffectGuess, infer_effect
from axor_wrap.runtime import WrappedToolset, wrap_callables

__version__ = get_version("axor-wrap")

__all__ = [
    "AdmissionHeld",
    "AxorWrapError",
    "ConnectorError",
    "DetectedTool",
    "EffectGuess",
    "KernelNotInstalledError",
    "LabRuntimeConnector",
    "ManifestValidationError",
    "PlaneConnector",
    "PlaneExtraNotInstalledError",
    "ToolDenied",
    "UnknownToolError",
    "WrappedToolset",
    "__version__",
    "build_manifest",
    "compile_manifests",
    "ensure_valid",
    "governance_yaml",
    "governor_kwargs",
    "infer_effect",
    "scan_project",
    "validate_manifest",
    "wrap_callables",
]
