"""
Agent Sandbox - Secure code execution environment for AI agents.

Provides isolated execution environments with resource limits,
permission controls, and audit logging for running AI-generated code safely.
"""

from .sandbox import (
    Sandbox,
    SandboxConfig,
    SandboxResult,
    SandboxStatus,
)
from .permissions import (
    Permission,
    PermissionSet,
    PermissionLevel,
    FilePermission,
    NetworkPermission,
    ProcessPermission,
)
from .isolation import (
    IsolationBackend,
    ProcessIsolation,
    ContainerIsolation,
    IsolationConfig,
)
from .audit import (
    AuditLog,
    AuditEntry,
    AuditLevel,
)
from .executor import (
    CodeExecutor,
    ExecutionContext,
    ExecutionResult,
)

__version__ = "0.1.0"

__all__ = [
    # Sandbox
    "Sandbox",
    "SandboxConfig",
    "SandboxResult",
    "SandboxStatus",
    # Permissions
    "Permission",
    "PermissionSet",
    "PermissionLevel",
    "FilePermission",
    "NetworkPermission",
    "ProcessPermission",
    # Isolation
    "IsolationBackend",
    "ProcessIsolation",
    "ContainerIsolation",
    "IsolationConfig",
    # Audit
    "AuditLog",
    "AuditEntry",
    "AuditLevel",
    # Executor
    "CodeExecutor",
    "ExecutionContext",
    "ExecutionResult",
]
