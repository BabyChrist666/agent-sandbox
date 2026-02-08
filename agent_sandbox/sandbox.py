"""
Main sandbox implementation.

High-level API for secure code execution environments.
"""

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .permissions import PermissionSet, FilePermission, NetworkPermission, ProcessPermission, PermissionLevel
from .isolation import IsolationBackend, ProcessIsolation, IsolationConfig, IsolationLevel
from .audit import AuditLog, AuditLevel
from .executor import CodeExecutor, ExecutionContext, ExecutionResult


class SandboxStatus(Enum):
    """Sandbox execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class SandboxConfig:
    """Configuration for sandbox environment."""
    # Resource limits
    timeout_seconds: float = 30.0
    max_memory_mb: int = 256
    max_output_bytes: int = 100000

    # Permissions
    allow_file_read: bool = False
    allow_file_write: bool = False
    allow_network: bool = False
    allow_subprocess: bool = False

    # Allowed paths for file access
    allowed_paths: List[str] = field(default_factory=list)
    denied_paths: List[str] = field(default_factory=list)

    # Audit
    enable_audit: bool = True
    audit_level: AuditLevel = AuditLevel.INFO

    def to_dict(self) -> dict:
        return {
            "timeout_seconds": self.timeout_seconds,
            "max_memory_mb": self.max_memory_mb,
            "max_output_bytes": self.max_output_bytes,
            "allow_file_read": self.allow_file_read,
            "allow_file_write": self.allow_file_write,
            "allow_network": self.allow_network,
            "allow_subprocess": self.allow_subprocess,
            "allowed_paths": self.allowed_paths,
            "denied_paths": self.denied_paths,
            "enable_audit": self.enable_audit,
        }

    def to_permission_set(self) -> PermissionSet:
        """Convert config to permission set."""
        permissions = PermissionSet()

        # File permissions
        if self.allow_file_read or self.allow_file_write:
            level = PermissionLevel.WRITE if self.allow_file_write else PermissionLevel.READ
            permissions.add(FilePermission(
                level=level,
                allowed_paths=self.allowed_paths or ["*"],
                denied_paths=self.denied_paths,
            ))
        else:
            permissions.add(FilePermission(level=PermissionLevel.NONE))

        # Network permissions
        permissions.add(NetworkPermission(
            allow_outbound=self.allow_network,
            allow_inbound=False,
            allowed_hosts=["*"] if self.allow_network else [],
        ))

        # Process permissions
        permissions.add(ProcessPermission(
            allow_subprocess=self.allow_subprocess,
            allow_shell=False,
        ))

        return permissions


@dataclass
class SandboxResult:
    """Result from sandbox execution."""
    status: SandboxStatus
    stdout: str
    stderr: str
    exit_code: int = 0
    execution_time: float = 0.0
    sandbox_id: str = ""
    error: Optional[str] = None
    audit_entries: int = 0

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "execution_time": round(self.execution_time, 3),
            "sandbox_id": self.sandbox_id,
            "error": self.error,
            "audit_entries": self.audit_entries,
        }


class Sandbox:
    """
    Secure code execution sandbox.

    Provides isolated environment for running untrusted code with:
    - Resource limits (CPU, memory, time)
    - Permission controls (file, network, process)
    - Audit logging
    - Multiple isolation backends
    """

    def __init__(
        self,
        config: Optional[SandboxConfig] = None,
        backend: Optional[IsolationBackend] = None,
    ):
        self.config = config or SandboxConfig()
        self.backend = backend or ProcessIsolation()
        self.audit = AuditLog() if self.config.enable_audit else None

        # Create executor with permissions
        permissions = self.config.to_permission_set()
        self.executor = CodeExecutor(
            permissions=permissions,
            backend=self.backend,
            audit=self.audit,
        )

        self._id = str(uuid.uuid4())[:8]

    @property
    def id(self) -> str:
        return self._id

    def execute(
        self,
        code: str,
        language: str = "python",
        env_vars: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        """
        Execute code in the sandbox.

        Args:
            code: Code to execute
            language: Programming language
            env_vars: Environment variables

        Returns:
            SandboxResult with output and status
        """
        context = ExecutionContext(
            id=self._id,
            language=language,
            timeout=self.config.timeout_seconds,
            max_memory_mb=self.config.max_memory_mb,
            env_vars=env_vars or {},
        )

        result = self.executor.execute(code, context)

        # Map execution result to sandbox result
        if result.error and "timed out" in result.error.lower():
            status = SandboxStatus.TIMEOUT
        elif result.success:
            status = SandboxStatus.COMPLETED
        else:
            status = SandboxStatus.FAILED

        # Truncate output
        stdout = result.stdout[:self.config.max_output_bytes]
        stderr = result.stderr[:self.config.max_output_bytes]

        # Get audit entry count
        audit_entries = 0
        if self.audit:
            summary = self.audit.get_summary(sandbox_id=self._id)
            audit_entries = summary["total_entries"]

        return SandboxResult(
            status=status,
            stdout=stdout,
            stderr=stderr,
            exit_code=result.exit_code,
            execution_time=result.execution_time,
            sandbox_id=self._id,
            error=result.error,
            audit_entries=audit_entries,
        )

    def validate(self, code: str, language: str = "python") -> Dict[str, Any]:
        """
        Validate code without executing.

        Args:
            code: Code to validate
            language: Programming language

        Returns:
            Validation result
        """
        return self.executor.validate_code(code, language)

    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit log entries for this sandbox."""
        if not self.audit:
            return []

        entries = self.audit.get_entries(sandbox_id=self._id, limit=limit)
        return [e.to_dict() for e in entries]

    def get_denied_actions(self) -> List[Dict[str, Any]]:
        """Get actions that were denied."""
        if not self.audit:
            return []

        entries = self.audit.get_denied_actions(sandbox_id=self._id)
        return [e.to_dict() for e in entries]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


def create_sandbox(
    timeout: float = 30.0,
    allow_file_read: bool = False,
    allow_file_write: bool = False,
    allow_network: bool = False,
    allowed_paths: Optional[List[str]] = None,
) -> Sandbox:
    """
    Create a sandbox with common settings.

    Args:
        timeout: Maximum execution time
        allow_file_read: Allow reading files
        allow_file_write: Allow writing files
        allow_network: Allow network access
        allowed_paths: Allowed file paths

    Returns:
        Configured Sandbox instance
    """
    config = SandboxConfig(
        timeout_seconds=timeout,
        allow_file_read=allow_file_read,
        allow_file_write=allow_file_write,
        allow_network=allow_network,
        allowed_paths=allowed_paths or [],
    )
    return Sandbox(config)
