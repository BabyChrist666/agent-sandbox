"""
Code executor with permission checking and auditing.

Executes code while enforcing permissions and logging actions.
"""

import uuid
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .permissions import PermissionSet, Permission
from .isolation import IsolationBackend, ProcessIsolation, IsolationConfig, IsolationResult
from .audit import AuditLog, AuditLevel


@dataclass
class ExecutionContext:
    """Context for code execution."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    language: str = "python"
    timeout: float = 30.0
    max_memory_mb: int = 256
    env_vars: Dict[str, str] = field(default_factory=dict)
    working_dir: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "language": self.language,
            "timeout": self.timeout,
            "max_memory_mb": self.max_memory_mb,
            "working_dir": self.working_dir,
            "metadata": self.metadata,
        }


@dataclass
class ExecutionResult:
    """Result from code execution."""
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    execution_time: float = 0.0
    context_id: str = ""
    error: Optional[str] = None
    denied_actions: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "execution_time": round(self.execution_time, 3),
            "context_id": self.context_id,
            "error": self.error,
            "denied_actions": self.denied_actions,
        }


class CodeExecutor:
    """
    Executes code with permission checking and auditing.

    Provides a high-level API for safe code execution with:
    - Permission enforcement
    - Multiple isolation backends
    - Audit logging
    - Resource limits
    """

    def __init__(
        self,
        permissions: Optional[PermissionSet] = None,
        backend: Optional[IsolationBackend] = None,
        audit: Optional[AuditLog] = None,
    ):
        self.permissions = permissions or PermissionSet.default()
        self.backend = backend or ProcessIsolation()
        self.audit = audit or AuditLog()

    def execute(
        self,
        code: str,
        context: Optional[ExecutionContext] = None,
    ) -> ExecutionResult:
        """
        Execute code in a sandboxed environment.

        Args:
            code: Code to execute
            context: Execution context with settings

        Returns:
            ExecutionResult with output and status
        """
        context = context or ExecutionContext()

        # Log execution start
        self.audit.info(
            category="execution",
            action="start",
            sandbox_id=context.id,
            details={
                "language": context.language,
                "code_length": len(code),
            },
        )

        start_time = time.time()

        # Check code for dangerous patterns
        denied_actions = self._check_code_patterns(code, context)
        if denied_actions:
            self.audit.warning(
                category="execution",
                action="denied_patterns",
                sandbox_id=context.id,
                allowed=False,
                details={"patterns": denied_actions},
            )
            return ExecutionResult(
                success=False,
                stdout="",
                stderr="",
                exit_code=-1,
                context_id=context.id,
                error="Code contains denied patterns",
                denied_actions=denied_actions,
            )

        # Create isolation config
        config = IsolationConfig(
            timeout_seconds=context.timeout,
            max_memory_mb=context.max_memory_mb,
            working_dir=context.working_dir,
            env_vars=context.env_vars,
        )

        # Execute in isolation
        try:
            result = self.backend.execute(code, context.language, config)

            execution_time = time.time() - start_time

            # Log result
            if result.success:
                self.audit.info(
                    category="execution",
                    action="complete",
                    sandbox_id=context.id,
                    details={
                        "execution_time": execution_time,
                        "exit_code": result.exit_code,
                    },
                )
            else:
                self.audit.error(
                    category="execution",
                    action="failed",
                    sandbox_id=context.id,
                    details={
                        "execution_time": execution_time,
                        "exit_code": result.exit_code,
                        "error": result.error,
                    },
                )

            return ExecutionResult(
                success=result.success,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                execution_time=execution_time,
                context_id=context.id,
                error=result.error,
            )
        except Exception as e:
            self.audit.critical(
                category="execution",
                action="exception",
                sandbox_id=context.id,
                details={"error": str(e)},
            )
            return ExecutionResult(
                success=False,
                stdout="",
                stderr="",
                exit_code=-1,
                context_id=context.id,
                error=str(e),
            )

    def _check_code_patterns(
        self,
        code: str,
        context: ExecutionContext,
    ) -> List[Dict[str, str]]:
        """Check code for dangerous patterns."""
        denied = []

        # Python-specific patterns
        if context.language in ["python", "python3"]:
            dangerous_imports = [
                "os.system",
                "subprocess",
                "multiprocessing",
                "__import__",
                "eval(",
                "exec(",
                "compile(",
                "open(",
                "socket",
                "requests",
                "urllib",
            ]

            # Check if process permissions allow subprocess
            process_perm = self.permissions.get("process")
            if process_perm and not process_perm.allows("spawn", "subprocess"):
                # Block process-related and dynamic code execution patterns
                process_patterns = [
                    "os.system",
                    "subprocess",
                    "multiprocessing",
                    "__import__",
                    "eval(",
                    "exec(",
                    "compile(",
                ]
                for pattern in process_patterns:
                    if pattern in code:
                        denied.append({
                            "pattern": pattern,
                            "reason": "Process spawn not allowed",
                        })

            # Check network permissions
            network_perm = self.permissions.get("network")
            if network_perm and not network_perm.allows("connect", "*"):
                for pattern in ["socket", "requests", "urllib", "http.client"]:
                    if pattern in code:
                        denied.append({
                            "pattern": pattern,
                            "reason": "Network access not allowed",
                        })

            # Check file permissions
            file_perm = self.permissions.get("file")
            if file_perm:
                if "open(" in code and not file_perm.allows("read", "*"):
                    denied.append({
                        "pattern": "open(",
                        "reason": "File access not allowed",
                    })

        return denied

    def validate_code(
        self,
        code: str,
        language: str = "python",
    ) -> Dict[str, Any]:
        """
        Validate code without executing it.

        Args:
            code: Code to validate
            language: Programming language

        Returns:
            Validation result with issues found
        """
        context = ExecutionContext(language=language)
        denied = self._check_code_patterns(code, context)

        return {
            "valid": len(denied) == 0,
            "issues": denied,
            "code_length": len(code),
            "language": language,
        }

    def get_audit_summary(self, context_id: Optional[str] = None) -> dict:
        """Get audit summary for executions."""
        return self.audit.get_summary(sandbox_id=context_id)
