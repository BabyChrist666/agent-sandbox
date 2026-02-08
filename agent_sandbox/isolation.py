"""
Isolation backends for sandbox execution.

Provides different levels of process isolation.
"""

import os
import sys
import subprocess
import tempfile
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum


class IsolationLevel(Enum):
    """Isolation strictness."""
    NONE = "none"           # No isolation (dangerous)
    PROCESS = "process"     # Separate process
    CONTAINER = "container" # Container isolation


@dataclass
class IsolationConfig:
    """Configuration for isolation."""
    level: IsolationLevel = IsolationLevel.PROCESS
    timeout_seconds: float = 30.0
    max_memory_mb: int = 256
    max_cpu_percent: int = 100
    working_dir: Optional[str] = None
    env_vars: Dict[str, str] = field(default_factory=dict)
    network_disabled: bool = True

    def to_dict(self) -> dict:
        return {
            "level": self.level.value,
            "timeout_seconds": self.timeout_seconds,
            "max_memory_mb": self.max_memory_mb,
            "max_cpu_percent": self.max_cpu_percent,
            "working_dir": self.working_dir,
            "network_disabled": self.network_disabled,
        }


@dataclass
class IsolationResult:
    """Result from isolated execution."""
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    execution_time: float = 0.0
    memory_used_mb: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "execution_time": round(self.execution_time, 3),
            "memory_used_mb": round(self.memory_used_mb, 2),
            "error": self.error,
        }


class IsolationBackend(ABC):
    """Base class for isolation backends."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Backend name."""
        pass

    @abstractmethod
    def execute(
        self,
        code: str,
        language: str,
        config: IsolationConfig,
    ) -> IsolationResult:
        """
        Execute code in isolation.

        Args:
            code: Code to execute
            language: Programming language
            config: Isolation configuration

        Returns:
            IsolationResult with output and status
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this backend is available."""
        pass


class ProcessIsolation(IsolationBackend):
    """Process-based isolation using subprocess."""

    @property
    def name(self) -> str:
        return "process"

    def is_available(self) -> bool:
        return True  # Always available

    def _get_interpreter(self, language: str) -> Optional[str]:
        """Get interpreter for a language."""
        interpreters = {
            "python": sys.executable,
            "python3": sys.executable,
            "node": "node",
            "javascript": "node",
            "ruby": "ruby",
            "bash": "bash",
            "sh": "sh",
        }
        return interpreters.get(language.lower())

    def execute(
        self,
        code: str,
        language: str,
        config: IsolationConfig,
    ) -> IsolationResult:
        import time

        interpreter = self._get_interpreter(language)
        if not interpreter:
            return IsolationResult(
                success=False,
                stdout="",
                stderr="",
                exit_code=-1,
                error=f"Unsupported language: {language}",
            )

        # Create temp directory for execution
        working_dir = config.working_dir
        temp_dir = None

        if not working_dir:
            temp_dir = tempfile.mkdtemp(prefix="sandbox_")
            working_dir = temp_dir

        try:
            # Write code to temp file
            ext = {"python": ".py", "python3": ".py", "node": ".js",
                   "javascript": ".js", "ruby": ".rb", "bash": ".sh", "sh": ".sh"}
            file_ext = ext.get(language.lower(), ".txt")
            code_file = os.path.join(working_dir, f"code{file_ext}")

            with open(code_file, "w", encoding="utf-8") as f:
                f.write(code)

            # Build command
            cmd = [interpreter, code_file]

            # Set up environment
            env = os.environ.copy()
            env.update(config.env_vars)

            # Remove dangerous env vars
            for key in ["PYTHONSTARTUP", "PYTHONPATH"]:
                env.pop(key, None)

            start_time = time.time()

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=config.timeout_seconds,
                    cwd=working_dir,
                    env=env,
                )

                execution_time = time.time() - start_time

                return IsolationResult(
                    success=result.returncode == 0,
                    stdout=result.stdout[:100000],  # Truncate
                    stderr=result.stderr[:100000],
                    exit_code=result.returncode,
                    execution_time=execution_time,
                )
            except subprocess.TimeoutExpired:
                return IsolationResult(
                    success=False,
                    stdout="",
                    stderr="",
                    exit_code=-1,
                    execution_time=config.timeout_seconds,
                    error=f"Execution timed out after {config.timeout_seconds}s",
                )
        except Exception as e:
            return IsolationResult(
                success=False,
                stdout="",
                stderr="",
                exit_code=-1,
                error=str(e),
            )
        finally:
            # Cleanup temp directory
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except Exception:
                    pass


class ContainerIsolation(IsolationBackend):
    """Container-based isolation using Docker."""

    def __init__(self, image: str = "python:3.11-slim"):
        self.image = image

    @property
    def name(self) -> str:
        return "container"

    def is_available(self) -> bool:
        """Check if Docker is available."""
        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def execute(
        self,
        code: str,
        language: str,
        config: IsolationConfig,
    ) -> IsolationResult:
        import time

        if not self.is_available():
            return IsolationResult(
                success=False,
                stdout="",
                stderr="",
                exit_code=-1,
                error="Docker not available",
            )

        # Create temp directory for code
        temp_dir = tempfile.mkdtemp(prefix="sandbox_")

        try:
            # Write code to file
            code_file = os.path.join(temp_dir, "code.py")
            with open(code_file, "w", encoding="utf-8") as f:
                f.write(code)

            # Build docker command
            cmd = [
                "docker", "run",
                "--rm",
                "--memory", f"{config.max_memory_mb}m",
                "--cpus", str(config.max_cpu_percent / 100),
                "-v", f"{temp_dir}:/code:ro",
                "-w", "/code",
            ]

            # Network isolation
            if config.network_disabled:
                cmd.extend(["--network", "none"])

            cmd.extend([
                self.image,
                "python", "/code/code.py",
            ])

            start_time = time.time()

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=config.timeout_seconds,
                )

                execution_time = time.time() - start_time

                return IsolationResult(
                    success=result.returncode == 0,
                    stdout=result.stdout[:100000],
                    stderr=result.stderr[:100000],
                    exit_code=result.returncode,
                    execution_time=execution_time,
                )
            except subprocess.TimeoutExpired:
                # Kill container if timeout
                subprocess.run(
                    ["docker", "kill", "sandbox-exec"],
                    capture_output=True,
                )
                return IsolationResult(
                    success=False,
                    stdout="",
                    stderr="",
                    exit_code=-1,
                    execution_time=config.timeout_seconds,
                    error=f"Execution timed out after {config.timeout_seconds}s",
                )
        except Exception as e:
            return IsolationResult(
                success=False,
                stdout="",
                stderr="",
                exit_code=-1,
                error=str(e),
            )
        finally:
            # Cleanup
            if os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except Exception:
                    pass
