"""Tests for isolation backends."""

import pytest
import sys
import os
from agent_sandbox.isolation import (
    IsolationLevel,
    IsolationConfig,
    IsolationResult,
    IsolationBackend,
    ProcessIsolation,
    ContainerIsolation,
)


class TestIsolationLevel:
    """Tests for IsolationLevel enum."""

    def test_levels_exist(self):
        assert IsolationLevel.NONE
        assert IsolationLevel.PROCESS
        assert IsolationLevel.CONTAINER

    def test_level_values(self):
        assert IsolationLevel.NONE.value == "none"
        assert IsolationLevel.PROCESS.value == "process"
        assert IsolationLevel.CONTAINER.value == "container"


class TestIsolationConfig:
    """Tests for IsolationConfig."""

    def test_default_config(self):
        config = IsolationConfig()
        assert config.level == IsolationLevel.PROCESS
        assert config.timeout_seconds == 30.0
        assert config.max_memory_mb == 256
        assert config.network_disabled is True

    def test_custom_config(self):
        config = IsolationConfig(
            level=IsolationLevel.CONTAINER,
            timeout_seconds=60.0,
            max_memory_mb=512,
            network_disabled=False,
        )
        assert config.level == IsolationLevel.CONTAINER
        assert config.timeout_seconds == 60.0
        assert config.max_memory_mb == 512
        assert config.network_disabled is False

    def test_env_vars(self):
        config = IsolationConfig(env_vars={"API_KEY": "secret", "DEBUG": "1"})
        assert config.env_vars["API_KEY"] == "secret"
        assert config.env_vars["DEBUG"] == "1"

    def test_to_dict(self):
        config = IsolationConfig(
            timeout_seconds=45.0,
            max_memory_mb=128,
        )
        d = config.to_dict()
        assert d["timeout_seconds"] == 45.0
        assert d["max_memory_mb"] == 128
        assert d["level"] == "process"


class TestIsolationResult:
    """Tests for IsolationResult."""

    def test_successful_result(self):
        result = IsolationResult(
            success=True,
            stdout="Hello, World!",
            stderr="",
            exit_code=0,
            execution_time=0.5,
        )
        assert result.success
        assert result.stdout == "Hello, World!"
        assert result.exit_code == 0

    def test_failed_result(self):
        result = IsolationResult(
            success=False,
            stdout="",
            stderr="Error occurred",
            exit_code=1,
            error="Script failed",
        )
        assert not result.success
        assert result.stderr == "Error occurred"
        assert result.error == "Script failed"

    def test_to_dict(self):
        result = IsolationResult(
            success=True,
            stdout="output",
            stderr="",
            exit_code=0,
            execution_time=1.234,
            memory_used_mb=50.5,
        )
        d = result.to_dict()
        assert d["success"] is True
        assert d["stdout"] == "output"
        assert d["exit_code"] == 0
        assert d["execution_time"] == 1.234
        assert d["memory_used_mb"] == 50.5


class TestProcessIsolation:
    """Tests for ProcessIsolation backend."""

    def test_backend_name(self):
        backend = ProcessIsolation()
        assert backend.name == "process"

    def test_is_available(self):
        backend = ProcessIsolation()
        assert backend.is_available() is True

    def test_execute_python_code(self):
        backend = ProcessIsolation()
        config = IsolationConfig(timeout_seconds=10.0)

        result = backend.execute(
            code='print("Hello from sandbox")',
            language="python",
            config=config,
        )

        assert result.success
        assert "Hello from sandbox" in result.stdout
        assert result.exit_code == 0

    def test_execute_python_with_error(self):
        backend = ProcessIsolation()
        config = IsolationConfig(timeout_seconds=10.0)

        result = backend.execute(
            code='raise ValueError("Test error")',
            language="python",
            config=config,
        )

        assert not result.success
        assert "ValueError" in result.stderr
        assert result.exit_code != 0

    def test_execute_with_env_vars(self):
        backend = ProcessIsolation()
        config = IsolationConfig(
            timeout_seconds=10.0,
            env_vars={"TEST_VAR": "test_value"},
        )

        result = backend.execute(
            code='import os; print(os.environ.get("TEST_VAR", "not found"))',
            language="python",
            config=config,
        )

        assert result.success
        assert "test_value" in result.stdout

    def test_timeout_handling(self):
        backend = ProcessIsolation()
        config = IsolationConfig(timeout_seconds=1.0)

        result = backend.execute(
            code='import time; time.sleep(10); print("done")',
            language="python",
            config=config,
        )

        assert not result.success
        assert "timed out" in result.error.lower()

    def test_unsupported_language(self):
        backend = ProcessIsolation()
        config = IsolationConfig()

        result = backend.execute(
            code='fn main() {}',
            language="rust",
            config=config,
        )

        assert not result.success
        assert "Unsupported language" in result.error

    def test_execution_time_tracked(self):
        backend = ProcessIsolation()
        config = IsolationConfig(timeout_seconds=10.0)

        result = backend.execute(
            code='import time; time.sleep(0.1); print("done")',
            language="python",
            config=config,
        )

        assert result.success
        assert result.execution_time >= 0.1

    def test_stderr_captured(self):
        backend = ProcessIsolation()
        config = IsolationConfig(timeout_seconds=10.0)

        result = backend.execute(
            code='import sys; sys.stderr.write("error message")',
            language="python",
            config=config,
        )

        assert "error message" in result.stderr

    def test_output_truncation(self):
        backend = ProcessIsolation()
        config = IsolationConfig(timeout_seconds=10.0)

        # Generate a lot of output
        result = backend.execute(
            code='print("x" * 200000)',
            language="python",
            config=config,
        )

        # Output should be truncated to 100000 chars
        assert len(result.stdout) <= 100000

    def test_python3_language(self):
        backend = ProcessIsolation()
        config = IsolationConfig(timeout_seconds=10.0)

        result = backend.execute(
            code='print("Python 3")',
            language="python3",
            config=config,
        )

        assert result.success
        assert "Python 3" in result.stdout


class TestContainerIsolation:
    """Tests for ContainerIsolation backend."""

    def test_backend_name(self):
        backend = ContainerIsolation()
        assert backend.name == "container"

    def test_custom_image(self):
        backend = ContainerIsolation(image="python:3.10-slim")
        assert backend.image == "python:3.10-slim"

    def test_is_available_check(self):
        backend = ContainerIsolation()
        # Just verify it returns a boolean
        result = backend.is_available()
        assert isinstance(result, bool)

    def test_docker_not_available_error(self):
        """Test behavior when Docker is not available."""
        backend = ContainerIsolation()

        # If Docker is not available, should return error result
        if not backend.is_available():
            config = IsolationConfig()
            result = backend.execute(
                code='print("test")',
                language="python",
                config=config,
            )
            assert not result.success
            assert "Docker not available" in result.error


class TestIsolationBackendInterface:
    """Tests for IsolationBackend interface."""

    def test_process_isolation_is_backend(self):
        backend = ProcessIsolation()
        assert isinstance(backend, IsolationBackend)

    def test_container_isolation_is_backend(self):
        backend = ContainerIsolation()
        assert isinstance(backend, IsolationBackend)

    def test_backend_abstract_methods(self):
        # Verify abstract methods exist
        assert hasattr(IsolationBackend, 'name')
        assert hasattr(IsolationBackend, 'execute')
        assert hasattr(IsolationBackend, 'is_available')
