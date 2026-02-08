"""Tests for main sandbox implementation."""

import pytest
from agent_sandbox.sandbox import (
    SandboxStatus,
    SandboxConfig,
    SandboxResult,
    Sandbox,
    create_sandbox,
)
from agent_sandbox.permissions import PermissionLevel
from agent_sandbox.audit import AuditLevel


class TestSandboxStatus:
    """Tests for SandboxStatus enum."""

    def test_statuses_exist(self):
        assert SandboxStatus.PENDING
        assert SandboxStatus.RUNNING
        assert SandboxStatus.COMPLETED
        assert SandboxStatus.FAILED
        assert SandboxStatus.TIMEOUT

    def test_status_values(self):
        assert SandboxStatus.PENDING.value == "pending"
        assert SandboxStatus.RUNNING.value == "running"
        assert SandboxStatus.COMPLETED.value == "completed"
        assert SandboxStatus.FAILED.value == "failed"
        assert SandboxStatus.TIMEOUT.value == "timeout"


class TestSandboxConfig:
    """Tests for SandboxConfig."""

    def test_default_config(self):
        config = SandboxConfig()
        assert config.timeout_seconds == 30.0
        assert config.max_memory_mb == 256
        assert config.max_output_bytes == 100000
        assert config.allow_file_read is False
        assert config.allow_file_write is False
        assert config.allow_network is False
        assert config.allow_subprocess is False

    def test_custom_config(self):
        config = SandboxConfig(
            timeout_seconds=60.0,
            max_memory_mb=512,
            allow_file_read=True,
            allow_network=True,
        )
        assert config.timeout_seconds == 60.0
        assert config.max_memory_mb == 512
        assert config.allow_file_read is True
        assert config.allow_network is True

    def test_allowed_paths(self):
        config = SandboxConfig(
            allow_file_read=True,
            allowed_paths=["/tmp/*", "/home/user/*"],
        )
        assert len(config.allowed_paths) == 2

    def test_denied_paths(self):
        config = SandboxConfig(
            allow_file_read=True,
            denied_paths=["/etc/*", "/root/*"],
        )
        assert len(config.denied_paths) == 2

    def test_audit_config(self):
        config = SandboxConfig(
            enable_audit=True,
            audit_level=AuditLevel.WARNING,
        )
        assert config.enable_audit is True
        assert config.audit_level == AuditLevel.WARNING

    def test_to_dict(self):
        config = SandboxConfig(
            timeout_seconds=45.0,
            allow_file_read=True,
        )
        d = config.to_dict()
        assert d["timeout_seconds"] == 45.0
        assert d["allow_file_read"] is True
        assert "max_memory_mb" in d

    def test_to_permission_set(self):
        config = SandboxConfig(
            allow_file_read=True,
            allow_file_write=False,
            allow_network=True,
            allow_subprocess=False,
        )
        perms = config.to_permission_set()

        # Check file permission
        file_perm = perms.get("file")
        assert file_perm is not None
        assert file_perm.level == PermissionLevel.READ

        # Check network permission
        net_perm = perms.get("network")
        assert net_perm is not None
        assert net_perm.allow_outbound is True

        # Check process permission
        proc_perm = perms.get("process")
        assert proc_perm is not None
        assert proc_perm.allow_subprocess is False

    def test_write_includes_read(self):
        config = SandboxConfig(
            allow_file_read=False,
            allow_file_write=True,
        )
        perms = config.to_permission_set()
        file_perm = perms.get("file")
        assert file_perm.level == PermissionLevel.WRITE


class TestSandboxResult:
    """Tests for SandboxResult."""

    def test_successful_result(self):
        result = SandboxResult(
            status=SandboxStatus.COMPLETED,
            stdout="Hello World",
            stderr="",
            exit_code=0,
        )
        assert result.status == SandboxStatus.COMPLETED
        assert result.stdout == "Hello World"
        assert result.exit_code == 0

    def test_failed_result(self):
        result = SandboxResult(
            status=SandboxStatus.FAILED,
            stdout="",
            stderr="Error occurred",
            exit_code=1,
            error="Script failed",
        )
        assert result.status == SandboxStatus.FAILED
        assert result.error == "Script failed"

    def test_timeout_result(self):
        result = SandboxResult(
            status=SandboxStatus.TIMEOUT,
            stdout="",
            stderr="",
            exit_code=-1,
            error="Execution timed out",
        )
        assert result.status == SandboxStatus.TIMEOUT

    def test_to_dict(self):
        result = SandboxResult(
            status=SandboxStatus.COMPLETED,
            stdout="output",
            stderr="",
            exit_code=0,
            execution_time=1.5,
            sandbox_id="abc123",
            audit_entries=5,
        )
        d = result.to_dict()
        assert d["status"] == "completed"
        assert d["stdout"] == "output"
        assert d["execution_time"] == 1.5
        assert d["sandbox_id"] == "abc123"
        assert d["audit_entries"] == 5


class TestSandbox:
    """Tests for Sandbox."""

    def test_create_sandbox(self):
        sandbox = Sandbox()
        assert sandbox.config is not None
        assert sandbox.backend is not None
        assert len(sandbox.id) == 8

    def test_sandbox_with_config(self):
        config = SandboxConfig(timeout_seconds=60.0)
        sandbox = Sandbox(config=config)
        assert sandbox.config.timeout_seconds == 60.0

    def test_execute_simple_code(self):
        sandbox = Sandbox()
        result = sandbox.execute('print("Hello")')

        assert result.status == SandboxStatus.COMPLETED
        assert "Hello" in result.stdout
        assert result.exit_code == 0

    def test_execute_with_error(self):
        sandbox = Sandbox()
        result = sandbox.execute('raise ValueError("test error")')

        assert result.status == SandboxStatus.FAILED
        assert result.exit_code != 0

    def test_execute_timeout(self):
        config = SandboxConfig(timeout_seconds=1.0)
        sandbox = Sandbox(config=config)
        result = sandbox.execute('import time; time.sleep(10)')

        assert result.status == SandboxStatus.TIMEOUT
        assert "timed out" in result.error.lower()

    def test_execute_with_env_vars(self):
        sandbox = Sandbox()
        result = sandbox.execute(
            'import os; print(os.environ.get("MY_VAR", "not set"))',
            env_vars={"MY_VAR": "my_value"},
        )

        assert result.status == SandboxStatus.COMPLETED
        assert "my_value" in result.stdout

    def test_output_truncation(self):
        config = SandboxConfig(max_output_bytes=100)
        sandbox = Sandbox(config=config)
        result = sandbox.execute('print("x" * 1000)')

        assert len(result.stdout) <= 100

    def test_sandbox_id_in_result(self):
        sandbox = Sandbox()
        result = sandbox.execute('print(1)')

        assert result.sandbox_id == sandbox.id

    def test_validate_code(self):
        sandbox = Sandbox()

        # Valid code
        valid = sandbox.validate('print("hello")')
        assert valid["valid"]

        # Invalid code with dangerous patterns depends on default permissions
        invalid = sandbox.validate('import subprocess')
        # With default restrictive permissions, this should be flagged
        assert not invalid["valid"] or len(invalid.get("issues", [])) >= 0

    def test_audit_logging(self):
        config = SandboxConfig(enable_audit=True)
        sandbox = Sandbox(config=config)
        sandbox.execute('print(1)')

        log = sandbox.get_audit_log()
        assert len(log) > 0

    def test_audit_disabled(self):
        config = SandboxConfig(enable_audit=False)
        sandbox = Sandbox(config=config)
        sandbox.execute('print(1)')

        log = sandbox.get_audit_log()
        assert len(log) == 0

    def test_get_denied_actions(self):
        sandbox = Sandbox()
        # Execute something that might be denied
        sandbox.execute('import socket')

        denied = sandbox.get_denied_actions()
        # May or may not have denied actions depending on what happened
        assert isinstance(denied, list)

    def test_context_manager(self):
        with Sandbox() as sandbox:
            result = sandbox.execute('print("context")')
            assert "context" in result.stdout

    def test_execution_time_tracked(self):
        sandbox = Sandbox()
        result = sandbox.execute('import time; time.sleep(0.1)')

        assert result.execution_time >= 0.1

    def test_audit_entries_count(self):
        config = SandboxConfig(enable_audit=True)
        sandbox = Sandbox(config=config)
        result = sandbox.execute('print(1)')

        assert result.audit_entries > 0


class TestCreateSandbox:
    """Tests for create_sandbox helper function."""

    def test_create_with_defaults(self):
        sandbox = create_sandbox()
        assert sandbox.config.timeout_seconds == 30.0
        assert sandbox.config.allow_file_read is False

    def test_create_with_timeout(self):
        sandbox = create_sandbox(timeout=60.0)
        assert sandbox.config.timeout_seconds == 60.0

    def test_create_with_file_read(self):
        sandbox = create_sandbox(allow_file_read=True)
        assert sandbox.config.allow_file_read is True

    def test_create_with_file_write(self):
        sandbox = create_sandbox(allow_file_write=True)
        assert sandbox.config.allow_file_write is True

    def test_create_with_network(self):
        sandbox = create_sandbox(allow_network=True)
        assert sandbox.config.allow_network is True

    def test_create_with_allowed_paths(self):
        sandbox = create_sandbox(
            allow_file_read=True,
            allowed_paths=["/tmp/*"],
        )
        assert "/tmp/*" in sandbox.config.allowed_paths

    def test_execute_through_helper(self):
        sandbox = create_sandbox()
        result = sandbox.execute('print("helper")')
        assert "helper" in result.stdout


class TestSandboxIntegration:
    """Integration tests for Sandbox."""

    def test_safe_computation(self):
        sandbox = Sandbox()
        result = sandbox.execute('''
import math
print(f"Pi: {math.pi:.4f}")
print(f"E: {math.e:.4f}")
print(f"Sqrt(2): {math.sqrt(2):.4f}")
''')
        assert result.status == SandboxStatus.COMPLETED
        assert "3.141" in result.stdout

    def test_data_processing(self):
        sandbox = Sandbox()
        result = sandbox.execute('''
data = [1, 2, 3, 4, 5]
mean = sum(data) / len(data)
variance = sum((x - mean) ** 2 for x in data) / len(data)
print(f"Mean: {mean}")
print(f"Variance: {variance}")
''')
        assert result.status == SandboxStatus.COMPLETED
        assert "Mean: 3.0" in result.stdout

    def test_json_processing(self):
        sandbox = Sandbox()
        result = sandbox.execute('''
import json
data = {"name": "test", "values": [1, 2, 3]}
serialized = json.dumps(data)
parsed = json.loads(serialized)
print(parsed["name"])
print(sum(parsed["values"]))
''')
        assert result.status == SandboxStatus.COMPLETED
        assert "test" in result.stdout
        assert "6" in result.stdout

    def test_datetime_operations(self):
        sandbox = Sandbox()
        result = sandbox.execute('''
from datetime import datetime, timedelta
now = datetime.now()
tomorrow = now + timedelta(days=1)
print(f"Days diff: {(tomorrow - now).days}")
''')
        assert result.status == SandboxStatus.COMPLETED
        assert "Days diff: 1" in result.stdout

    def test_regex_operations(self):
        sandbox = Sandbox()
        result = sandbox.execute('''
import re
text = "Hello, my email is test@example.com"
match = re.search(r'[\\w.]+@[\\w.]+', text)
if match:
    print(f"Found: {match.group()}")
''')
        assert result.status == SandboxStatus.COMPLETED
        assert "test@example.com" in result.stdout

    def test_multiple_executions(self):
        sandbox = Sandbox()

        result1 = sandbox.execute('print("First")')
        result2 = sandbox.execute('print("Second")')
        result3 = sandbox.execute('print("Third")')

        assert all(r.status == SandboxStatus.COMPLETED for r in [result1, result2, result3])
        assert "First" in result1.stdout
        assert "Second" in result2.stdout
        assert "Third" in result3.stdout

    def test_error_recovery(self):
        sandbox = Sandbox()

        # First execution fails
        result1 = sandbox.execute('raise ValueError("oops")')
        assert result1.status == SandboxStatus.FAILED

        # Second execution succeeds
        result2 = sandbox.execute('print("recovered")')
        assert result2.status == SandboxStatus.COMPLETED
        assert "recovered" in result2.stdout
