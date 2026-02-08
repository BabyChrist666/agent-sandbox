"""Tests for code executor."""

import pytest
from agent_sandbox.executor import (
    ExecutionContext,
    ExecutionResult,
    CodeExecutor,
)
from agent_sandbox.permissions import (
    PermissionSet,
    PermissionLevel,
    FilePermission,
    NetworkPermission,
    ProcessPermission,
)
from agent_sandbox.isolation import ProcessIsolation, IsolationConfig
from agent_sandbox.audit import AuditLog, AuditLevel


class TestExecutionContext:
    """Tests for ExecutionContext."""

    def test_default_context(self):
        ctx = ExecutionContext()
        assert ctx.language == "python"
        assert ctx.timeout == 30.0
        assert ctx.max_memory_mb == 256
        assert len(ctx.id) == 8

    def test_custom_context(self):
        ctx = ExecutionContext(
            id="custom_id",
            language="javascript",
            timeout=60.0,
            max_memory_mb=512,
        )
        assert ctx.id == "custom_id"
        assert ctx.language == "javascript"
        assert ctx.timeout == 60.0
        assert ctx.max_memory_mb == 512

    def test_env_vars(self):
        ctx = ExecutionContext(env_vars={"API_KEY": "secret"})
        assert ctx.env_vars["API_KEY"] == "secret"

    def test_working_dir(self):
        ctx = ExecutionContext(working_dir="/tmp/sandbox")
        assert ctx.working_dir == "/tmp/sandbox"

    def test_metadata(self):
        ctx = ExecutionContext(metadata={"user": "test", "task": "example"})
        assert ctx.metadata["user"] == "test"

    def test_to_dict(self):
        ctx = ExecutionContext(
            id="test_id",
            language="python",
            timeout=45.0,
        )
        d = ctx.to_dict()
        assert d["id"] == "test_id"
        assert d["language"] == "python"
        assert d["timeout"] == 45.0


class TestExecutionResult:
    """Tests for ExecutionResult."""

    def test_successful_result(self):
        result = ExecutionResult(
            success=True,
            stdout="Hello World",
            stderr="",
            exit_code=0,
        )
        assert result.success
        assert result.stdout == "Hello World"
        assert result.exit_code == 0

    def test_failed_result(self):
        result = ExecutionResult(
            success=False,
            stdout="",
            stderr="Error",
            exit_code=1,
            error="Script failed",
        )
        assert not result.success
        assert result.error == "Script failed"

    def test_denied_actions(self):
        result = ExecutionResult(
            success=False,
            stdout="",
            stderr="",
            exit_code=-1,
            denied_actions=[
                {"pattern": "socket", "reason": "Network denied"},
            ],
        )
        assert len(result.denied_actions) == 1
        assert result.denied_actions[0]["pattern"] == "socket"

    def test_to_dict(self):
        result = ExecutionResult(
            success=True,
            stdout="output",
            stderr="",
            exit_code=0,
            execution_time=1.5,
            context_id="ctx123",
        )
        d = result.to_dict()
        assert d["success"] is True
        assert d["stdout"] == "output"
        assert d["execution_time"] == 1.5
        assert d["context_id"] == "ctx123"


class TestCodeExecutor:
    """Tests for CodeExecutor."""

    def test_create_executor(self):
        executor = CodeExecutor()
        assert executor.permissions is not None
        assert executor.backend is not None
        assert executor.audit is not None

    def test_custom_permissions(self):
        perms = PermissionSet()
        perms.add(FilePermission(level=PermissionLevel.READ))
        executor = CodeExecutor(permissions=perms)
        assert executor.permissions is perms

    def test_execute_simple_code(self):
        executor = CodeExecutor(
            permissions=PermissionSet.permissive(),
        )

        result = executor.execute('print("Hello")')
        assert result.success
        assert "Hello" in result.stdout

    def test_execute_with_context(self):
        executor = CodeExecutor(
            permissions=PermissionSet.permissive(),
        )
        ctx = ExecutionContext(
            id="test123",
            timeout=10.0,
        )

        result = executor.execute('print("test")', context=ctx)
        assert result.success
        assert result.context_id == "test123"

    def test_code_pattern_check_subprocess(self):
        perms = PermissionSet()
        perms.add(ProcessPermission(allow_subprocess=False))
        executor = CodeExecutor(permissions=perms)

        result = executor.execute('import subprocess; subprocess.run(["ls"])')
        assert not result.success
        assert "denied" in result.error.lower()
        assert any("subprocess" in d["pattern"] for d in result.denied_actions)

    def test_code_pattern_check_network(self):
        perms = PermissionSet()
        perms.add(NetworkPermission(allow_outbound=False))
        executor = CodeExecutor(permissions=perms)

        result = executor.execute('import socket; s = socket.socket()')
        assert not result.success
        assert any("socket" in d["pattern"] for d in result.denied_actions)

    def test_code_pattern_check_requests(self):
        perms = PermissionSet()
        perms.add(NetworkPermission(allow_outbound=False))
        executor = CodeExecutor(permissions=perms)

        result = executor.execute('import requests; requests.get("http://example.com")')
        assert not result.success
        assert any("requests" in d["pattern"] for d in result.denied_actions)

    def test_code_pattern_check_file(self):
        perms = PermissionSet()
        perms.add(FilePermission(level=PermissionLevel.NONE))
        executor = CodeExecutor(permissions=perms)

        result = executor.execute('f = open("/etc/passwd", "r")')
        assert not result.success
        assert any("open(" in d["pattern"] for d in result.denied_actions)

    def test_allowed_file_access(self):
        perms = PermissionSet()
        perms.add(FilePermission(level=PermissionLevel.READ, allowed_paths=["*"]))
        perms.add(NetworkPermission(allow_outbound=False))
        perms.add(ProcessPermission(allow_subprocess=False))
        executor = CodeExecutor(permissions=perms)

        # File open is allowed when permissions grant it
        result = executor.execute('print("test file access")')
        assert result.success

    def test_validate_code(self):
        perms = PermissionSet()
        perms.add(ProcessPermission(allow_subprocess=False))
        perms.add(NetworkPermission(allow_outbound=False))
        executor = CodeExecutor(permissions=perms)

        # Valid code
        valid = executor.validate_code('print("hello")')
        assert valid["valid"]
        assert len(valid["issues"]) == 0

        # Invalid code
        invalid = executor.validate_code('import subprocess')
        assert not invalid["valid"]
        assert len(invalid["issues"]) > 0

    def test_audit_logging(self):
        audit = AuditLog()
        executor = CodeExecutor(
            permissions=PermissionSet.permissive(),
            audit=audit,
        )

        executor.execute('print("logged")')

        entries = audit.get_entries()
        assert len(entries) >= 2  # start and complete
        assert any(e.action == "start" for e in entries)
        assert any(e.action == "complete" for e in entries)

    def test_audit_denied_patterns(self):
        audit = AuditLog()
        perms = PermissionSet()
        perms.add(NetworkPermission(allow_outbound=False))
        executor = CodeExecutor(permissions=perms, audit=audit)

        executor.execute('import socket')

        entries = audit.get_entries()
        assert any(e.action == "denied_patterns" for e in entries)

    def test_execution_time_tracking(self):
        executor = CodeExecutor(
            permissions=PermissionSet.permissive(),
        )

        result = executor.execute('import time; time.sleep(0.1)')
        assert result.execution_time >= 0.1

    def test_execution_error_handling(self):
        executor = CodeExecutor(
            permissions=PermissionSet.permissive(),
        )

        result = executor.execute('raise RuntimeError("test error")')
        assert not result.success
        assert result.exit_code != 0

    def test_get_audit_summary(self):
        audit = AuditLog()
        executor = CodeExecutor(
            permissions=PermissionSet.permissive(),
            audit=audit,
        )

        ctx = ExecutionContext(id="summary_test")
        executor.execute('print(1)', context=ctx)
        executor.execute('print(2)', context=ctx)

        summary = executor.get_audit_summary(context_id="summary_test")
        assert summary["total_entries"] >= 4  # 2 starts + 2 completes

    def test_os_system_blocked(self):
        perms = PermissionSet()
        perms.add(ProcessPermission(allow_subprocess=False))
        executor = CodeExecutor(permissions=perms)

        result = executor.execute('import os; os.system("ls")')
        assert not result.success
        assert any("os.system" in d["pattern"] for d in result.denied_actions)

    def test_eval_blocked(self):
        perms = PermissionSet()
        perms.add(ProcessPermission(allow_subprocess=False))
        executor = CodeExecutor(permissions=perms)

        result = executor.execute('eval("1+1")')
        assert not result.success
        assert any("eval(" in d["pattern"] for d in result.denied_actions)

    def test_exec_blocked(self):
        perms = PermissionSet()
        perms.add(ProcessPermission(allow_subprocess=False))
        executor = CodeExecutor(permissions=perms)

        result = executor.execute('exec("print(1)")')
        assert not result.success
        assert any("exec(" in d["pattern"] for d in result.denied_actions)

    def test_import_blocked(self):
        perms = PermissionSet()
        perms.add(ProcessPermission(allow_subprocess=False))
        executor = CodeExecutor(permissions=perms)

        result = executor.execute('__import__("os")')
        assert not result.success
        assert any("__import__" in d["pattern"] for d in result.denied_actions)


class TestCodeExecutorIntegration:
    """Integration tests for CodeExecutor."""

    def test_safe_math_execution(self):
        executor = CodeExecutor(
            permissions=PermissionSet.default(),
        )

        result = executor.execute('print(2 + 2)')
        assert result.success
        assert "4" in result.stdout

    def test_safe_string_manipulation(self):
        executor = CodeExecutor(
            permissions=PermissionSet.default(),
        )

        result = executor.execute('print("hello".upper())')
        assert result.success
        assert "HELLO" in result.stdout

    def test_list_comprehension(self):
        executor = CodeExecutor(
            permissions=PermissionSet.default(),
        )

        result = executor.execute('print([x**2 for x in range(5)])')
        assert result.success
        assert "[0, 1, 4, 9, 16]" in result.stdout

    def test_function_definition(self):
        executor = CodeExecutor(
            permissions=PermissionSet.default(),
        )

        code = '''
def greet(name):
    return f"Hello, {name}!"

print(greet("World"))
'''
        result = executor.execute(code)
        assert result.success
        assert "Hello, World!" in result.stdout

    def test_class_definition(self):
        executor = CodeExecutor(
            permissions=PermissionSet.default(),
        )

        code = '''
class Counter:
    def __init__(self):
        self.count = 0

    def increment(self):
        self.count += 1
        return self.count

c = Counter()
print(c.increment())
print(c.increment())
'''
        result = executor.execute(code)
        assert result.success
        assert "1" in result.stdout
        assert "2" in result.stdout
