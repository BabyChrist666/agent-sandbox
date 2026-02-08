# Agent Sandbox

[![Tests](https://github.com/BabyChrist666/agent-sandbox/actions/workflows/tests.yml/badge.svg)](https://github.com/BabyChrist666/agent-sandbox/actions/workflows/tests.yml)
[![codecov](https://codecov.io/gh/BabyChrist666/agent-sandbox/branch/master/graph/badge.svg)](https://codecov.io/gh/BabyChrist666/agent-sandbox)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A secure code execution environment for AI agents. Provides isolated sandboxes with configurable permissions, audit logging, and multiple isolation backends.

## Features

- **Permission System**: Fine-grained control over file, network, and process access
- **Multiple Isolation Backends**: Process-based and container-based isolation
- **Audit Logging**: Track all actions with filtering and export capabilities
- **Pattern Detection**: Block dangerous code patterns before execution
- **Resource Limits**: Timeout, memory, and output size controls
- **Thread-Safe**: Safe for concurrent use in multi-agent scenarios

## Installation

```bash
pip install agent-sandbox
```

## Quick Start

```python
from agent_sandbox import Sandbox, create_sandbox

# Create a sandbox with default (restrictive) settings
sandbox = Sandbox()

# Execute code
result = sandbox.execute('print("Hello from sandbox!")')
print(result.stdout)  # Hello from sandbox!
print(result.status)  # SandboxStatus.COMPLETED

# Use helper function for common configurations
sandbox = create_sandbox(
    timeout=60.0,
    allow_file_read=True,
    allowed_paths=["/tmp/*"],
)
```

## Configuration

### SandboxConfig

```python
from agent_sandbox import Sandbox, SandboxConfig
from agent_sandbox.audit import AuditLevel

config = SandboxConfig(
    # Resource limits
    timeout_seconds=30.0,
    max_memory_mb=256,
    max_output_bytes=100000,

    # Permissions
    allow_file_read=False,
    allow_file_write=False,
    allow_network=False,
    allow_subprocess=False,

    # Path controls
    allowed_paths=["/tmp/*", "/home/user/data/*"],
    denied_paths=["/etc/*", "/root/*"],

    # Audit
    enable_audit=True,
    audit_level=AuditLevel.INFO,
)

sandbox = Sandbox(config=config)
```

### Permission System

```python
from agent_sandbox.permissions import (
    PermissionSet,
    PermissionLevel,
    FilePermission,
    NetworkPermission,
    ProcessPermission,
)

# Create custom permission set
permissions = PermissionSet()

# File permissions with glob patterns
permissions.add(FilePermission(
    level=PermissionLevel.READ,
    allowed_paths=["/data/*", "/config/*.json"],
    denied_paths=["/data/secrets/*"],
    allow_hidden=False,
))

# Network permissions with host/port control
permissions.add(NetworkPermission(
    allow_outbound=True,
    allow_inbound=False,
    allowed_hosts=["api.openai.com", "*.github.com"],
    denied_hosts=["*.malware.com"],
    allowed_ports=[80, 443],
    allow_localhost=True,
))

# Process permissions
permissions.add(ProcessPermission(
    allow_subprocess=True,
    allow_shell=False,
    allowed_commands=["python*", "pip", "git"],
    denied_commands=["rm", "dd", "mkfs*"],
    max_processes=5,
))
```

## Isolation Backends

### Process Isolation (Default)

Uses subprocess with environment isolation:

```python
from agent_sandbox.isolation import ProcessIsolation, IsolationConfig

backend = ProcessIsolation()
config = IsolationConfig(
    timeout_seconds=30.0,
    max_memory_mb=256,
    network_disabled=True,
    env_vars={"API_KEY": "secret"},
)

result = backend.execute(
    code='print("isolated")',
    language="python",
    config=config,
)
```

### Container Isolation

Uses Docker for stronger isolation:

```python
from agent_sandbox.isolation import ContainerIsolation

backend = ContainerIsolation(image="python:3.11-slim")

if backend.is_available():
    result = backend.execute(
        code='print("in container")',
        language="python",
        config=config,
    )
```

## Audit Logging

Track all sandbox operations:

```python
from agent_sandbox.audit import AuditLog, AuditLevel

# Create audit log with callback
def on_entry(entry):
    if not entry.allowed:
        print(f"DENIED: {entry.action} on {entry.target}")

audit = AuditLog(
    max_entries=10000,
    on_entry=on_entry,
)

# Get entries with filtering
entries = audit.get_entries(
    level=AuditLevel.WARNING,
    category="file",
    sandbox_id="abc123",
    limit=100,
)

# Get denied actions
denied = audit.get_denied_actions(sandbox_id="abc123")

# Get summary statistics
summary = audit.get_summary()
print(f"Total: {summary['total_entries']}")
print(f"Denied: {summary['denied']}")

# Export to file
audit.export_to_file("audit.jsonl")
```

## Code Executor

Lower-level API with more control:

```python
from agent_sandbox.executor import CodeExecutor, ExecutionContext

executor = CodeExecutor(
    permissions=permissions,
    backend=ProcessIsolation(),
    audit=audit,
)

# Validate code without executing
validation = executor.validate_code(
    'import socket; socket.connect(("evil.com", 80))',
    language="python",
)
print(validation["valid"])  # False
print(validation["issues"])  # [{"pattern": "socket", "reason": "..."}]

# Execute with context
context = ExecutionContext(
    id="task_123",
    language="python",
    timeout=60.0,
    max_memory_mb=512,
    env_vars={"DEBUG": "1"},
    metadata={"user": "agent_1"},
)

result = executor.execute('print("executed")', context)
```

## Pattern Detection

The sandbox blocks dangerous patterns before execution:

```python
# These patterns are blocked by default:
blocked_patterns = [
    "os.system",      # Shell execution
    "subprocess",     # Process spawning
    "__import__",     # Dynamic imports
    "eval(",          # Code evaluation
    "exec(",          # Code execution
    "compile(",       # Code compilation
    "open(",          # File access (when file perms disabled)
    "socket",         # Network access
    "requests",       # HTTP library
    "urllib",         # URL library
]
```

## Context Manager

Use sandbox as context manager:

```python
with Sandbox() as sandbox:
    result = sandbox.execute('print("managed")')
    print(result.stdout)
```

## Supported Languages

- Python / Python3
- JavaScript (Node.js)
- Ruby
- Bash / Shell

## Error Handling

```python
result = sandbox.execute('raise ValueError("oops")')

if result.status == SandboxStatus.FAILED:
    print(f"Error: {result.error}")
    print(f"Exit code: {result.exit_code}")
    print(f"Stderr: {result.stderr}")

elif result.status == SandboxStatus.TIMEOUT:
    print(f"Execution timed out after {result.execution_time}s")

elif result.status == SandboxStatus.COMPLETED:
    print(f"Success: {result.stdout}")
```

## Security Considerations

1. **Default Deny**: All permissions are denied by default
2. **Pattern Blocking**: Dangerous code patterns are blocked before execution
3. **Path Filtering**: Glob patterns for allowed/denied paths
4. **Network Control**: Fine-grained host and port restrictions
5. **Resource Limits**: Prevent resource exhaustion
6. **Audit Trail**: Complete logging of all operations

## API Reference

### Classes

- `Sandbox` - Main sandbox interface
- `SandboxConfig` - Configuration dataclass
- `SandboxResult` - Execution result
- `SandboxStatus` - Status enum (PENDING, RUNNING, COMPLETED, FAILED, TIMEOUT)
- `PermissionSet` - Collection of permissions
- `FilePermission` - File system permissions
- `NetworkPermission` - Network access permissions
- `ProcessPermission` - Process execution permissions
- `IsolationBackend` - Abstract base for isolation
- `ProcessIsolation` - Subprocess-based isolation
- `ContainerIsolation` - Docker-based isolation
- `CodeExecutor` - Low-level executor
- `ExecutionContext` - Execution configuration
- `ExecutionResult` - Execution outcome
- `AuditLog` - Audit logging
- `AuditEntry` - Single audit entry
- `AuditLevel` - Log severity levels

### Functions

- `create_sandbox()` - Helper to create configured sandbox

## License

MIT

