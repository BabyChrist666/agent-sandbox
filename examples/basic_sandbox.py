#!/usr/bin/env python3
"""
Agent Sandbox - Basic Usage Example

This example demonstrates secure code execution with
permission controls and safety checks.
"""

from agent_sandbox import (
    Sandbox,
    SandboxConfig,
    Permission,
    PermissionSet,
    ExecutionResult,
)


def main():
    print("=" * 60)
    print("Agent Sandbox - Basic Example")
    print("=" * 60)

    # Example 1: Basic safe execution
    print("\n1. Basic safe execution...")

    sandbox = Sandbox()

    code = """
result = sum(range(100))
print(f"Sum of 0-99: {result}")
"""

    result = sandbox.execute(code)
    print(f"   Success: {result.success}")
    print(f"   Output: {result.output}")

    # Example 2: Execution with permissions
    print("\n2. Execution with specific permissions...")

    permissions = PermissionSet([
        Permission.FILE_READ,
        Permission.NETWORK_NONE,
    ])

    config = SandboxConfig(
        permissions=permissions,
        timeout=5,
        max_memory_mb=100,
    )

    sandbox = Sandbox(config)

    code = """
# This is allowed (file read)
import os
files = os.listdir('.')
print(f"Files in current directory: {len(files)}")
"""

    result = sandbox.execute(code)
    print(f"   Success: {result.success}")
    print(f"   Output: {result.output}")

    # Example 3: Blocked dangerous operations
    print("\n3. Blocking dangerous operations...")

    dangerous_code = """
import os
os.system('rm -rf /')  # This should be blocked!
"""

    result = sandbox.execute(dangerous_code)
    print(f"   Blocked: {not result.success}")
    print(f"   Reason: {result.error}")

    # Example 4: Resource limits
    print("\n4. Resource limit enforcement...")

    config = SandboxConfig(
        timeout=2,  # 2 second timeout
        max_memory_mb=50,
    )
    sandbox = Sandbox(config)

    infinite_loop = """
while True:
    pass
"""

    result = sandbox.execute(infinite_loop)
    print(f"   Timed out: {result.timed_out}")
    print(f"   Execution time: {result.execution_time:.2f}s")

    # Example 5: Capturing return values
    print("\n5. Capturing return values...")

    code = """
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)

result = fibonacci(10)
"""

    result = sandbox.execute(code, capture_locals=True)
    print(f"   Success: {result.success}")
    print(f"   Captured 'result': {result.locals.get('result')}")

    # Example 6: Audit logging
    print("\n6. Audit logging...")

    config = SandboxConfig(
        enable_audit=True,
        log_level="INFO",
    )
    sandbox = Sandbox(config)

    code = """
x = 10
y = 20
z = x + y
print(f"Result: {z}")
"""

    result = sandbox.execute(code)
    print(f"   Audit log entries: {len(result.audit_log)}")
    for entry in result.audit_log[:3]:
        print(f"   - {entry}")

    print("\n" + "=" * 60)
    print("Example complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
