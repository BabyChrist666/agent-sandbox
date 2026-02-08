"""
Demo: Agent Sandbox Usage Examples

This script demonstrates various sandbox configurations and usage patterns.
"""

import sys
sys.path.insert(0, '..')

from agent_sandbox import Sandbox, SandboxConfig, create_sandbox, SandboxStatus
from agent_sandbox.permissions import (
    PermissionSet, PermissionLevel,
    FilePermission, NetworkPermission, ProcessPermission
)
from agent_sandbox.isolation import ProcessIsolation, ContainerIsolation
from agent_sandbox.audit import AuditLog, AuditLevel


def demo_basic_usage():
    """Basic sandbox usage."""
    print("\n" + "="*60)
    print("Demo: Basic Sandbox Usage")
    print("="*60)

    # Create default sandbox
    sandbox = Sandbox()

    # Execute safe code
    result = sandbox.execute('print("Hello from sandbox!")')
    print(f"Status: {result.status.value}")
    print(f"Output: {result.stdout.strip()}")
    print(f"Execution time: {result.execution_time:.3f}s")

    # Execute computation
    result = sandbox.execute('''
import math
numbers = [1, 2, 3, 4, 5]
mean = sum(numbers) / len(numbers)
std = math.sqrt(sum((x - mean)**2 for x in numbers) / len(numbers))
print(f"Mean: {mean}, Std: {std:.4f}")
''')
    print(f"\nComputation output: {result.stdout.strip()}")


def demo_permission_blocking():
    """Demonstrate permission-based blocking."""
    print("\n" + "="*60)
    print("Demo: Permission Blocking")
    print("="*60)

    sandbox = Sandbox()

    # Try to use network (blocked)
    result = sandbox.execute('import socket; s = socket.socket()')
    print(f"\nNetwork access attempt:")
    print(f"Status: {result.status.value}")
    print(f"Error: {result.error}")
    if result.denied_actions:
        print(f"Denied patterns: {[d['pattern'] for d in result.denied_actions]}")

    # Try to spawn subprocess (blocked)
    result = sandbox.execute('import subprocess; subprocess.run(["ls"])')
    print(f"\nSubprocess attempt:")
    print(f"Status: {result.status.value}")
    print(f"Denied patterns: {[d['pattern'] for d in result.denied_actions]}")


def demo_code_validation():
    """Demonstrate code validation without execution."""
    print("\n" + "="*60)
    print("Demo: Code Validation")
    print("="*60)

    sandbox = Sandbox()

    # Validate safe code
    result = sandbox.validate('print("safe")')
    print(f"\nValidating 'print(\"safe\")':")
    print(f"Valid: {result['valid']}")

    # Validate dangerous code
    dangerous_codes = [
        'import subprocess',
        'eval("1+1")',
        '__import__("os").system("rm -rf /")',
        'import socket; socket.connect(("evil.com", 80))',
    ]

    for code in dangerous_codes:
        result = sandbox.validate(code)
        print(f"\nValidating '{code[:40]}...':")
        print(f"Valid: {result['valid']}")
        if not result['valid']:
            print(f"Issues: {[i['pattern'] for i in result['issues']]}")


def demo_custom_permissions():
    """Demonstrate custom permission configuration."""
    print("\n" + "="*60)
    print("Demo: Custom Permissions")
    print("="*60)

    # Create permissive sandbox
    config = SandboxConfig(
        timeout_seconds=10.0,
        allow_file_read=True,
        allow_file_write=False,
        allow_network=False,
        allowed_paths=["/tmp/*"],
    )
    sandbox = Sandbox(config=config)

    print(f"Config: file_read={config.allow_file_read}, file_write={config.allow_file_write}")
    print(f"Allowed paths: {config.allowed_paths}")

    # Test with allowed file access
    result = sandbox.execute('''
import tempfile
import os
# Can read temp files
temp_dir = tempfile.gettempdir()
print(f"Temp dir: {temp_dir}")
''')
    print(f"\nResult: {result.stdout.strip()}")


def demo_audit_logging():
    """Demonstrate audit logging."""
    print("\n" + "="*60)
    print("Demo: Audit Logging")
    print("="*60)

    # Create sandbox with audit
    config = SandboxConfig(enable_audit=True)
    sandbox = Sandbox(config=config)

    # Execute some operations
    sandbox.execute('print("operation 1")')
    sandbox.execute('print("operation 2")')
    sandbox.execute('import socket')  # This will be blocked

    # Get audit log
    log = sandbox.get_audit_log()
    print(f"\nAudit entries: {len(log)}")

    for entry in log[:5]:  # Show first 5 entries
        print(f"  [{entry['level']}] {entry['category']}/{entry['action']}")

    # Get denied actions
    denied = sandbox.get_denied_actions()
    print(f"\nDenied actions: {len(denied)}")
    for entry in denied:
        print(f"  {entry['action']}: {entry.get('details', {})}")


def demo_timeout_handling():
    """Demonstrate timeout handling."""
    print("\n" + "="*60)
    print("Demo: Timeout Handling")
    print("="*60)

    config = SandboxConfig(timeout_seconds=2.0)
    sandbox = Sandbox(config=config)

    print("Executing long-running code with 2s timeout...")
    result = sandbox.execute('import time; time.sleep(10); print("done")')

    print(f"Status: {result.status.value}")
    print(f"Error: {result.error}")
    print(f"Execution time: {result.execution_time:.3f}s")


def demo_error_handling():
    """Demonstrate error handling."""
    print("\n" + "="*60)
    print("Demo: Error Handling")
    print("="*60)

    sandbox = Sandbox()

    # Code with exception
    result = sandbox.execute('raise ValueError("Something went wrong!")')
    print(f"\nException handling:")
    print(f"Status: {result.status.value}")
    print(f"Exit code: {result.exit_code}")
    print(f"Stderr: {result.stderr[:100]}...")

    # Syntax error
    result = sandbox.execute('def foo( # syntax error')
    print(f"\nSyntax error:")
    print(f"Status: {result.status.value}")


def demo_helper_function():
    """Demonstrate create_sandbox helper."""
    print("\n" + "="*60)
    print("Demo: create_sandbox Helper")
    print("="*60)

    # Quick sandbox creation
    sandbox = create_sandbox(
        timeout=30.0,
        allow_file_read=True,
        allowed_paths=["/tmp/*", "/home/*"],
    )

    print(f"Created sandbox with ID: {sandbox.id}")
    print(f"Timeout: {sandbox.config.timeout_seconds}s")
    print(f"File read: {sandbox.config.allow_file_read}")

    result = sandbox.execute('print("Created with helper!")')
    print(f"Output: {result.stdout.strip()}")


def demo_context_manager():
    """Demonstrate context manager usage."""
    print("\n" + "="*60)
    print("Demo: Context Manager")
    print("="*60)

    with Sandbox() as sandbox:
        result = sandbox.execute('''
print("Inside context manager")
x = sum(range(100))
print(f"Sum of 0-99: {x}")
''')
        print(result.stdout)

    print("Context exited cleanly")


def main():
    """Run all demos."""
    print("\n" + "#"*60)
    print("# Agent Sandbox Demonstration")
    print("#"*60)

    demos = [
        demo_basic_usage,
        demo_permission_blocking,
        demo_code_validation,
        demo_custom_permissions,
        demo_audit_logging,
        demo_timeout_handling,
        demo_error_handling,
        demo_helper_function,
        demo_context_manager,
    ]

    for demo in demos:
        try:
            demo()
        except Exception as e:
            print(f"\nError in {demo.__name__}: {e}")

    print("\n" + "#"*60)
    print("# Demonstration Complete")
    print("#"*60)


if __name__ == "__main__":
    main()
