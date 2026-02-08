"""
Permission system for sandbox execution.

Provides fine-grained control over what actions sandboxed code can perform.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Set, Optional, Pattern
import re
import fnmatch


class PermissionLevel(Enum):
    """Permission strictness levels."""
    NONE = auto()      # No permissions
    READ = auto()      # Read-only access
    WRITE = auto()     # Read and write access
    EXECUTE = auto()   # Can execute
    FULL = auto()      # All permissions


class Permission(ABC):
    """Base class for permissions."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Permission name."""
        pass

    @abstractmethod
    def allows(self, action: str, target: str) -> bool:
        """
        Check if this permission allows an action on a target.

        Args:
            action: The action being performed (read, write, execute, etc.)
            target: The target of the action (file path, URL, etc.)

        Returns:
            True if the action is allowed
        """
        pass

    @abstractmethod
    def to_dict(self) -> dict:
        """Serialize the permission."""
        pass


@dataclass
class FilePermission(Permission):
    """File system permission."""
    allowed_paths: List[str] = field(default_factory=list)
    denied_paths: List[str] = field(default_factory=list)
    level: PermissionLevel = PermissionLevel.READ
    allow_hidden: bool = False

    @property
    def name(self) -> str:
        return "file"

    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """Check if path matches a glob pattern."""
        return fnmatch.fnmatch(path, pattern)

    def allows(self, action: str, target: str) -> bool:
        # Check denied paths first
        for pattern in self.denied_paths:
            if self._matches_pattern(target, pattern):
                return False

        # Check if hidden files are blocked
        if not self.allow_hidden:
            parts = target.replace("\\", "/").split("/")
            for part in parts:
                if part.startswith(".") and part not in [".", ".."]:
                    return False

        # Check allowed paths
        if self.allowed_paths:
            matched = False
            for pattern in self.allowed_paths:
                if self._matches_pattern(target, pattern):
                    matched = True
                    break
            if not matched:
                return False

        # Check action against level
        action = action.lower()
        if action == "read":
            return self.level in [PermissionLevel.READ, PermissionLevel.WRITE, PermissionLevel.FULL]
        elif action == "write":
            return self.level in [PermissionLevel.WRITE, PermissionLevel.FULL]
        elif action == "execute":
            return self.level in [PermissionLevel.EXECUTE, PermissionLevel.FULL]
        elif action == "delete":
            return self.level == PermissionLevel.FULL

        return False

    def to_dict(self) -> dict:
        return {
            "type": "file",
            "allowed_paths": self.allowed_paths,
            "denied_paths": self.denied_paths,
            "level": self.level.name,
            "allow_hidden": self.allow_hidden,
        }


@dataclass
class NetworkPermission(Permission):
    """Network access permission."""
    allowed_hosts: List[str] = field(default_factory=list)
    denied_hosts: List[str] = field(default_factory=list)
    allowed_ports: List[int] = field(default_factory=list)
    allow_localhost: bool = True
    allow_outbound: bool = False
    allow_inbound: bool = False

    @property
    def name(self) -> str:
        return "network"

    def allows(self, action: str, target: str) -> bool:
        # Parse target as host:port
        host = target
        port = None
        if ":" in target:
            parts = target.rsplit(":", 1)
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass

        # Check localhost
        if host in ["localhost", "127.0.0.1", "::1"]:
            if not self.allow_localhost:
                return False

        # Check denied hosts
        for pattern in self.denied_hosts:
            if fnmatch.fnmatch(host, pattern):
                return False

        # Check allowed hosts
        if self.allowed_hosts:
            matched = False
            for pattern in self.allowed_hosts:
                if fnmatch.fnmatch(host, pattern):
                    matched = True
                    break
            if not matched:
                return False

        # Check port restrictions
        if port is not None and self.allowed_ports:
            if port not in self.allowed_ports:
                return False

        # Check action
        action = action.lower()
        if action in ["connect", "send", "request"]:
            return self.allow_outbound
        elif action in ["listen", "accept", "bind"]:
            return self.allow_inbound

        return False

    def to_dict(self) -> dict:
        return {
            "type": "network",
            "allowed_hosts": self.allowed_hosts,
            "denied_hosts": self.denied_hosts,
            "allowed_ports": self.allowed_ports,
            "allow_localhost": self.allow_localhost,
            "allow_outbound": self.allow_outbound,
            "allow_inbound": self.allow_inbound,
        }


@dataclass
class ProcessPermission(Permission):
    """Process execution permission."""
    allowed_commands: List[str] = field(default_factory=list)
    denied_commands: List[str] = field(default_factory=list)
    max_processes: int = 1
    allow_shell: bool = False
    allow_subprocess: bool = False

    @property
    def name(self) -> str:
        return "process"

    def allows(self, action: str, target: str) -> bool:
        # Parse target as command
        command = target.split()[0] if target else ""

        # Check denied commands
        for pattern in self.denied_commands:
            if fnmatch.fnmatch(command, pattern):
                return False

        # Check shell access
        if command in ["sh", "bash", "zsh", "cmd", "powershell"]:
            if not self.allow_shell:
                return False

        # Check allowed commands
        if self.allowed_commands:
            matched = False
            for pattern in self.allowed_commands:
                if fnmatch.fnmatch(command, pattern):
                    matched = True
                    break
            if not matched:
                return False

        # Check action
        action = action.lower()
        if action in ["spawn", "exec", "fork"]:
            return self.allow_subprocess

        return True

    def to_dict(self) -> dict:
        return {
            "type": "process",
            "allowed_commands": self.allowed_commands,
            "denied_commands": self.denied_commands,
            "max_processes": self.max_processes,
            "allow_shell": self.allow_shell,
            "allow_subprocess": self.allow_subprocess,
        }


@dataclass
class PermissionSet:
    """Collection of permissions."""
    permissions: List[Permission] = field(default_factory=list)

    def add(self, permission: Permission) -> None:
        """Add a permission."""
        self.permissions.append(permission)

    def remove(self, name: str) -> bool:
        """Remove permissions by name."""
        original = len(self.permissions)
        self.permissions = [p for p in self.permissions if p.name != name]
        return len(self.permissions) < original

    def get(self, name: str) -> Optional[Permission]:
        """Get a permission by name."""
        for p in self.permissions:
            if p.name == name:
                return p
        return None

    def allows(self, permission_name: str, action: str, target: str) -> bool:
        """Check if an action is allowed on a target."""
        permission = self.get(permission_name)
        if permission is None:
            return False
        return permission.allows(action, target)

    def to_dict(self) -> dict:
        return {
            "permissions": [p.to_dict() for p in self.permissions],
        }

    @classmethod
    def default(cls) -> "PermissionSet":
        """Create a default restrictive permission set."""
        return cls(permissions=[
            FilePermission(level=PermissionLevel.NONE),
            NetworkPermission(allow_outbound=False, allow_inbound=False),
            ProcessPermission(allow_subprocess=False, allow_shell=False),
        ])

    @classmethod
    def permissive(cls) -> "PermissionSet":
        """Create a permissive permission set."""
        return cls(permissions=[
            FilePermission(level=PermissionLevel.FULL, allowed_paths=["*"]),
            NetworkPermission(allow_outbound=True, allow_inbound=True, allowed_hosts=["*"]),
            ProcessPermission(allow_subprocess=True, allow_shell=True, allowed_commands=["*"]),
        ])
