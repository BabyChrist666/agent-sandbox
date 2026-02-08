"""Tests for permission system."""

import pytest
from agent_sandbox.permissions import (
    Permission,
    PermissionLevel,
    FilePermission,
    NetworkPermission,
    ProcessPermission,
    PermissionSet,
)


class TestPermissionLevel:
    """Tests for PermissionLevel enum."""

    def test_permission_levels_exist(self):
        assert PermissionLevel.NONE
        assert PermissionLevel.READ
        assert PermissionLevel.WRITE
        assert PermissionLevel.EXECUTE
        assert PermissionLevel.FULL

    def test_levels_are_distinct(self):
        levels = [
            PermissionLevel.NONE,
            PermissionLevel.READ,
            PermissionLevel.WRITE,
            PermissionLevel.EXECUTE,
            PermissionLevel.FULL,
        ]
        assert len(set(levels)) == 5


class TestFilePermission:
    """Tests for FilePermission."""

    def test_file_permission_name(self):
        perm = FilePermission()
        assert perm.name == "file"

    def test_default_read_permission(self):
        perm = FilePermission(level=PermissionLevel.READ)
        assert perm.allows("read", "/some/file.txt")
        assert not perm.allows("write", "/some/file.txt")

    def test_write_includes_read(self):
        perm = FilePermission(level=PermissionLevel.WRITE)
        assert perm.allows("read", "/some/file.txt")
        assert perm.allows("write", "/some/file.txt")

    def test_none_denies_all(self):
        perm = FilePermission(level=PermissionLevel.NONE)
        assert not perm.allows("read", "/some/file.txt")
        assert not perm.allows("write", "/some/file.txt")

    def test_allowed_paths_pattern(self):
        perm = FilePermission(
            level=PermissionLevel.READ,
            allowed_paths=["/home/user/*", "/tmp/*"],
        )
        assert perm.allows("read", "/home/user/file.txt")
        assert perm.allows("read", "/tmp/data.json")
        assert not perm.allows("read", "/etc/passwd")

    def test_denied_paths_override(self):
        perm = FilePermission(
            level=PermissionLevel.FULL,
            allowed_paths=["*"],
            denied_paths=["/etc/*", "/root/*"],
        )
        assert perm.allows("read", "/home/user/file.txt")
        assert not perm.allows("read", "/etc/passwd")
        assert not perm.allows("read", "/root/.bashrc")

    def test_hidden_files_blocked(self):
        perm = FilePermission(
            level=PermissionLevel.READ,
            allow_hidden=False,
        )
        assert not perm.allows("read", "/home/user/.secret")
        assert not perm.allows("read", "/home/.config/file")

    def test_hidden_files_allowed(self):
        perm = FilePermission(
            level=PermissionLevel.READ,
            allow_hidden=True,
        )
        assert perm.allows("read", "/home/user/.secret")

    def test_delete_requires_full(self):
        perm = FilePermission(level=PermissionLevel.WRITE)
        assert not perm.allows("delete", "/some/file.txt")

        perm_full = FilePermission(level=PermissionLevel.FULL)
        assert perm_full.allows("delete", "/some/file.txt")

    def test_execute_permission(self):
        perm = FilePermission(level=PermissionLevel.EXECUTE)
        assert perm.allows("execute", "/usr/bin/python")
        assert not perm.allows("read", "/usr/bin/python")

    def test_to_dict(self):
        perm = FilePermission(
            level=PermissionLevel.READ,
            allowed_paths=["/tmp/*"],
            denied_paths=["/tmp/secret"],
            allow_hidden=True,
        )
        d = perm.to_dict()
        assert d["type"] == "file"
        assert d["level"] == "READ"
        assert d["allowed_paths"] == ["/tmp/*"]
        assert d["denied_paths"] == ["/tmp/secret"]
        assert d["allow_hidden"] is True


class TestNetworkPermission:
    """Tests for NetworkPermission."""

    def test_network_permission_name(self):
        perm = NetworkPermission()
        assert perm.name == "network"

    def test_default_denies_outbound(self):
        perm = NetworkPermission()
        assert not perm.allows("connect", "example.com:80")

    def test_allow_outbound(self):
        perm = NetworkPermission(allow_outbound=True, allowed_hosts=["*"])
        assert perm.allows("connect", "example.com:80")
        assert perm.allows("send", "api.github.com:443")

    def test_deny_inbound_by_default(self):
        perm = NetworkPermission(allow_outbound=True, allowed_hosts=["*"])
        assert not perm.allows("listen", "0.0.0.0:8080")
        assert not perm.allows("accept", "0.0.0.0:8080")

    def test_allow_inbound(self):
        perm = NetworkPermission(allow_inbound=True, allowed_hosts=["*"])
        assert perm.allows("listen", "0.0.0.0:8080")
        assert perm.allows("bind", "0.0.0.0:8080")

    def test_localhost_control(self):
        perm = NetworkPermission(
            allow_outbound=True,
            allow_localhost=False,
            allowed_hosts=["*"],
        )
        assert not perm.allows("connect", "localhost:8080")
        assert not perm.allows("connect", "127.0.0.1:8080")
        assert perm.allows("connect", "example.com:80")

    def test_host_patterns(self):
        perm = NetworkPermission(
            allow_outbound=True,
            allowed_hosts=["*.github.com", "api.openai.com"],
        )
        assert perm.allows("connect", "api.github.com:443")
        assert perm.allows("connect", "raw.github.com:443")
        assert perm.allows("connect", "api.openai.com:443")
        assert not perm.allows("connect", "evil.com:80")

    def test_denied_hosts(self):
        perm = NetworkPermission(
            allow_outbound=True,
            allowed_hosts=["*"],
            denied_hosts=["*.malware.com", "evil.org"],
        )
        assert perm.allows("connect", "github.com:443")
        assert not perm.allows("connect", "download.malware.com:80")
        assert not perm.allows("connect", "evil.org:80")

    def test_port_restrictions(self):
        perm = NetworkPermission(
            allow_outbound=True,
            allowed_hosts=["*"],
            allowed_ports=[80, 443],
        )
        assert perm.allows("connect", "example.com:80")
        assert perm.allows("connect", "example.com:443")
        assert not perm.allows("connect", "example.com:22")

    def test_to_dict(self):
        perm = NetworkPermission(
            allow_outbound=True,
            allow_inbound=False,
            allowed_hosts=["*.example.com"],
            allowed_ports=[443],
        )
        d = perm.to_dict()
        assert d["type"] == "network"
        assert d["allow_outbound"] is True
        assert d["allow_inbound"] is False
        assert d["allowed_hosts"] == ["*.example.com"]
        assert d["allowed_ports"] == [443]


class TestProcessPermission:
    """Tests for ProcessPermission."""

    def test_process_permission_name(self):
        perm = ProcessPermission()
        assert perm.name == "process"

    def test_default_denies_subprocess(self):
        perm = ProcessPermission()
        assert not perm.allows("spawn", "python")
        assert not perm.allows("exec", "ls")

    def test_allow_subprocess(self):
        perm = ProcessPermission(allow_subprocess=True, allowed_commands=["*"])
        assert perm.allows("spawn", "python script.py")
        assert perm.allows("exec", "ls -la")

    def test_deny_shell_by_default(self):
        perm = ProcessPermission(allow_subprocess=True, allowed_commands=["*"])
        assert not perm.allows("spawn", "bash -c 'echo hi'")
        assert not perm.allows("exec", "sh")

    def test_allow_shell(self):
        perm = ProcessPermission(
            allow_subprocess=True,
            allow_shell=True,
            allowed_commands=["*"],
        )
        assert perm.allows("spawn", "bash -c 'echo hi'")
        assert perm.allows("exec", "sh script.sh")

    def test_command_patterns(self):
        perm = ProcessPermission(
            allow_subprocess=True,
            allowed_commands=["python*", "pip", "git"],
        )
        assert perm.allows("spawn", "python3 script.py")
        assert perm.allows("exec", "pip install package")
        assert perm.allows("spawn", "git status")
        assert not perm.allows("spawn", "rm -rf /")

    def test_denied_commands(self):
        perm = ProcessPermission(
            allow_subprocess=True,
            allowed_commands=["*"],
            denied_commands=["rm", "dd", "mkfs*"],
        )
        assert perm.allows("spawn", "ls -la")
        assert not perm.allows("spawn", "rm -rf /")
        assert not perm.allows("exec", "dd if=/dev/zero")
        assert not perm.allows("spawn", "mkfs.ext4 /dev/sda")

    def test_to_dict(self):
        perm = ProcessPermission(
            allow_subprocess=True,
            allow_shell=False,
            allowed_commands=["python", "pip"],
            max_processes=5,
        )
        d = perm.to_dict()
        assert d["type"] == "process"
        assert d["allow_subprocess"] is True
        assert d["allow_shell"] is False
        assert d["allowed_commands"] == ["python", "pip"]
        assert d["max_processes"] == 5


class TestPermissionSet:
    """Tests for PermissionSet."""

    def test_add_permission(self):
        ps = PermissionSet()
        ps.add(FilePermission())
        assert len(ps.permissions) == 1

    def test_get_permission(self):
        ps = PermissionSet()
        ps.add(FilePermission(level=PermissionLevel.READ))
        ps.add(NetworkPermission(allow_outbound=True))

        fp = ps.get("file")
        assert fp is not None
        assert isinstance(fp, FilePermission)

        np = ps.get("network")
        assert np is not None
        assert isinstance(np, NetworkPermission)

        assert ps.get("nonexistent") is None

    def test_remove_permission(self):
        ps = PermissionSet()
        ps.add(FilePermission())
        ps.add(NetworkPermission())

        assert ps.remove("file")
        assert len(ps.permissions) == 1
        assert ps.get("file") is None

        assert not ps.remove("nonexistent")

    def test_allows_method(self):
        ps = PermissionSet()
        ps.add(FilePermission(level=PermissionLevel.READ))
        ps.add(NetworkPermission(allow_outbound=True, allowed_hosts=["*"]))

        assert ps.allows("file", "read", "/tmp/file.txt")
        assert not ps.allows("file", "write", "/tmp/file.txt")
        assert ps.allows("network", "connect", "example.com:80")
        assert not ps.allows("process", "spawn", "python")

    def test_default_permission_set(self):
        ps = PermissionSet.default()
        # Should be restrictive
        assert not ps.allows("file", "read", "/any/file")
        assert not ps.allows("network", "connect", "any.host:80")
        assert not ps.allows("process", "spawn", "any_command")

    def test_permissive_permission_set(self):
        ps = PermissionSet.permissive()
        # Should allow most things
        assert ps.allows("file", "read", "/any/file")
        assert ps.allows("file", "write", "/any/file")
        assert ps.allows("network", "connect", "any.host:80")
        assert ps.allows("process", "spawn", "any_command")

    def test_to_dict(self):
        ps = PermissionSet()
        ps.add(FilePermission(level=PermissionLevel.READ))
        ps.add(NetworkPermission())

        d = ps.to_dict()
        assert "permissions" in d
        assert len(d["permissions"]) == 2
