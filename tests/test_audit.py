"""Tests for audit logging."""

import pytest
import time
import json
import tempfile
import os
from agent_sandbox.audit import (
    AuditLevel,
    AuditEntry,
    AuditLog,
)


class TestAuditLevel:
    """Tests for AuditLevel enum."""

    def test_levels_exist(self):
        assert AuditLevel.DEBUG
        assert AuditLevel.INFO
        assert AuditLevel.WARNING
        assert AuditLevel.ERROR
        assert AuditLevel.CRITICAL

    def test_level_values(self):
        assert AuditLevel.DEBUG.value == "debug"
        assert AuditLevel.INFO.value == "info"
        assert AuditLevel.WARNING.value == "warning"
        assert AuditLevel.ERROR.value == "error"
        assert AuditLevel.CRITICAL.value == "critical"


class TestAuditEntry:
    """Tests for AuditEntry."""

    def test_create_entry(self):
        entry = AuditEntry(
            timestamp=time.time(),
            level=AuditLevel.INFO,
            category="execution",
            action="start",
        )
        assert entry.level == AuditLevel.INFO
        assert entry.category == "execution"
        assert entry.action == "start"

    def test_entry_with_target(self):
        entry = AuditEntry(
            timestamp=time.time(),
            level=AuditLevel.WARNING,
            category="file",
            action="read",
            target="/etc/passwd",
        )
        assert entry.target == "/etc/passwd"

    def test_entry_with_details(self):
        entry = AuditEntry(
            timestamp=time.time(),
            level=AuditLevel.ERROR,
            category="network",
            action="connect",
            details={"host": "evil.com", "port": 80},
        )
        assert entry.details["host"] == "evil.com"
        assert entry.details["port"] == 80

    def test_entry_allowed_flag(self):
        entry = AuditEntry(
            timestamp=time.time(),
            level=AuditLevel.WARNING,
            category="file",
            action="write",
            allowed=False,
        )
        assert entry.allowed is False

    def test_entry_sandbox_id(self):
        entry = AuditEntry(
            timestamp=time.time(),
            level=AuditLevel.INFO,
            category="execution",
            action="complete",
            sandbox_id="abc123",
        )
        assert entry.sandbox_id == "abc123"

    def test_to_dict(self):
        ts = time.time()
        entry = AuditEntry(
            timestamp=ts,
            level=AuditLevel.INFO,
            category="test",
            action="action",
            target="/path",
            details={"key": "value"},
            allowed=True,
            sandbox_id="xyz",
        )
        d = entry.to_dict()
        assert d["timestamp"] == ts
        assert d["level"] == "info"
        assert d["category"] == "test"
        assert d["action"] == "action"
        assert d["target"] == "/path"
        assert d["details"] == {"key": "value"}
        assert d["allowed"] is True
        assert d["sandbox_id"] == "xyz"
        assert "datetime" in d

    def test_to_json(self):
        entry = AuditEntry(
            timestamp=time.time(),
            level=AuditLevel.INFO,
            category="test",
            action="action",
        )
        j = entry.to_json()
        parsed = json.loads(j)
        assert parsed["level"] == "info"
        assert parsed["category"] == "test"


class TestAuditLog:
    """Tests for AuditLog."""

    def test_create_log(self):
        log = AuditLog()
        assert log.max_entries == 10000

    def test_custom_max_entries(self):
        log = AuditLog(max_entries=100)
        assert log.max_entries == 100

    def test_log_entry(self):
        log = AuditLog()
        entry = log.log(
            level=AuditLevel.INFO,
            category="test",
            action="action",
        )
        assert isinstance(entry, AuditEntry)
        assert entry.level == AuditLevel.INFO

    def test_log_levels_shortcuts(self):
        log = AuditLog()

        debug = log.debug("cat", "act")
        assert debug.level == AuditLevel.DEBUG

        info = log.info("cat", "act")
        assert info.level == AuditLevel.INFO

        warning = log.warning("cat", "act")
        assert warning.level == AuditLevel.WARNING

        error = log.error("cat", "act")
        assert error.level == AuditLevel.ERROR

        critical = log.critical("cat", "act")
        assert critical.level == AuditLevel.CRITICAL

    def test_get_entries(self):
        log = AuditLog()
        log.info("cat1", "action1")
        log.info("cat2", "action2")
        log.warning("cat1", "action3")

        entries = log.get_entries()
        assert len(entries) == 3

    def test_get_entries_by_level(self):
        log = AuditLog()
        log.info("cat", "action1")
        log.warning("cat", "action2")
        log.info("cat", "action3")

        entries = log.get_entries(level=AuditLevel.WARNING)
        assert len(entries) == 1
        assert entries[0].level == AuditLevel.WARNING

    def test_get_entries_by_category(self):
        log = AuditLog()
        log.info("file", "read")
        log.info("network", "connect")
        log.info("file", "write")

        entries = log.get_entries(category="file")
        assert len(entries) == 2

    def test_get_entries_by_sandbox_id(self):
        log = AuditLog()
        log.info("cat", "action1", sandbox_id="sandbox1")
        log.info("cat", "action2", sandbox_id="sandbox2")
        log.info("cat", "action3", sandbox_id="sandbox1")

        entries = log.get_entries(sandbox_id="sandbox1")
        assert len(entries) == 2

    def test_get_entries_since(self):
        log = AuditLog()
        log.info("cat", "old")

        cutoff = time.time()
        time.sleep(0.01)

        log.info("cat", "new")

        entries = log.get_entries(since=cutoff)
        assert len(entries) == 1
        assert entries[0].action == "new"

    def test_get_entries_limit(self):
        log = AuditLog()
        for i in range(10):
            log.info("cat", f"action{i}")

        entries = log.get_entries(limit=5)
        assert len(entries) == 5

    def test_get_denied_actions(self):
        log = AuditLog()
        log.info("cat", "allowed", allowed=True)
        log.warning("cat", "denied1", allowed=False)
        log.warning("cat", "denied2", allowed=False)

        denied = log.get_denied_actions()
        assert len(denied) == 2
        assert all(not e.allowed for e in denied)

    def test_get_denied_actions_by_sandbox(self):
        log = AuditLog()
        log.warning("cat", "denied1", allowed=False, sandbox_id="s1")
        log.warning("cat", "denied2", allowed=False, sandbox_id="s2")

        denied = log.get_denied_actions(sandbox_id="s1")
        assert len(denied) == 1

    def test_get_summary(self):
        log = AuditLog()
        log.info("file", "read")
        log.info("file", "write")
        log.warning("network", "blocked", allowed=False)

        summary = log.get_summary()
        assert summary["total_entries"] == 3
        assert summary["allowed"] == 2
        assert summary["denied"] == 1
        assert summary["by_category"]["file"] == 2
        assert summary["by_category"]["network"] == 1
        assert summary["by_level"]["info"] == 2
        assert summary["by_level"]["warning"] == 1

    def test_get_summary_by_sandbox(self):
        log = AuditLog()
        log.info("cat", "action", sandbox_id="s1")
        log.info("cat", "action", sandbox_id="s1")
        log.info("cat", "action", sandbox_id="s2")

        summary = log.get_summary(sandbox_id="s1")
        assert summary["total_entries"] == 2

    def test_clear_all(self):
        log = AuditLog()
        log.info("cat", "action1")
        log.info("cat", "action2")

        cleared = log.clear()
        assert cleared == 2
        assert len(log.get_entries()) == 0

    def test_clear_by_sandbox(self):
        log = AuditLog()
        log.info("cat", "action1", sandbox_id="s1")
        log.info("cat", "action2", sandbox_id="s2")

        cleared = log.clear(sandbox_id="s1")
        assert cleared == 1

        entries = log.get_entries()
        assert len(entries) == 1
        assert entries[0].sandbox_id == "s2"

    def test_max_entries_trimming(self):
        log = AuditLog(max_entries=5)

        for i in range(10):
            log.info("cat", f"action{i}")

        entries = log.get_entries(limit=100)
        assert len(entries) == 5
        # Should keep the latest entries
        assert entries[-1].action == "action9"

    def test_on_entry_callback(self):
        received = []
        def callback(entry):
            received.append(entry)

        log = AuditLog(on_entry=callback)
        log.info("cat", "action1")
        log.warning("cat", "action2")

        assert len(received) == 2
        assert received[0].level == AuditLevel.INFO
        assert received[1].level == AuditLevel.WARNING

    def test_callback_exception_handled(self):
        def bad_callback(entry):
            raise RuntimeError("Callback failed")

        log = AuditLog(on_entry=bad_callback)
        # Should not raise
        log.info("cat", "action")

        entries = log.get_entries()
        assert len(entries) == 1

    def test_export_json(self):
        log = AuditLog()
        log.info("cat", "action1")
        log.warning("cat", "action2")

        exported = log.export_json()
        parsed = json.loads(exported)
        assert len(parsed) == 2
        assert parsed[0]["action"] == "action1"

    def test_export_json_by_sandbox(self):
        log = AuditLog()
        log.info("cat", "action1", sandbox_id="s1")
        log.info("cat", "action2", sandbox_id="s2")

        exported = log.export_json(sandbox_id="s1")
        parsed = json.loads(exported)
        assert len(parsed) == 1

    def test_export_to_file(self):
        log = AuditLog()
        log.info("cat", "action1")
        log.info("cat", "action2")

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            path = f.name

        try:
            count = log.export_to_file(path)
            assert count == 2

            with open(path, 'r') as f:
                lines = f.readlines()

            assert len(lines) == 2
            parsed = json.loads(lines[0])
            assert "action" in parsed
        finally:
            os.unlink(path)

    def test_thread_safety(self):
        import threading

        log = AuditLog()
        errors = []

        def writer():
            try:
                for i in range(100):
                    log.info("cat", f"action{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        entries = log.get_entries(limit=1000)
        assert len(entries) == 500
