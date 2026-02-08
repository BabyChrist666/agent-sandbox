"""
Audit logging for sandbox execution.

Tracks all actions taken by sandboxed code for security review.
"""

import time
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Callable
from threading import Lock


class AuditLevel(Enum):
    """Audit log severity levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class AuditEntry:
    """A single audit log entry."""
    timestamp: float
    level: AuditLevel
    category: str
    action: str
    target: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    allowed: bool = True
    sandbox_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp).isoformat(),
            "level": self.level.value,
            "category": self.category,
            "action": self.action,
            "target": self.target,
            "details": self.details,
            "allowed": self.allowed,
            "sandbox_id": self.sandbox_id,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class AuditLog:
    """
    Audit log for tracking sandbox operations.

    Thread-safe logging of all actions with filtering and export capabilities.
    """

    def __init__(
        self,
        max_entries: int = 10000,
        on_entry: Optional[Callable[[AuditEntry], None]] = None,
    ):
        self.max_entries = max_entries
        self.on_entry = on_entry
        self._entries: List[AuditEntry] = []
        self._lock = Lock()

    def log(
        self,
        level: AuditLevel,
        category: str,
        action: str,
        target: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        allowed: bool = True,
        sandbox_id: Optional[str] = None,
    ) -> AuditEntry:
        """Log an audit entry."""
        entry = AuditEntry(
            timestamp=time.time(),
            level=level,
            category=category,
            action=action,
            target=target,
            details=details,
            allowed=allowed,
            sandbox_id=sandbox_id,
        )

        with self._lock:
            self._entries.append(entry)

            # Trim if over limit
            if len(self._entries) > self.max_entries:
                self._entries = self._entries[-self.max_entries:]

        # Callback
        if self.on_entry:
            try:
                self.on_entry(entry)
            except Exception:
                pass

        return entry

    def debug(self, category: str, action: str, **kwargs) -> AuditEntry:
        """Log debug level entry."""
        return self.log(AuditLevel.DEBUG, category, action, **kwargs)

    def info(self, category: str, action: str, **kwargs) -> AuditEntry:
        """Log info level entry."""
        return self.log(AuditLevel.INFO, category, action, **kwargs)

    def warning(self, category: str, action: str, **kwargs) -> AuditEntry:
        """Log warning level entry."""
        return self.log(AuditLevel.WARNING, category, action, **kwargs)

    def error(self, category: str, action: str, **kwargs) -> AuditEntry:
        """Log error level entry."""
        return self.log(AuditLevel.ERROR, category, action, **kwargs)

    def critical(self, category: str, action: str, **kwargs) -> AuditEntry:
        """Log critical level entry."""
        return self.log(AuditLevel.CRITICAL, category, action, **kwargs)

    def get_entries(
        self,
        level: Optional[AuditLevel] = None,
        category: Optional[str] = None,
        sandbox_id: Optional[str] = None,
        since: Optional[float] = None,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """Get filtered audit entries."""
        with self._lock:
            entries = list(self._entries)

        # Apply filters
        if level:
            entries = [e for e in entries if e.level == level]
        if category:
            entries = [e for e in entries if e.category == category]
        if sandbox_id:
            entries = [e for e in entries if e.sandbox_id == sandbox_id]
        if since:
            entries = [e for e in entries if e.timestamp >= since]

        # Return latest entries up to limit
        return entries[-limit:]

    def get_denied_actions(
        self,
        sandbox_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """Get entries where actions were denied."""
        with self._lock:
            entries = [e for e in self._entries if not e.allowed]

        if sandbox_id:
            entries = [e for e in entries if e.sandbox_id == sandbox_id]

        return entries[-limit:]

    def get_summary(self, sandbox_id: Optional[str] = None) -> dict:
        """Get summary statistics."""
        with self._lock:
            entries = list(self._entries)

        if sandbox_id:
            entries = [e for e in entries if e.sandbox_id == sandbox_id]

        total = len(entries)
        allowed = sum(1 for e in entries if e.allowed)
        denied = total - allowed

        by_category: Dict[str, int] = {}
        by_level: Dict[str, int] = {}

        for entry in entries:
            by_category[entry.category] = by_category.get(entry.category, 0) + 1
            by_level[entry.level.value] = by_level.get(entry.level.value, 0) + 1

        return {
            "total_entries": total,
            "allowed": allowed,
            "denied": denied,
            "by_category": by_category,
            "by_level": by_level,
        }

    def clear(self, sandbox_id: Optional[str] = None) -> int:
        """Clear entries. Returns count cleared."""
        with self._lock:
            if sandbox_id:
                original = len(self._entries)
                self._entries = [e for e in self._entries if e.sandbox_id != sandbox_id]
                return original - len(self._entries)
            else:
                count = len(self._entries)
                self._entries.clear()
                return count

    def export_json(
        self,
        sandbox_id: Optional[str] = None,
    ) -> str:
        """Export entries as JSON."""
        entries = self.get_entries(sandbox_id=sandbox_id, limit=self.max_entries)
        return json.dumps([e.to_dict() for e in entries], indent=2)

    def export_to_file(
        self,
        path: str,
        sandbox_id: Optional[str] = None,
    ) -> int:
        """Export entries to a file. Returns count exported."""
        entries = self.get_entries(sandbox_id=sandbox_id, limit=self.max_entries)

        with open(path, "w", encoding="utf-8") as f:
            for entry in entries:
                f.write(entry.to_json() + "\n")

        return len(entries)
