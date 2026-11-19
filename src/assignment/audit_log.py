"""
Assignment 11 — Audit Log.

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.

- ``request_id`` là trace ID nối input ↔ output.
- Thời điểm theo UTC (ISO 8601); latency đo bằng ``perf_counter``.
- Append-only: chỉ thêm bản ghi vào ``self.logs``, không sửa / xoá.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input + start timestamp keyed by request_id (fallback: user_id)."""
        key = request_id or user_id
        self._open[key] = {
            "request_id": request_id or uuid.uuid4().hex,
            "user_id": user_id,
            "input": text,
            "ts_start": utc_now_iso(),
            "_t0": time.perf_counter(),
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision, latency; append to self.logs."""
        entry = self._open.pop(request_id or user_id, None) or {
            "request_id": request_id or uuid.uuid4().hex,
            "user_id": user_id,
            "input": None,
            "ts_start": None,
            "_t0": None,
        }
        t0 = entry.pop("_t0")
        entry.update(
            {
                "output_preview": (text or "")[:300],
                "blocked": blocked,
                "layer": layer,
                "ts_end": utc_now_iso(),
                "latency_ms": (
                    round((time.perf_counter() - t0) * 1000, 1)
                    if t0 is not None
                    else None
                ),
            }
        )
        self.logs.append(entry)

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
