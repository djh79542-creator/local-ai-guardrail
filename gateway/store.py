"""影子 IT 审计：只落 SHA256 哈希与元数据，原文不出日志。"""
import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    user TEXT NOT NULL,
    action TEXT NOT NULL,
    verdict TEXT NOT NULL,
    block_reason TEXT,
    request_hash TEXT NOT NULL,
    masked_length INTEGER NOT NULL,
    dlp_findings TEXT NOT NULL,
    local_audit TEXT NOT NULL,
    remote_model TEXT,
    latency_ms INTEGER
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts);
"""


class AuditLog:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    @staticmethod
    def sha256(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def record(self, *, user: str, action: str, verdict: str, block_reason: str | None,
               masked_text: str, dlp_findings: list[dict], local_audit: dict,
               remote_model: str | None, latency_ms: int) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit_logs (ts, user, action, verdict, block_reason, request_hash,"
                " masked_length, dlp_findings, local_audit, remote_model, latency_ms)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    int(time.time()), user, action, verdict, block_reason, self.sha256(masked_text),
                    len(masked_text), json.dumps(dlp_findings, ensure_ascii=False),
                    json.dumps(local_audit, ensure_ascii=False), remote_model, latency_ms,
                ),
            )
            self._conn.commit()

    def recent(self, limit: int = 20) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        cols = [c[0] for c in self._conn.execute("SELECT * FROM audit_logs LIMIT 0").description]
        out = []
        for row in rows:
            d = dict(zip(cols, row))
            d["dlp_findings"] = json.loads(d["dlp_findings"])
            d["local_audit"] = json.loads(d["local_audit"])
            out.append(d)
        return out

    def stats(self) -> dict:
        total, blocked = self._conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(verdict='block'),0) FROM audit_logs"
        ).fetchone()
        return {"total": total, "blocked": blocked, "allowed": total - blocked}

    def close(self) -> None:
        self._conn.close()
