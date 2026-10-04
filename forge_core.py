from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import uuid


class ForgeError(Exception):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


_SENSITIVE = re.compile(
    r"password|passwd|passphrase|(?:^|[-_])pass(?:$|[-_])|token|secret|cookie|authorization|"
    r"api[-_]?key|credential|csrf|xsrf|session[-_]?id|email|username", re.I
)
_TEXT_SECRET = re.compile(
    r'(?i)(?<![\w.-])((?:["\']?[\w.-]*(?:password|passwd|token|secret|cookie|authorization|api[_-]?key|csrf|xsrf)[\w.-]*["\']?)'
    r'\s*[=:]\s*)(?:"[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;&<>\r\n]+)'
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")


def scrub_text(text, secrets=()):
    text = str(text)
    for secret in sorted({str(s) for s in secrets if s is not None and str(s)}, key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    text = _JWT.sub("[REDACTED]", text)
    text = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", text)
    return _TEXT_SECRET.sub(lambda m: m.group(1) + "[REDACTED]", text)


def redact_url(url, secrets=()):
    try:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https", "socks5", "socks5h"}:
            return scrub_text(url, secrets)
        netloc = parts.netloc
        if "@" in netloc:
            netloc = "[REDACTED]@" + netloc.rsplit("@", 1)[1]
        query = urlencode([(key, "[REDACTED]" if _SENSITIVE.search(key) else scrub_text(value, secrets))
                           for key, value in parse_qsl(parts.query, keep_blank_values=True)])
        return urlunsplit((parts.scheme, netloc, scrub_text(parts.path, secrets), query, ""))
    except ValueError:
        return "[INVALID URL REDACTED]"


def redact(value, secrets=()):
    if isinstance(value, dict):
        return {str(key): "[REDACTED]" if _SENSITIVE.search(str(key)) else
                redact_url(item, secrets) if str(key).lower() in {"url", "proxy", "final_url", "source_url", "from_url", "to_url"} and isinstance(item, str)
                else redact(item, secrets) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item, secrets) for item in value]
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except (ValueError, TypeError):
            return scrub_text(value, secrets)
        if isinstance(decoded, (dict, list)):
            return json.dumps(redact(decoded, secrets), ensure_ascii=False)
        return scrub_text(value, secrets)
    return value


class EvidenceStore:
    def __init__(self, root):
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise ForgeError(f"Project directory does not exist: {self.root}")
        self.directory = self.root / ".forge"
        self._inside(self.directory)
        self.directory.mkdir(exist_ok=True)
        database = self._inside(self.directory / "evidence.sqlite3")
        for suffix in ("-wal", "-shm"):
            self._inside(database.with_name(database.name + suffix))
        self.connection = sqlite3.connect(database, timeout=30)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("""CREATE TABLE IF NOT EXISTS evidence (
            id TEXT PRIMARY KEY, kind TEXT NOT NULL, created_at TEXT NOT NULL, data TEXT NOT NULL
        )""")
        self.connection.execute("CREATE INDEX IF NOT EXISTS evidence_kind_time ON evidence(kind, created_at)")
        self.connection.commit()

    def _inside(self, path):
        try:
            path.resolve().relative_to(self.root)
        except (ValueError, RuntimeError) as error:
            raise ForgeError("Evidence storage must remain inside the project directory") from error
        return path

    def close(self):
        self.connection.close()

    def add(self, kind, data):
        record = {"id": "ev_" + uuid.uuid4().hex, "kind": kind, "created_at": utc_now(), "data": redact(data)}
        with self.connection:
            self.connection.execute("INSERT INTO evidence VALUES (?, ?, ?, ?)",
                                    (record["id"], kind, record["created_at"], json.dumps(record["data"], ensure_ascii=False)))
        return record

    def get(self, evidence_id):
        row = self.connection.execute("SELECT id, kind, created_at, data FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if row is None:
            raise ForgeError(f"Unknown evidence ID: {evidence_id}")
        return {"id": row[0], "kind": row[1], "created_at": row[2], "data": json.loads(row[3])}

    def list(self, kind=None, limit=50):
        if not 1 <= limit <= 1000:
            raise ForgeError("Evidence limit must be between 1 and 1000")
        sql, params = "SELECT id, kind, created_at, data FROM evidence", []
        if kind:
            sql += " WHERE kind=?"
            params.append(kind)
        sql += " ORDER BY created_at DESC, rowid DESC LIMIT ?"
        params.append(limit)
        return [{"id": row[0], "kind": row[1], "created_at": row[2], "data": json.loads(row[3])}
                for row in self.connection.execute(sql, params)]

    def blob_path(self, sha256):
        if not re.fullmatch(r"[a-f0-9]{64}", sha256):
            raise ForgeError("Invalid SHA256")
        directory = self.directory / "blobs"
        self._inside(directory)
        directory.mkdir(exist_ok=True)
        return self._inside(directory / sha256)

    def put_bytes(self, data):
        sha256 = hashlib.sha256(data).hexdigest()
        destination = self.blob_path(sha256)
        if not destination.exists():
            fd, name = tempfile.mkstemp(prefix="incoming-", dir=destination.parent)
            try:
                with os.fdopen(fd, "wb") as output:
                    output.write(data)
                os.replace(name, destination)
            finally:
                Path(name).unlink(missing_ok=True)
        return {"sha256": sha256, "size": len(data), "path": destination.relative_to(self.root).as_posix()}


def load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as error:
        raise ForgeError(f"Cannot read JSON file {path}: {error}") from error
