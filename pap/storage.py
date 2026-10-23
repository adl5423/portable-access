"""Private, durable local authority state. SQL transactions serialize admission decisions."""

import json
import os
import sqlite3
import stat
import time
from contextlib import contextmanager
from pathlib import Path


def private_directory(path: Path):
    if path.is_symlink():
        raise ValueError("state directory cannot be a symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("state directory must be owned by this user with mode 0700")


class Store:
    def __init__(self, path: Path):
        private_directory(path.parent)
        if path.is_symlink():
            raise ValueError("state database cannot be a symlink")
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        info = os.fstat(fd)
        os.close(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("state database must be owned by this user with mode 0600")
        self.db = sqlite3.connect(path, isolation_level=None, timeout=3)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS workloads (
          id TEXT PRIMARY KEY, uid INTEGER UNIQUE NOT NULL, tenant TEXT NOT NULL,
          environment TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, epoch INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS grants (
          id TEXT PRIMARY KEY, workload TEXT NOT NULL REFERENCES workloads(id),
          actions TEXT NOT NULL, expires REAL NOT NULL, enabled INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS signing_keys (
          kid TEXT PRIMARY KEY, private TEXT, public TEXT NOT NULL, state TEXT NOT NULL,
          created REAL NOT NULL, retire REAL, last_exp REAL NOT NULL DEFAULT 0);
        CREATE UNIQUE INDEX IF NOT EXISTS one_active_key ON signing_keys(state) WHERE state='active';
        CREATE TABLE IF NOT EXISTS nonces (
          digest TEXT PRIMARY KEY, jkt TEXT NOT NULL, subject TEXT NOT NULL, kind TEXT NOT NULL, expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS proofs (
          jkt TEXT NOT NULL, jti TEXT NOT NULL, expires REAL NOT NULL, PRIMARY KEY(jkt,jti));
        CREATE TABLE IF NOT EXISTS buckets (
          subject TEXT NOT NULL, bucket INTEGER NOT NULL, used INTEGER NOT NULL, PRIMARY KEY(subject,bucket));
        CREATE TABLE IF NOT EXISTS notes (
          id TEXT PRIMARY KEY, tenant TEXT NOT NULL, subject TEXT NOT NULL, message TEXT NOT NULL, created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS operations (
          subject TEXT NOT NULL, tenant TEXT NOT NULL, operation_key TEXT NOT NULL, digest TEXT NOT NULL,
          response TEXT NOT NULL, PRIMARY KEY(subject,tenant,operation_key));
        CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, digest TEXT NOT NULL, response TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit (
          seq INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, event TEXT NOT NULL, details TEXT NOT NULL);
        """)
        if "provider_ref" not in {r[1] for r in self.db.execute("PRAGMA table_info(signing_keys)")}:
            self.db.execute("ALTER TABLE signing_keys ADD COLUMN provider_ref TEXT")

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield self.db
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        else:
            self.db.execute("COMMIT")

    def audit(self, event: str, details: dict):
        # Call sites pass only allowlisted metadata, never headers, bodies, tokens or keys.
        self.db.execute(
            "INSERT INTO audit(at,event,details) VALUES (?,?,?)",
            (time.time(), event, json.dumps(details, sort_keys=True)),
        )

    def setting(self, name: str, default=None):
        row = self.db.execute("SELECT value FROM settings WHERE name=?", (name,)).fetchone()
        return default if row is None else json.loads(row[0])

    def set_setting(self, name: str, value):
        self.db.execute(
            "INSERT INTO settings VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",
            (name, json.dumps(value)),
        )

    def close(self):
        self.db.close()
