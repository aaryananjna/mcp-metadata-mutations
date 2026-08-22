"""
Content-addressed storage for MCP Registry snapshots.

Design notes (defend these in an interview):

* Two hashes per record, not one.
    - content_hash  = sha256(canonical(record["server"]))
      This is the part the registry claims is immutable. If it ever changes
      while the version string stays constant, that is a silent in-place edit,
      which is the single most interesting event this study can observe.
    - envelope_hash = sha256(canonical(whole record, incl. _meta))
      Changes here with a stable content_hash mean status/timestamp churn
      (active -> deprecated -> deleted, resurrection) with no content change.
  One combined hash would smear these two very different events together.

* Canonicalisation is sorted-keys, tight-separators, UTF-8, no NaN.
  JSON object key order is not semantically meaningful, and the API does not
  guarantee it. Hashing raw bytes would produce false-positive "changes" the
  first time the upstream serialiser reorders a field.

* Blobs live on disk, the index lives in SQLite. The blob store is the evidence
  (append-only, hash-named, independently verifiable by anyone who downloads
  the dataset). SQLite is a disposable query layer that can be rebuilt from
  blobs at any time. Never put the only copy of anything in the database.

* Blobs are stored once, globally, not once per snapshot. The registry is
  overwhelmingly append-only, so day N+1 re-stores almost nothing.
"""

import gzip
import hashlib
import json
import os
import sqlite3
from pathlib import Path

OFFICIAL_META_KEY = "io.modelcontextprotocol.registry/official"


def canonical(obj) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Store:
    def __init__(self, root: str = "data"):
        self.root = Path(root)
        self.objects = self.root / "objects"
        self.snapshots = self.root / "snapshots"
        self.objects.mkdir(parents=True, exist_ok=True)
        self.snapshots.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "index.sqlite"
        self.db = sqlite3.connect(self.db_path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self._migrate()

    def _migrate(self):
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS observations (
                snapshot_date     TEXT NOT NULL,
                observed_at       TEXT NOT NULL,
                server_name       TEXT NOT NULL,
                version           TEXT NOT NULL,
                content_hash      TEXT NOT NULL,
                envelope_hash     TEXT NOT NULL,
                status            TEXT,
                is_latest         INTEGER,
                published_at      TEXT,
                updated_at        TEXT,
                status_changed_at TEXT,
                schema_uri        TEXT,
                PRIMARY KEY (snapshot_date, server_name, version)
            );
            CREATE INDEX IF NOT EXISTS idx_obs_server
                ON observations (server_name, version, snapshot_date);
            CREATE INDEX IF NOT EXISTS idx_obs_content
                ON observations (content_hash);

            CREATE TABLE IF NOT EXISTS blobs (
                content_hash TEXT PRIMARY KEY,
                first_seen   TEXT NOT NULL,
                n_bytes      INTEGER NOT NULL
            );

            -- One row per collector run. If a run half-fails you must be able
            -- to tell "no servers changed" apart from "the collector broke",
            -- otherwise a gap in the series silently becomes a finding.
            CREATE TABLE IF NOT EXISTS runs (
                snapshot_date TEXT PRIMARY KEY,
                started_at    TEXT NOT NULL,
                finished_at   TEXT,
                pages         INTEGER,
                records       INTEGER,
                new_blobs     INTEGER,
                ok            INTEGER NOT NULL DEFAULT 0,
                error         TEXT
            );
            """
        )
        self.db.commit()

    # ---------- blob layer ----------

    def _blob_path(self, h: str) -> Path:
        return self.objects / h[:2] / h[2:4] / f"{h}.json.gz"

    def put_blob(self, h: str, data: bytes, observed_at: str) -> bool:
        """Returns True if this is a newly seen blob."""
        row = self.db.execute(
            "SELECT 1 FROM blobs WHERE content_hash=?", (h,)
        ).fetchone()
        if row:
            return False
        p = self._blob_path(h)
        p.parent.mkdir(parents=True, exist_ok=True)
        # mtime=0 so the gzip container is itself deterministic
        with gzip.GzipFile(filename="", mode="wb", fileobj=open(p, "wb"), mtime=0) as f:
            f.write(data)
        self.db.execute(
            "INSERT INTO blobs (content_hash, first_seen, n_bytes) VALUES (?,?,?)",
            (h, observed_at, len(data)),
        )
        return True

    def get_blob(self, h: str) -> dict:
        with gzip.open(self._blob_path(h), "rb") as f:
            return json.loads(f.read())

    def verify_blob(self, h: str) -> bool:
        """Re-hash a stored blob. This is why content addressing is here:
        the dataset is self-verifying by any third party."""
        return sha256_hex(canonical(self.get_blob(h))) == h

    # ---------- observation layer ----------

    def record_observation(self, snapshot_date: str, observed_at: str, rec: dict) -> bool:
        server = rec.get("server", {})
        meta = (rec.get("_meta") or {}).get(OFFICIAL_META_KEY, {}) or {}

        body = canonical(server)
        content_hash = sha256_hex(body)
        envelope_hash = sha256_hex(canonical(rec))

        is_new = self.put_blob(content_hash, body, observed_at)

        self.db.execute(
            """INSERT OR REPLACE INTO observations
               (snapshot_date, observed_at, server_name, version, content_hash,
                envelope_hash, status, is_latest, published_at, updated_at,
                status_changed_at, schema_uri)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                snapshot_date,
                observed_at,
                server.get("name"),
                server.get("version"),
                content_hash,
                envelope_hash,
                meta.get("status"),
                1 if meta.get("isLatest") else 0,
                meta.get("publishedAt"),
                meta.get("updatedAt"),
                meta.get("statusChangedAt"),
                server.get("$schema"),
            ),
        )
        return is_new

    # ---------- run bookkeeping ----------

    def start_run(self, snapshot_date: str, started_at: str):
        self.db.execute(
            "INSERT OR REPLACE INTO runs (snapshot_date, started_at, ok) VALUES (?,?,0)",
            (snapshot_date, started_at),
        )
        self.db.commit()

    def finish_run(self, snapshot_date, finished_at, pages, records, new_blobs,
                   ok=True, error=None):
        self.db.execute(
            """UPDATE runs SET finished_at=?, pages=?, records=?, new_blobs=?,
               ok=?, error=? WHERE snapshot_date=?""",
            (finished_at, pages, records, new_blobs, 1 if ok else 0, error, snapshot_date),
        )
        self.db.commit()

    def commit(self):
        self.db.commit()