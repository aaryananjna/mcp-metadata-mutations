"""
Content-addressed storage for MCP Registry snapshots.

v2. The v1 schema stored one row per (snapshot, server, version), which grew by
~80k rows every single day and produced a 62MB binary that git had to re-store
in full on every commit. Over a 12 week study that is multiple gigabytes of
repo for data that barely changes. That was the wrong shape.

v2 stores STATE INTERVALS. One row per distinct observed state, with the first
and last snapshot it was seen in. A server record that never changes stays a
single row no matter how many days you observe it. The table grows with actual
change, not with calendar time, which is the thing being measured anyway.

Three layers, deliberately separated:

  data/objects/     Content-addressed blobs. The evidence. Append-only,
                    hash-named, verifiable by anyone without trusting you.
  data/snapshots/   Per-day delta manifests (what opened, what closed).
                    The durable record of the time series. Small.
  data/index.sqlite Derived query layer. GITIGNORED. Rebuildable at any time
                    from the two layers above via rebuild().

Never put the only copy of anything in the database.

Two hashes per record, still:
  content_hash  = sha256(canonical(record["server"]))
                  The part the registry claims is immutable. A change here
                  with a stable version string is a silent in-place edit.
  envelope_hash = sha256(canonical(whole record incl. _meta))
                  Also covers status and timestamps. A change here with a
                  stable content_hash is status churn, a completely different
                  event that one combined hash would have smeared together.
"""

import gzip
import hashlib
import json
import sqlite3
from pathlib import Path

OFFICIAL_META_KEY = "io.modelcontextprotocol.registry/official"


def canonical(obj) -> bytes:
    """Sorted keys, tight separators, UTF-8. JSON key order is not semantically
    meaningful and the API does not guarantee it, so hashing raw response bytes
    would produce a fleet-wide false positive the first time upstream reorders
    a field."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def state_row(rec: dict) -> dict:
    server = rec.get("server", {}) or {}
    meta = (rec.get("_meta") or {}).get(OFFICIAL_META_KEY, {}) or {}
    body = canonical(server)
    return {
        "server_name": server.get("name"),
        "version": server.get("version"),
        "content_hash": sha256_hex(body),
        "envelope_hash": sha256_hex(canonical(rec)),
        "status": meta.get("status"),
        "is_latest": 1 if meta.get("isLatest") else 0,
        "published_at": meta.get("publishedAt"),
        "updated_at": meta.get("updatedAt"),
        "status_changed_at": meta.get("statusChangedAt"),
        "schema_uri": server.get("$schema"),
        "_body": body,
    }


STATE_FIELDS = ["server_name", "version", "content_hash", "envelope_hash",
                "status", "is_latest", "published_at", "updated_at",
                "status_changed_at", "schema_uri"]


class Store:
    def __init__(self, root: str = "data"):
        self.root = Path(root)
        self.objects = self.root / "objects"
        self.snapshots = self.root / "snapshots"
        self.objects.mkdir(parents=True, exist_ok=True)
        self.snapshots.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.root / "index.sqlite")
        self.db.execute("PRAGMA journal_mode=WAL")
        self._migrate()
        self._snapshot = None
        self._prev = None
        self._opened = []
        self._seen_keys = set()

    def _migrate(self):
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS states (
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
                first_seen        TEXT NOT NULL,
                last_seen         TEXT NOT NULL,
                PRIMARY KEY (server_name, version, envelope_hash, first_seen)
            );
            CREATE INDEX IF NOT EXISTS idx_states_key
                ON states (server_name, version);
            CREATE INDEX IF NOT EXISTS idx_states_span
                ON states (last_seen, first_seen);

            CREATE TABLE IF NOT EXISTS blobs (
                content_hash TEXT PRIMARY KEY,
                first_seen   TEXT NOT NULL,
                n_bytes      INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS runs (
                snapshot    TEXT PRIMARY KEY,
                started_at  TEXT NOT NULL,
                finished_at TEXT,
                pages       INTEGER,
                records     INTEGER,
                new_blobs   INTEGER,
                opened      INTEGER,
                closed      INTEGER,
                ok          INTEGER NOT NULL DEFAULT 0,
                error       TEXT
            );

            CREATE TABLE IF NOT EXISTS incremental_reports (
                snapshot    TEXT NOT NULL,
                since       TEXT NOT NULL,
                server_name TEXT NOT NULL,
                version     TEXT NOT NULL,
                PRIMARY KEY (snapshot, server_name, version)
            );
        """)
        self.db.commit()

    # ---------- blobs ----------

    def _blob_path(self, h):
        return self.objects / h[:2] / h[2:4] / (h + ".json.gz")

    def put_blob(self, h, data, when):
        if self.db.execute("SELECT 1 FROM blobs WHERE content_hash=?", (h,)).fetchone():
            return False
        p = self._blob_path(h)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as f:
                f.write(data)
        self.db.execute(
            "INSERT INTO blobs (content_hash, first_seen, n_bytes) VALUES (?,?,?)",
            (h, when, len(data)))
        return True

    def get_blob(self, h):
        with gzip.open(self._blob_path(h), "rb") as f:
            return json.loads(f.read())

    def verify_blob(self, h):
        """Re-hash a stored blob. This is why content addressing is here: the
        published dataset is self-verifying by any third party."""
        return sha256_hex(canonical(self.get_blob(h))) == h

    # ---------- snapshot lifecycle ----------

    def prev_snapshot(self, before):
        row = self.db.execute(
            "SELECT snapshot FROM runs WHERE ok=1 AND snapshot<? "
            "ORDER BY snapshot DESC LIMIT 1", (before,)).fetchone()
        return row[0] if row else None

    def begin_snapshot(self, label, started_at):
        self._snapshot = label
        self._prev = self.prev_snapshot(label)
        self._opened, self._seen_keys = [], set()
        self.db.execute(
            "INSERT OR REPLACE INTO runs (snapshot, started_at, ok) VALUES (?,?,0)",
            (label, started_at))
        self.db.commit()

    def observe(self, rec, when):
        """Record one server record. Returns True if the blob was new.

        If this exact state was open in the previous snapshot, extend its
        interval. Otherwise open a new one. Opening a fresh interval when the
        previous snapshot did not contain the state keeps gaps honest: a record
        that disappears and comes back gets two intervals, not one long one
        that falsely implies continuous presence.
        """
        r = state_row(rec)
        body = r.pop("_body")
        key = (r["server_name"], r["version"], r["envelope_hash"])
        self._seen_keys.add(key)
        is_new_blob = self.put_blob(r["content_hash"], body, when)

        extended = False
        if self._prev:
            cur = self.db.execute(
                "UPDATE states SET last_seen=? WHERE server_name=? AND version=? "
                "AND envelope_hash=? AND last_seen=?",
                (self._snapshot, key[0], key[1], key[2], self._prev))
            extended = cur.rowcount > 0

        if not extended:
            self.db.execute(
                "INSERT OR IGNORE INTO states (" + ",".join(STATE_FIELDS) +
                ",first_seen,last_seen) VALUES (" +
                ",".join(["?"] * len(STATE_FIELDS)) + ",?,?)",
                [r[f] for f in STATE_FIELDS] + [self._snapshot, self._snapshot])
            self._opened.append(dict(r))

        return is_new_blob

    def end_snapshot(self, finished_at, pages, records, new_blobs,
                     ok=True, error=None):
        """Close intervals open yesterday and absent today, then write the delta
        manifest. The manifest is what makes the sqlite disposable."""
        closed = []
        if ok and self._prev:
            for k in self.db.execute(
                    "SELECT server_name, version, envelope_hash FROM states "
                    "WHERE last_seen=?", (self._prev,)).fetchall():
                if tuple(k) not in self._seen_keys:
                    closed.append(list(k))

        if ok:
            path = self.snapshots / (self._snapshot + ".json.gz")
            with open(path, "wb") as raw:
                with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as f:
                    f.write(canonical({
                        "snapshot": self._snapshot,
                        "prev": self._prev,
                        "opened": self._opened,
                        "closed": closed,
                    }))

        self.db.execute(
            "UPDATE runs SET finished_at=?, pages=?, records=?, new_blobs=?, "
            "opened=?, closed=?, ok=?, error=? WHERE snapshot=?",
            (finished_at, pages, records, new_blobs, len(self._opened),
             len(closed), 1 if ok else 0, error, self._snapshot))
        self.db.commit()
        return len(self._opened), len(closed)

    def log_incremental(self, label, since, records):
        """Incremental (updated_since) runs are logged here and deliberately kept
        OUT of the state machine. They return only a subset of the registry, so
        feeding them to the interval logic would look like every unreturned
        server had vanished."""
        for rec in records:
            s = rec.get("server", {}) or {}
            self.db.execute(
                "INSERT OR IGNORE INTO incremental_reports "
                "(snapshot, since, server_name, version) VALUES (?,?,?,?)",
                (label, since, s.get("name"), s.get("version")))
        self.db.commit()

    # ---------- queries ----------

    def states_at(self, label):
        self.db.row_factory = sqlite3.Row
        return self.db.execute(
            "SELECT * FROM states WHERE first_seen<=? AND last_seen>=? "
            "ORDER BY server_name, published_at, version", (label, label)).fetchall()

    def snapshots_list(self):
        return [r[0] for r in self.db.execute(
            "SELECT snapshot FROM runs WHERE ok=1 ORDER BY snapshot")]

    def commit(self):
        self.db.commit()


def rebuild(root="data"):
    """Reconstruct index.sqlite from the committed delta manifests.

    This is the whole reason the sqlite can be gitignored: it is derived data.
    The manifests plus the blobs are the dataset.
    """
    for suffix in ("", "-wal", "-shm"):
        q = Path(root) / ("index.sqlite" + suffix)
        if q.exists():
            q.unlink()

    store = Store(root)
    files = sorted((Path(root) / "snapshots").glob("*.json.gz"))
    open_states = {}

    for fp in files:
        with gzip.open(fp, "rb") as f:
            man = json.loads(f.read())
        snap = man["snapshot"]
        for c in man["closed"]:
            open_states.pop(tuple(c), None)
        for r in man["opened"]:
            key = (r["server_name"], r["version"], r["envelope_hash"])
            open_states[key] = snap
            store.db.execute(
                "INSERT OR IGNORE INTO states (" + ",".join(STATE_FIELDS) +
                ",first_seen,last_seen) VALUES (" +
                ",".join(["?"] * len(STATE_FIELDS)) + ",?,?)",
                [r[f] for f in STATE_FIELDS] + [snap, snap])
        for (n, v, e), fs in open_states.items():
            store.db.execute(
                "UPDATE states SET last_seen=? WHERE server_name=? AND version=? "
                "AND envelope_hash=? AND first_seen=?", (snap, n, v, e, fs))
        store.db.execute(
            "INSERT OR REPLACE INTO runs (snapshot, started_at, ok) VALUES (?,?,1)",
            (snap, "rebuilt"))
    store.commit()

    for bp in (Path(root) / "objects").rglob("*.json.gz"):
        h = bp.name[:-len(".json.gz")]
        store.db.execute(
            "INSERT OR IGNORE INTO blobs (content_hash, first_seen, n_bytes) "
            "VALUES (?,?,?)", (h, "rebuilt", bp.stat().st_size))
    store.commit()
    return len(files)


if __name__ == "__main__":
    import sys
    n = rebuild(sys.argv[1] if len(sys.argv) > 1 else "data")
    print("rebuilt index from " + str(n) + " snapshot manifests")