"""
SQLite-backed storage for KRISIS institutional memory (see PATTERN INTELLIGENCE
and CASE MEMORY in the design doc).

Three tables:
  - cases:      one row per investigation, full case JSON + summary columns for querying
  - indicators: every entity ever observed, tagged with which case it came from and
                that case's outcome — this is "indicator memory" and the substrate
                the pattern matcher uses for historical similarity
  - patterns:   named higher-level patterns with a strength counter that the
                learning loop increments/decrements as outcomes come in

SQLite (not a graph DB, not a vector DB) is a deliberate hackathon-scale choice:
it is inspectable with any SQLite browser, requires no server, and is sufficient
for structured indicator/case matching (see PATTERN SIMILARITY in the design doc,
which explicitly says not to force a vector database).
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from typing import Any, Iterator, Optional

DEFAULT_DB_PATH = os.path.join("krisis_data", "krisis.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    seed TEXT NOT NULL,
    seed_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    risk_score INTEGER,
    risk_category TEXT,
    confidence REAL,
    outcome TEXT,
    data_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    value TEXT NOT NULL,
    seed TEXT NOT NULL,
    outcome TEXT,
    risk_category TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id)
);
CREATE INDEX IF NOT EXISTS idx_indicators_lookup ON indicators (entity_type, value);

CREATE TABLE IF NOT EXISTS patterns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    signature_json TEXT,
    observed_count INTEGER DEFAULT 0,
    confirmed_count INTEGER DEFAULT 0,
    false_positive_count INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Which cases exhibited which pattern signature. When a case outcome is later
-- validated, this is the link the learning loop walks to credit or discredit
-- the patterns that case actually displayed.
CREATE TABLE IF NOT EXISTS case_patterns (
    case_id TEXT NOT NULL,
    pattern_id TEXT NOT NULL,
    PRIMARY KEY (case_id, pattern_id)
);

-- Provider responses, so re-asking a provider the same question inside its cache
-- window costs nothing. fetched_at is kept because a cached answer must be
-- reported as an observation from that moment, never as current intelligence.
CREATE TABLE IF NOT EXISTS provider_cache (
    provider TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    value TEXT NOT NULL,
    fetched_at REAL NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (provider, entity_type, value)
);

-- Every request actually spent, and every rate-limit response received. One
-- append-only log answers all three budget questions by time window: requests in
-- the last minute, requests today, and when the provider last pushed back.
CREATE TABLE IF NOT EXISTS provider_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    ts REAL NOT NULL,
    kind TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_provider_events ON provider_events (provider, kind, ts);
"""

# Columns added after the first release. SQLite has no "ADD COLUMN IF NOT EXISTS",
# so missing ones are added on open — existing local databases keep working.
_MIGRATIONS = [("patterns", "observed_count", "INTEGER DEFAULT 0")]


class Storage:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        directory = os.path.dirname(db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            for table, column, decl in _MIGRATIONS:
                existing = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
                if column not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

    # -- cases ------------------------------------------------------------

    def save_case(self, case_dict: dict[str, Any]) -> None:
        risk = case_dict.get("risk") or {}
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO cases
                   (id, seed, seed_type, created_at, risk_score, risk_category, confidence, outcome, data_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    case_dict["id"],
                    case_dict["seed"],
                    case_dict["seed_type"],
                    case_dict["created_at"],
                    risk.get("score"),
                    risk.get("category"),
                    risk.get("confidence"),
                    case_dict.get("outcome"),
                    json.dumps(case_dict),
                ),
            )

    def get_case(self, case_id: str) -> Optional[dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT data_json FROM cases WHERE id = ?", (case_id,)).fetchone()
        return json.loads(row["data_json"]) if row else None

    def list_cases(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, seed, seed_type, created_at, risk_score, risk_category, confidence, outcome "
                "FROM cases ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def set_outcome(self, case_id: str, outcome: str) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE cases SET outcome = ? WHERE id = ?", (outcome, case_id))
            # The full case JSON is the record of truth an analyst reads back later;
            # leaving its outcome stale while the summary column says otherwise would
            # make the stored case disagree with itself.
            row = conn.execute("SELECT data_json FROM cases WHERE id = ?", (case_id,)).fetchone()
            if row:
                data = json.loads(row["data_json"])
                data["outcome"] = outcome
                conn.execute(
                    "UPDATE cases SET data_json = ? WHERE id = ?", (json.dumps(data), case_id)
                )
            # keep indicators in sync so future matching reflects the confirmed outcome
            conn.execute("UPDATE indicators SET outcome = ? WHERE case_id = ?", (outcome, case_id))

    # -- indicators ---------------------------------------------------------

    def record_indicator(
        self, case_id: str, entity_type: str, value: str, seed: str,
        outcome: Optional[str], risk_category: Optional[str], created_at: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO indicators (case_id, entity_type, value, seed, outcome, risk_category, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (case_id, entity_type, value.lower(), seed, outcome, risk_category, created_at),
            )

    def count_cases_for_indicator(self, entity_type: str, value: str) -> int:
        """How many distinct seed artifacts have ever produced this indicator.

        Counting distinct *seeds* rather than cases keeps repeated investigations of
        one artifact from inflating the number and making its own infrastructure look
        like a commodity service.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(DISTINCT seed) AS n FROM indicators WHERE entity_type = ? AND value = ?",
                (entity_type, value.lower()),
            ).fetchone()
        return row["n"] if row else 0

    def find_indicator_matches(
        self, entity_type: str, value: str, exclude_seed: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """Prior cases that observed this exact indicator.

        exclude_seed drops cases seeded on the same artifact: re-investigating one
        domain would otherwise "match" its own earlier run and be reported as an
        infrastructure resemblance to a different case.
        """
        sql = (
            "SELECT DISTINCT case_id, seed, outcome, risk_category FROM indicators "
            "WHERE entity_type = ? AND value = ?"
        )
        params: list[Any] = [entity_type, value.lower()]
        if exclude_seed:
            sql += " AND seed <> ?"
            params.append(exclude_seed)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # -- patterns -------------------------------------------------------------

    def observe_pattern(self, pattern_id: str, name: str, description: str, signature: dict, now: str) -> None:
        """Record that this pattern signature was seen once more. Observation is not
        validation — it only advances the lifecycle as far as 'repeated'."""
        with self._connect() as conn:
            existing = conn.execute("SELECT id FROM patterns WHERE id = ?", (pattern_id,)).fetchone()
            if existing:
                conn.execute(
                    "UPDATE patterns SET name=?, description=?, signature_json=?, "
                    "observed_count = observed_count + 1, updated_at=? WHERE id=?",
                    (name, description, json.dumps(signature), now, pattern_id),
                )
            else:
                conn.execute(
                    """INSERT INTO patterns
                       (id, name, description, signature_json, observed_count, created_at, updated_at)
                       VALUES (?, ?, ?, ?, 1, ?, ?)""",
                    (pattern_id, name, description, json.dumps(signature), now, now),
                )

    def get_pattern(self, pattern_id: str) -> Optional[dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM patterns WHERE id = ?", (pattern_id,)).fetchone()
        return dict(row) if row else None

    def link_case_pattern(self, case_id: str, pattern_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO case_patterns (case_id, pattern_id) VALUES (?, ?)",
                (case_id, pattern_id),
            )

    def patterns_for_case(self, case_id: str) -> list[str]:
        """Pattern ids whose signature this case exhibited — the link the learning
        loop follows when an outcome arrives."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT pattern_id FROM case_patterns WHERE case_id = ?", (case_id,)
            ).fetchall()
        return [r["pattern_id"] for r in rows]

    def strengthen_pattern(self, pattern_id: str, confirmed: bool, now: str) -> None:
        column = "confirmed_count" if confirmed else "false_positive_count"
        with self._connect() as conn:
            conn.execute(
                f"UPDATE patterns SET {column} = {column} + 1, updated_at = ? WHERE id = ?",
                (now, pattern_id),
            )

    def list_patterns(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM patterns ORDER BY confirmed_count DESC").fetchall()
        return [dict(r) for r in rows]

    # -- provider cache + budget ledger ----------------------------------------

    def cache_get(self, provider: str, entity_type: str, value: str) -> Optional[dict[str, Any]]:
        """The stored response, with the time it was fetched. Expiry is the planner's
        decision, not storage's — the TTL is provider policy, and this table has no
        business knowing it."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT fetched_at, payload_json FROM provider_cache "
                "WHERE provider = ? AND entity_type = ? AND value = ?",
                (provider, entity_type, value.lower()),
            ).fetchone()
        if not row:
            return None
        return {"fetched_at": row["fetched_at"], "payload": json.loads(row["payload_json"])}

    def cache_put(self, provider: str, entity_type: str, value: str, fetched_at: float, payload: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO provider_cache "
                "(provider, entity_type, value, fetched_at, payload_json) VALUES (?, ?, ?, ?, ?)",
                (provider, entity_type, value.lower(), fetched_at, json.dumps(payload)),
            )

    def record_provider_event(self, provider: str, kind: str, ts: float) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO provider_events (provider, ts, kind) VALUES (?, ?, ?)",
                (provider, ts, kind),
            )

    def count_provider_events(self, provider: str, kind: str, since_ts: float) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM provider_events WHERE provider = ? AND kind = ? AND ts >= ?",
                (provider, kind, since_ts),
            ).fetchone()
        return row["n"] if row else 0

    def last_provider_event(self, provider: str, kind: str) -> Optional[float]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT MAX(ts) AS ts FROM provider_events WHERE provider = ? AND kind = ?",
                (provider, kind),
            ).fetchone()
        return row["ts"] if row and row["ts"] is not None else None

    def oldest_provider_event(self, provider: str, kind: str, since_ts: float) -> Optional[float]:
        """When the earliest request still inside the window was made — i.e. when the
        window will next free a slot."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT MIN(ts) AS ts FROM provider_events "
                "WHERE provider = ? AND kind = ? AND ts >= ?",
                (provider, kind, since_ts),
            ).fetchone()
        return row["ts"] if row and row["ts"] is not None else None

    def list_patterns_with_cases(self) -> list[dict[str, Any]]:
        """Every stored pattern, its parsed signature, and the cases that exhibited it.

        Structural matching needs all three at once: the signature to compare shapes,
        the counts to weight how well the shape has been validated, and the seeds so a
        re-run of one artifact cannot match against its own history.
        """
        sql = """SELECT p.*, c.id AS case_id, c.seed AS case_seed, c.outcome AS case_outcome
                 FROM patterns p
                 LEFT JOIN case_patterns cp ON cp.pattern_id = p.id
                 LEFT JOIN cases c ON c.id = cp.case_id"""
        with self._connect() as conn:
            rows = conn.execute(sql).fetchall()

        grouped: dict[str, dict[str, Any]] = {}
        for row in rows:
            pattern = grouped.get(row["id"])
            if pattern is None:
                pattern = {
                    k: row[k] for k in row.keys()
                    if k not in ("case_id", "case_seed", "case_outcome", "signature_json")
                }
                pattern["signature"] = json.loads(row["signature_json"] or "{}")
                pattern["cases"] = []
                grouped[row["id"]] = pattern
            if row["case_id"]:
                pattern["cases"].append(
                    {"id": row["case_id"], "seed": row["case_seed"], "outcome": row["case_outcome"]}
                )
        return list(grouped.values())
