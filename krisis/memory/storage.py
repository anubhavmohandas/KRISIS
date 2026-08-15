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
    confirmed_count INTEGER DEFAULT 0,
    false_positive_count INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


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
        # keep indicators in sync so future matching reflects the confirmed outcome
        with self._connect() as conn:
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

    def find_indicator_matches(self, entity_type: str, value: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT case_id, seed, outcome, risk_category FROM indicators "
                "WHERE entity_type = ? AND value = ?",
                (entity_type, value.lower()),
            ).fetchall()
        return [dict(r) for r in rows]

    # -- patterns -------------------------------------------------------------

    def upsert_pattern(self, pattern_id: str, name: str, description: str, signature: dict, now: str) -> None:
        with self._connect() as conn:
            existing = conn.execute("SELECT id FROM patterns WHERE id = ?", (pattern_id,)).fetchone()
            if existing:
                conn.execute(
                    "UPDATE patterns SET name=?, description=?, signature_json=?, updated_at=? WHERE id=?",
                    (name, description, json.dumps(signature), now, pattern_id),
                )
            else:
                conn.execute(
                    """INSERT INTO patterns (id, name, description, signature_json, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (pattern_id, name, description, json.dumps(signature), now, now),
                )

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
