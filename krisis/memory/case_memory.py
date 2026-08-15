"""
Case memory — stores completed investigations and keeps indicator memory in sync.

See CASE MEMORY / CLOSED-LOOP LEARNING in the design doc: a case does not
disappear after the verdict. Saving a case also feeds its entities into
PatternMemory so later investigations can be compared against it.
"""

from __future__ import annotations

from typing import Any, Optional

from ..core.models import Case
from .pattern_memory import PatternMemory
from .storage import Storage


class CaseMemory:
    def __init__(self, storage: Storage, pattern_memory: PatternMemory):
        self.storage = storage
        self.pattern_memory = pattern_memory

    def save(self, case: Case) -> None:
        self.storage.save_case(case.to_dict())
        self.pattern_memory.record_case(case)

    def get(self, case_id: str) -> Optional[dict[str, Any]]:
        return self.storage.get_case(case_id)

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.storage.list_cases(limit=limit)

    def set_outcome(self, case_id: str, outcome: str) -> None:
        """outcome: any core.models.Outcome value. Only human-confirmed ones move
        pattern strength — see PatternMemory.apply_outcome."""
        self.pattern_memory.apply_outcome(case_id, outcome)
