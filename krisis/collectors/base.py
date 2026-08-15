"""
EvidenceCollector — the interface every provider adapter implements.

KRISIS's core engine (graph, pivot engine, correlation, risk) never imports a
provider SDK directly. It only ever sees Evidence objects. This is what makes
providers swappable/optional and lets KRISIS degrade gracefully when a
provider is down, rate-limited, or simply not configured (see PROVIDER
FAILURE / GRACEFUL DEGRADATION).
"""

from __future__ import annotations

import abc
from dataclasses import dataclass

from ..core.models import Entity, Evidence


class CollectorError(Exception):
    """Raised by a collector when it fails. Caught by the orchestrator, never fatal."""


@dataclass
class CollectorResult:
    evidence: list[Evidence]
    available: bool                 # False if the provider could not be reached/used at all
    note: str = ""                  # e.g. "no API key configured", "rate limited"


class EvidenceCollector(abc.ABC):
    name: str = "base"
    # which EntityType.value strings this collector knows how to investigate
    supports: tuple[str, ...] = ()

    @abc.abstractmethod
    def collect(self, entity: Entity) -> CollectorResult:
        """Collect evidence about `entity`. Must never raise — catch internally and
        return CollectorResult(available=False, note=...) on any failure so a single
        flaky provider can never take down the investigation.
        """
        raise NotImplementedError

    def can_handle(self, entity: Entity) -> bool:
        return entity.type.value in self.supports
