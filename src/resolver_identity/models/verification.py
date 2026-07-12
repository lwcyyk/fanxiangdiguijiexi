from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class VerificationResult:
    accepted: bool
    status: str
    resolver_id: str | None = None
    reasons: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def accept(cls, resolver_id: str, status: str = "VERIFIED", **evidence: Any) -> "VerificationResult":
        return cls(True, status, resolver_id, [], evidence)

    @classmethod
    def reject(cls, reason: str, resolver_id: str | None = None, **evidence: Any) -> "VerificationResult":
        return cls(False, "REJECTED", resolver_id, [reason], evidence)

    def to_dict(self) -> dict:
        return {
            "accepted": self.accepted,
            "status": self.status,
            "resolver_id": self.resolver_id,
            "reasons": self.reasons,
            "evidence": self.evidence,
        }
