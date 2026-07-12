from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from resolver_identity.common.time import parse_rfc3339
from resolver_identity.models.authenticity_object import ACTIVE, ResolverAuthenticityObjectV1


@dataclass(slots=True)
class VerificationPolicy:
    allowed_transports: set[str]
    soft_ttl_seconds: int = 600
    hard_ttl_seconds: int = 3600

    @classmethod
    def default(cls) -> "VerificationPolicy":
        return cls({"udp", "tcp", "doh"})

    def check_object_semantics(self, obj: ResolverAuthenticityObjectV1, now: datetime) -> str | None:
        if obj.schema_version != "resolver-auth-object-v1":
            return "unsupported_schema_version"
        if obj.canonical_version != 1:
            return "unsupported_canonical_version"
        if obj.status != ACTIVE:
            return "status_not_active"
        if parse_rfc3339(obj.valid_from) > now:
            return "object_not_yet_valid"
        if parse_rfc3339(obj.valid_until) <= now:
            return "object_expired"
        for ep in obj.endpoints:
            if ep.transport not in self.allowed_transports:
                return "transport_not_allowed"
        return None

    def expirations(self, now: datetime, valid_until: datetime) -> tuple[str, str]:
        soft = now + timedelta(seconds=self.soft_ttl_seconds)
        hard = min(now + timedelta(seconds=self.hard_ttl_seconds), valid_until)
        return _fmt(soft), _fmt(hard)


def _fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
