from __future__ import annotations

from dataclasses import dataclass

from resolver_identity.models.endpoint import ResolverEndpoint


@dataclass(slots=True)
class FallbackResolver:
    endpoint: ResolverEndpoint
