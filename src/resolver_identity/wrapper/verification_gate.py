from __future__ import annotations

from resolver_identity.models.endpoint import ResolverEndpoint
from resolver_identity.verifier.resolver_verifier import ResolverVerifier
from resolver_identity.wrapper.dns_message import make_servfail
from resolver_identity.wrapper.request_journal import RequestJournal


class VerificationGate:
    def __init__(self, verifier: ResolverVerifier, journal: RequestJournal | None = None):
        self.verifier = verifier
        self.journal = journal or RequestJournal()

    def release_or_servfail(self, query: bytes, response: bytes, observed: list[ResolverEndpoint]) -> tuple[bytes, str]:
        request_id = self.journal.create(query)
        for endpoint in observed:
            result = self.verifier.verify_endpoint(endpoint)
            self.journal.add(request_id, {"endpoint": endpoint.to_dict(), "result": result.to_dict()})
            if not result.accepted:
                return make_servfail(query), request_id
        return response, request_id
