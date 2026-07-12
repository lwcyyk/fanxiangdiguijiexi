from __future__ import annotations

from collections import defaultdict
from threading import Lock

from resolver_identity.models.verification import VerificationResult


class RuntimeMetrics:
    def __init__(self) -> None:
        self._lock = Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._latency_count = 0
        self._latency_sum_seconds = 0.0

    def record_decision(self, decision: str, latency_ms: float, results: list[VerificationResult]) -> None:
        with self._lock:
            self._counters[("resolver_identity_dns_queries_total", (("decision", decision.lower()),))] += 1
            for result in results:
                cache = str(result.evidence.get("cache", "miss"))
                self._counters[("resolver_identity_verifications_total", (("accepted", str(result.accepted).lower()), ("cache", cache)))] += 1
            self._latency_count += 1
            self._latency_sum_seconds += latency_ms / 1000.0

    def render(self) -> str:
        with self._lock:
            lines = [
                "# HELP resolver_identity_up Whether the DNS wrapper process is running.",
                "# TYPE resolver_identity_up gauge",
                "resolver_identity_up 1",
                "# HELP resolver_identity_dns_queries_total DNS decisions by outcome.",
                "# TYPE resolver_identity_dns_queries_total counter",
            ]
            for (name, labels), value in sorted(self._counters.items()):
                label_text = ",".join(f'{key}="{value_}"' for key, value_ in labels)
                lines.append(f"{name}{{{label_text}}} {value:g}")
            lines.extend([
                "# HELP resolver_identity_query_duration_seconds Total DNS gate latency.",
                "# TYPE resolver_identity_query_duration_seconds summary",
                f"resolver_identity_query_duration_seconds_count {self._latency_count}",
                f"resolver_identity_query_duration_seconds_sum {self._latency_sum_seconds:.9f}",
            ])
            return "\n".join(lines) + "\n"
