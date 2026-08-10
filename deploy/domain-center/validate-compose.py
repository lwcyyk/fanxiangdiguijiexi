#!/usr/bin/env python3
"""Validate the clean seven-role domain-center Compose contract."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
ROLES = ("management", "norn-a", "norn-b", "authdns", "r3", "r2", "r1")
RESOLVERS = ("r3", "r2", "r1")
RESOLVER_SERVICE_IMAGES = {
    "resolver": "RI_KNOT_IMAGE",
    "trace-producer": "RI_TRACE_PRODUCER_IMAGE",
    "registry-sync": "RI_REGISTRY_SYNC_IMAGE",
    "agent": "RI_AGENT_IMAGE",
    "trace-adapter": "RI_TRACE_ADAPTER_IMAGE",
}
AUTHDNS_SERVICE_IMAGES = {
    "registry-sync": "RI_REGISTRY_SYNC_IMAGE",
    "agent": "RI_AGENT_IMAGE",
    "authority-proxy": "RI_AUTHORITY_PROXY_IMAGE",
}
RC16_MARKERS = (
    "RI_ROOT_REQUEST_CONTEXT",
    "RI_HOP_CONTEXT",
    "RI_CONTEXT_STORE",
    "RI_CONTEXT_API",
    "RIK2",
    "EVIDENCE_V3",
)
OVERLAY_MARKERS = (
    "docker-compose.rc11.yml",
    "compose.rc12",
    "compose.rc13",
    "compose.rc14",
    "compose.rc15",
    "registry-rc13-experiment",
)


def fail(message: str) -> None:
    raise AssertionError(message)


def service_environment(service: dict) -> dict[str, object]:
    environment = service.get("environment", {})
    if isinstance(environment, dict):
        return environment
    fail("service environment must use mapping form")


def main() -> int:
    documents: dict[str, dict] = {}
    texts: dict[str, str] = {}
    for role in ROLES:
        path = ROOT / role / "compose.yml"
        if not path.is_file():
            fail(f"missing {path}")
        text = path.read_text(encoding="utf-8")
        document = yaml.safe_load(text)
        if not isinstance(document, dict) or not isinstance(document.get("services"), dict):
            fail(f"{path}: services mapping missing")
        documents[role] = document
        texts[role] = text

    combined = "\n".join(texts.values())
    for marker in OVERLAY_MARKERS:
        if marker in combined:
            fail(f"historical overlay dependency found: {marker}")
    for marker in RC16_MARKERS:
        if marker in combined:
            fail(f"RC16 context marker found: {marker}")

    wrapper_roles = [role for role, doc in documents.items() if "wrapper" in doc["services"]]
    if wrapper_roles != ["r1"]:
        fail(f"wrapper must exist only on r1, got {wrapper_roles}")

    for role in RESOLVERS:
        services = documents[role]["services"]
        expected = {"resolver", "trace-producer", "registry-sync", "agent", "trace-adapter"}
        if not expected.issubset(services):
            fail(f"{role}: missing resolver services {sorted(expected - services.keys())}")
        resolver_volumes = [str(volume) for volume in services["resolver"].get("volumes", [])]
        if not any("RI_KNOT_CACHE_HOST_DIR" in volume and volume.endswith(":/var/cache/knot-resolver") for volume in resolver_volumes):
            fail(f"{role}: resolver cache must use an explicit adoptable host path")
        producer = services["trace-producer"]
        if producer.get("network_mode") != "none" or "networks" in producer:
            fail(f"{role}: trace-producer must use network_mode none")
        agent_env = service_environment(services["agent"])
        if agent_env.get("RI_VERIFICATION_MODE") != "controlled-strict":
            fail(f"{role}: agent is not controlled-strict")
        if str(agent_env.get("RI_REGISTRY_MAX_STALENESS_SECONDS")) != "45":
            fail(f"{role}: agent freshness is not fixed at 45")
        if agent_env.get("RI_AGENT_PEER_CREDENTIALS_FILE") != "/run/secrets/agent_peer_credentials.json":
            fail(f"{role}: directional peer credentials file missing")
        for key in (
            "RI_AGENT_TLS_CERT_FILE",
            "RI_AGENT_TLS_KEY_FILE",
            "RI_AGENT_TLS_CLIENT_CA_FILE",
            "RI_AGENT_TLS_CLIENT_CERT_FILE",
            "RI_AGENT_TLS_CLIENT_KEY_FILE",
            "RI_AGENT_TLS_CA_FILE",
        ):
            if key not in agent_env:
                fail(f"{role}: agent mTLS variable missing: {key}")
        registry_env = service_environment(services["registry-sync"])
        rpc_urls = str(registry_env.get("RI_CHAIN_RPC_URLS", ""))
        if "two mTLS Norn read endpoints" not in rpc_urls:
            fail(f"{role}: Norn dual-read requirement is not explicit")
        adapter_env = service_environment(services["trace-adapter"])
        if "RI_TRACE_CACHE_PROVENANCE_WAIT_MS" not in adapter_env:
            fail(f"{role}: cache provenance wait configuration missing")
        if str(agent_env.get("RI_TRACE_WAIT_MILLIS")) != "${RI_TRACE_WAIT_MILLIS:-30000}":
            fail(f"{role}: Agent trace wait differs from the stable RC15 value")
        if str(adapter_env.get("RI_TRACE_CACHE_PROVENANCE_WAIT_MS")) != "${RI_TRACE_CACHE_PROVENANCE_WAIT_MS:-30000}":
            fail(f"{role}: cache provenance wait differs from the stable RC15 value")
        expected_images = dict(RESOLVER_SERVICE_IMAGES)
        if role == "r1":
            expected_images["wrapper"] = "RI_WRAPPER_IMAGE"
        for service_name, variable in expected_images.items():
            image = str(services[service_name].get("image", ""))
            if not image.startswith(f"${{{variable}:"):
                fail(f"{role}/{service_name}: image must be pinned through {variable}")

    r1_wrapper_env = service_environment(documents["r1"]["services"]["wrapper"])
    if r1_wrapper_env.get("RI_VERIFICATION_MODE") != "controlled-strict":
        fail("r1: wrapper is not controlled-strict")
    if str(r1_wrapper_env.get("RI_REGISTRY_MAX_STALENESS_SECONDS")) != "45":
        fail("r1: wrapper freshness is not fixed at 45")
    if str(r1_wrapper_env.get("RI_WRAPPER_UPSTREAM_TIMEOUT_MS")) != "${RI_WRAPPER_UPSTREAM_TIMEOUT_MS:-12000}":
        fail("r1: Wrapper upstream timeout does not include the stable cold-MISS budget")
    if str(r1_wrapper_env.get("RI_WRAPPER_AGENT_TIMEOUT_MS")) != "${RI_WRAPPER_AGENT_TIMEOUT_MS:-120000}":
        fail("r1: Wrapper Agent timeout differs from the stable RC15 value")

    auth_services = documents["authdns"]["services"]
    if set(auth_services) != {"registry-sync", "agent", "authority-proxy"}:
        fail("authdns: Compose must contain only the three host-network Rust services")
    for service in auth_services.values():
        if service.get("network_mode") != "host":
            fail("authdns: every service must use host network")
    authority_env = service_environment(auth_services["authority-proxy"])
    if authority_env.get("RI_AUTHORITY_BACKEND") != "127.0.0.1:5353":
        fail("authdns: authority backend must remain host BIND on loopback:5353")
    for service_name, variable in AUTHDNS_SERVICE_IMAGES.items():
        image = str(auth_services[service_name].get("image", ""))
        if not image.startswith(f"${{{variable}:"):
            fail(f"authdns/{service_name}: image must be pinned through {variable}")
    auth_agent_env = service_environment(auth_services["agent"])
    if auth_agent_env.get("RI_VERIFICATION_MODE") != "controlled-strict":
        fail("authdns: agent is not controlled-strict")
    if str(auth_agent_env.get("RI_REGISTRY_MAX_STALENESS_SECONDS")) != "45":
        fail("authdns: freshness is not fixed at 45")
    if str(auth_agent_env.get("RI_TRACE_WAIT_MILLIS")) != "${RI_TRACE_WAIT_MILLIS:-30000}":
        fail("authdns: Agent trace wait differs from the stable RC15 value")
    if auth_agent_env.get("RI_AGENT_PEER_CREDENTIALS_FILE") != "/run/secrets/agent_peer_credentials.json":
        fail("authdns: directional peer credentials file missing")

    for role in ("norn-a", "norn-b"):
        services = documents[role]["services"]
        proxy = services.get("norn-read-proxy", {})
        if not proxy:
            fail(f"{role}: mTLS read proxy missing")
        if not any("RI_NORN_TLS_DIR" in str(volume) for volume in proxy.get("volumes", [])):
            fail(f"{role}: mTLS read proxy TLS mount missing")

    for role, doc in documents.items():
        for service_name, service in doc["services"].items():
            image = str(service.get("image", ""))
            if not image:
                fail(f"{role}/{service_name}: image missing")
            if "@sha256:" not in image and not image.startswith("${"):
                fail(f"{role}/{service_name}: image is not digest-pinned or required by an image variable")

    print("validated 7 clean domain-center Compose files")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, yaml.YAMLError) as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        sys.exit(1)
