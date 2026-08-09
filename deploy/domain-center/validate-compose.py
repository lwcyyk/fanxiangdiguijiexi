#!/usr/bin/env python3
"""Validate the clean seven-role domain-center Compose contract."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
ROLES = ("management", "norn-a", "norn-b", "authdns", "r3", "r2", "r1")
RESOLVERS = ("r3", "r2", "r1")
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
        rust_image = str(services["agent"].get("image", ""))
        if not re.search(r"\$\{RI_IMAGE:\?", rust_image):
            fail(f"{role}: unified post-reconnect Rust image must be explicitly pinned")

    r1_wrapper_env = service_environment(documents["r1"]["services"]["wrapper"])
    if r1_wrapper_env.get("RI_VERIFICATION_MODE") != "controlled-strict":
        fail("r1: wrapper is not controlled-strict")
    if str(r1_wrapper_env.get("RI_REGISTRY_MAX_STALENESS_SECONDS")) != "45":
        fail("r1: wrapper freshness is not fixed at 45")

    auth_services = documents["authdns"]["services"]
    if set(auth_services) != {"registry-sync", "agent", "authority-proxy"}:
        fail("authdns: Compose must contain only the three host-network Rust services")
    for service in auth_services.values():
        if service.get("network_mode") != "host":
            fail("authdns: every service must use host network")
    authority_env = service_environment(auth_services["authority-proxy"])
    if authority_env.get("RI_AUTHORITY_BACKEND") != "127.0.0.1:5353":
        fail("authdns: authority backend must remain host BIND on loopback:5353")
    auth_agent_env = service_environment(auth_services["agent"])
    if auth_agent_env.get("RI_VERIFICATION_MODE") != "controlled-strict":
        fail("authdns: agent is not controlled-strict")
    if str(auth_agent_env.get("RI_REGISTRY_MAX_STALENESS_SECONDS")) != "45":
        fail("authdns: freshness is not fixed at 45")
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
            if "@sha256:" not in image and not image.startswith("${RI_IMAGE:?"):
                fail(f"{role}/{service_name}: image is not digest-pinned or required unified Rust image")

    print("validated 7 clean domain-center Compose files")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, yaml.YAMLError) as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        sys.exit(1)
