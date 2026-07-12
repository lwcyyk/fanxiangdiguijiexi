from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_contract_abi(artifact_path: str | Path) -> list[dict[str, Any]]:
    artifact = json.loads(Path(artifact_path).read_text(encoding="utf-8"))
    abi = artifact.get("abi")
    if not isinstance(abi, list):
        raise ValueError("contract artifact does not contain an ABI array")
    return abi


def default_foundry_artifact(project_root: str | Path) -> Path:
    return Path(project_root) / "contracts/out/ResolverIdentityRegistryV1.sol/ResolverIdentityRegistryV1.json"
