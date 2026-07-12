from __future__ import annotations

import json
from typing import Any


def strip_signature(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: strip_signature(v) for k, v in value.items() if k != "signature"}
    if isinstance(value, list):
        return [strip_signature(v) for v in value]
    return value


def canonical_json_bytes(value: Any) -> bytes:
    unsigned = strip_signature(value)
    return json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_json_text(value: Any) -> str:
    return canonical_json_bytes(value).decode("utf-8")
