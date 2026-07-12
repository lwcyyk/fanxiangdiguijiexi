from __future__ import annotations

QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
}


def parse_question(query: bytes) -> tuple[str, str]:
    """Best-effort extraction of qname/qtype for audit logging only."""
    try:
        if len(query) < 12:
            return "", "UNKNOWN"
        offset = 12
        labels: list[str] = []
        while offset < len(query):
            length = query[offset]
            offset += 1
            if length == 0:
                break
            if length & 0xC0:
                return "", "COMPRESSED_UNSUPPORTED"
            labels.append(query[offset:offset + length].decode("ascii", errors="replace"))
            offset += length
        if offset + 4 > len(query):
            return ".".join(labels), "UNKNOWN"
        qtype = int.from_bytes(query[offset:offset + 2], "big")
        return ".".join(labels), QTYPE_NAMES.get(qtype, str(qtype))
    except Exception:
        return "", "UNKNOWN"
