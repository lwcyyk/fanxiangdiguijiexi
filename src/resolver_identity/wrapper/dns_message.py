from __future__ import annotations


def make_servfail(query: bytes) -> bytes:
    if len(query) < 12:
        return b""
    transaction_id = query[:2]
    # QR=1, copy RD if present, set RA=1, RCODE=2 (SERVFAIL)
    original_flags = int.from_bytes(query[2:4], "big")
    rd = original_flags & 0x0100
    flags = 0x8000 | rd | 0x0080 | 0x0002
    qdcount = query[4:6]
    header = transaction_id + flags.to_bytes(2, "big") + qdcount + b"\x00\x00\x00\x00\x00\x00"
    return header + query[12:]
