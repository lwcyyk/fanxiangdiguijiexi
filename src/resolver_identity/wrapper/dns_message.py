from __future__ import annotations


def _question_section_end(query: bytes) -> int | None:
    if len(query) < 12:
        return None
    question_count = int.from_bytes(query[4:6], "big")
    if question_count == 0:
        return None
    offset = 12
    for _ in range(question_count):
        while True:
            if offset >= len(query):
                return None
            length = query[offset]
            offset += 1
            if length == 0:
                break
            if length > 63 or offset + length > len(query):
                return None
            offset += length
        if offset + 4 > len(query):
            return None
        offset += 4
    return offset


def make_servfail(query: bytes) -> bytes:
    question_end = _question_section_end(query)
    if question_end is None:
        return b""
    transaction_id = query[:2]
    # QR=1, copy RD if present, set RA=1, RCODE=2 (SERVFAIL)
    original_flags = int.from_bytes(query[2:4], "big")
    rd = original_flags & 0x0100
    flags = 0x8000 | rd | 0x0080 | 0x0002
    qdcount = query[4:6]
    header = transaction_id + flags.to_bytes(2, "big") + qdcount + b"\x00\x00\x00\x00\x00\x00"
    return header + query[12:question_end]
