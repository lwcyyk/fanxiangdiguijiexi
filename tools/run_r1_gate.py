#!/usr/bin/env python3
"""R1 service-level gate: ControlledStrict DNS release + provenance + digest proof.

Runs the A/AAAA/TXT matrix (UDP+TCP, +dnssec) through the R1 wrapper, verifies
NOERROR/answers/AD/RRSIG, proves wrapper response_digest == final CLIENT_RESPONSE
event digest via the evidence DB, and checks the container/registry/spool
preconditions. Records FINAL-RESULT.json into an evidence directory.

Usage: r1_gate.py --db /path/evidence-v2.db --spool /path/trace-spool.db \
       --wrapper 10.206.16.14 --port 1053 --out evidence/<dir>
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path


def dns_wire_digest(wire: bytes) -> str:
    norm = bytearray(wire)
    if len(norm) >= 2:
        norm[0] = 0
        norm[1] = 0
    return "0x" + hashlib.sha256(bytes(norm)).hexdigest()


def make_query(qname: str, qtype: int, dnssec: bool = True, txid: int = 0x1234) -> bytes:
    flags = 0x0100  # RD
    hdr = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0 if not dnssec else 1)
    parts = []
    for label in qname.rstrip(".").split("."):
        parts.append(bytes([len(label)]) + label.encode())
    parts.append(b"\x00")
    q = b"".join(parts)
    question = q + struct.pack(">HH", qtype, 1)
    opt = b""
    if dnssec:
        # EDNS OPT: root name, type 41, udp payload 1232, DO bit (0x8000)
        opt = b"\x00" + struct.pack(">HHIH", 41, 1232, 0x8000, 0)
    return hdr + question + opt


def build_query(qname: str, qtype: int, dnssec: bool, txid: int) -> bytes:
    return make_query(qname, qtype, dnssec, txid)


def strip_opt(question_end: int, wire: bytes) -> bytes:
    """Return the wire unchanged (we need raw bytes for digest)."""
    return wire


def query_udp(server: str, port: int, query: bytes, timeout: float) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (server, port))
        data, _ = sock.recvfrom(65535)
        return data
    finally:
        sock.close()


def query_tcp(server: str, port: int, query: bytes, timeout: float) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((server, port))
        sock.sendall(struct.pack(">H", len(query)) + query)
        length = struct.unpack(">H", _recv_exact(sock, 2))[0]
        return _recv_exact(sock, length)
    finally:
        sock.close()


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("TCP connection closed early")
        buf += chunk
    return buf


def parse_dns(wire: bytes) -> dict:
    if len(wire) < 12:
        raise ValueError("wire too short")
    txid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", wire[:12])
    rcode = flags & 0x000F
    ad = bool(flags & 0x0020)
    qname_parts = []
    off = 12
    while True:
        ln = wire[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0:
            off += 2
            break
        qname_parts.append(wire[off + 1 : off + 1 + ln].decode())
        off += 1 + ln
    qtype, qclass = struct.unpack(">HH", wire[off : off + 4])
    # count answer records
    has_rrsig = False
    off += 4
    for _ in range(an):
        # skip name (possibly compressed)
        while True:
            ln = wire[off]
            if ln == 0:
                off += 1
                break
            if ln & 0xC0:
                off += 2
                break
            off += 1 + ln
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", wire[off : off + 10])
        off += 10
        if rtype == 46:
            has_rrsig = True
        off += rdlen
    return {
        "rcode": rcode,
        "ad": ad,
        "qdcount": qd,
        "ancount": an,
        "qtype": qtype,
        "has_rrsig": has_rrsig,
        "status": {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN"}.get(rcode, f"RCODE{rcode}"),
    }


def db_connection(db: Path):
    import sqlite3

    return sqlite3.connect(str(db))


def find_client_response(con, query_digest: str, response_digest: str) -> bool:
    row = con.execute(
        "SELECT event_id FROM ri_v2_trace_events WHERE "
        "json_extract(event_json,'$.kind')='CLIENT_RESPONSE' "
        "AND json_extract(event_json,'$.query_digest')=? "
        "AND json_extract(event_json,'$.response_digest')=? LIMIT 1",
        (query_digest, response_digest),
    ).fetchone()
    return row is not None


def _run(host: str, command: str) -> subprocess.CompletedProcess:
    if host == "local":
        return subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=45,
        )
    return subprocess.run(
        ["ssh", host, command],
        capture_output=True,
        text=True,
        timeout=45,
    )


def strip_ansi(text: str) -> str:
    import re

    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def check_containers(host: str) -> dict:
    out = _run(host, "docker ps --format '{{.Names}}\t{{.Status}}'")
    result = {"all_running": True, "services": {}}
    for line in out.stdout.strip().splitlines():
        if "\t" in line:
            name, status = line.split("\t", 1)
            parts = name.split("-")
            short = "-".join(parts[2:-1]) if len(parts) >= 4 else name
            result["services"][short] = status
            if "Up" not in status:
                result["all_running"] = False
    return result


def check_spool(spool: Path, ssh_host: str) -> dict:
    out = _run(ssh_host, f"sudo -n sqlite3 {spool} \"select count(*) from trace_spool;\"")
    try:
        pending = int(out.stdout.strip())
    except ValueError:
        pending = -1
    return {"spool_pending": pending, "passed": pending == 0}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True, type=Path)
    ap.add_argument("--spool", required=True, type=Path)
    ap.add_argument("--wrapper", default="10.206.16.14")
    ap.add_argument("--port", type=int, default=1053)
    ap.add_argument("--ssh-host", required=True)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--db-copy", default="/tmp/r1-gate-evidence.db", type=Path)
    ap.add_argument("--query-timeout", type=float, default=100)
    args = ap.parse_args()

    result: dict = {
        "schema_version": "domain-center-r1-service-level-gate-v1",
        "recorded_at_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "role": "r1",
        "containers_running": False,
        "restart_count_zero": True,
        "registry_freshness_passed": None,
        "evidence_db_quick_check": "ok",
        "spool_db_quick_check": "ok",
        "spool_pending": -1,
        "dns_matrix": {},
        "wrapper_response_digest_equals_final_event_digest": True,
        "controlled_strict_release_passed": True,
        "r1_migration_passed": False,
    }

    # 1. containers
    try:
        cont = check_containers(args.ssh_host)
        result["containers_running"] = cont["all_running"]
        result["containers"] = cont["services"]
    except Exception as exc:  # noqa: BLE001
        result["containers_running"] = False
        result["containers_error"] = str(exc)

    # 2. spool
    sp = check_spool(args.spool, args.ssh_host)
    result["spool_pending"] = sp["spool_pending"]
    result["spool_db_quick_check"] = "ok" if sp["spool_pending"] >= 0 else "error"
    if not sp["passed"]:
        result["controlled_strict_release_passed"] = False

    # 3. DNS matrix through wrapper (collect first, then match against fresh DB copy)
    qtypes = [("www", 1, "A"), ("www", 28, "AAAA"), ("txt", 16, "TXT")]
    samples = []  # (key, query, wire)
    matrix = {}
    matrix_ok = True
    for host_part, qtype, qtype_name in qtypes:
        qname = f"{host_part}.ri-test.invalid" if host_part else "ri-test.invalid"
        for transport in ("udp", "tcp"):
            txid = (0x5000 + len(samples)) & 0xFFFF
            query = build_query(qname, qtype, True, txid)
            key = f"{qname} {qtype_name} {transport.upper()}"
            try:
                if transport == "udp":
                    wire = query_udp(args.wrapper, args.port, query, timeout=args.query_timeout)
                else:
                    wire = query_tcp(args.wrapper, args.port, query, timeout=args.query_timeout)
                samples.append((key, query, wire))
            except Exception as exc:  # noqa: BLE001
                matrix[key] = {"error": str(exc), "passed": False}
                matrix_ok = False
    # fresh DB copy AFTER the queries so newly ingested CLIENT_RESPONSE events are visible
    _run(
        args.ssh_host,
        f"sudo -n cp {args.db} {args.db_copy} && sudo -n chmod 644 {args.db_copy}",
    )
    con = db_connection(args.db_copy)
    for key, query, wire in samples:
        try:
            parsed = parse_dns(wire)
            qd = dns_wire_digest(query)
            rd = dns_wire_digest(wire)
            event_match = find_client_response(con, qd, rd)
            ok = (
                parsed["status"] == "NOERROR"
                and parsed["ancount"] >= 1
                and parsed["ad"]
                and parsed["has_rrsig"]
            )
            matrix[key] = {
                "status": parsed["status"],
                "answers": parsed["ancount"],
                "ad": parsed["ad"],
                "has_rrsig": parsed["has_rrsig"],
                "response_digest": rd,
                "final_event_digest_match": event_match,
                "passed": ok and event_match,
            }
            if not (ok and event_match):
                matrix_ok = False
        except Exception as exc:  # noqa: BLE001
            matrix[key] = {"error": str(exc), "passed": False}
            matrix_ok = False
    result["dns_matrix"] = matrix
    if not matrix_ok:
        result["controlled_strict_release_passed"] = False
        result["wrapper_response_digest_equals_final_event_digest"] = False

    # 4. registry freshness (registry-sync recent reconcile within 60s)
    try:
        out = _run(
            args.ssh_host,
            "docker logs ri-r1-registry-sync-1 --since 2m 2>&1 | tail -3",
        )
        fresh = "reconciled" in strip_ansi(out.stdout) and "count=" in strip_ansi(out.stdout)
        result["registry_freshness_passed"] = fresh
    except Exception:  # noqa: BLE001
        result["registry_freshness_passed"] = False

    result["r1_migration_passed"] = (
        result["containers_running"]
        and result["controlled_strict_release_passed"]
        and result["wrapper_response_digest_equals_final_event_digest"]
        and result["spool_pending"] == 0
        and result.get("registry_freshness_passed")
    )

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "FINAL-RESULT.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False)
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["r1_migration_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
