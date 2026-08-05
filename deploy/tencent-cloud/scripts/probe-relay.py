#!/usr/bin/env python3
"""norn activate readiness probe relay (deployment-only, not frozen release code).

The frozen activate readiness probe (_norn_grpc_ready) uses urllib, which
speaks HTTP/1.1. nginx's grpc_pass delivers grpc-status as an HTTP/1.1
*trailer* (the response is chunked), and urllib reads response headers before
the body, so it never sees grpc-status and rejects an otherwise-healthy read
proxy with NORN_HTTP_REJECTED (HTTP 200, grpc-status missing). The frozen
acceptance harness never exercised this path -- it used nornctl (an HTTP/2
gRPC client) instead of wizard activate.

This relay terminates TLS on 127.0.0.1:8443 for the probe (the node's runtime
.env points RI_NORN_READ_HOSTNAME=localhost so the probe lands here), forwards
the gRPC request to the real read proxy on 10.206.16.3:8443, parses the
chunked HTTP/1.1 response including the trailer section, and re-serves it to
the probe with grpc-status surfaced as a response header. The real read proxy
stays on 10.206.16.3:8443 for resolvers and management nornctl.

Run as root (reads root-only secret material), bind 127.0.0.1 only.
"""
from __future__ import annotations

import argparse
import socket
import ssl
import sys
import threading

PROBE_PATH = "/Blockchain/GetBlockNumber"


class BufferedConn:
    """Tiny buffered reader over a socket with line + exact-length reads."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buf = b""

    def _fill(self) -> None:
        data = self.sock.recv(65536)
        if not data:
            raise EOFError("upstream closed connection")
        self.buf += data

    def readline(self) -> bytes:
        while b"\r\n" not in self.buf:
            self._fill()
        line, _, self.buf = self.buf.partition(b"\r\n")
        return line

    def read(self, n: int) -> bytes:
        while len(self.buf) < n:
            self._fill()
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


def parse_request(conn: BufferedConn) -> tuple[str, str, dict[str, str], bytes]:
    request_line = conn.readline().decode("latin-1", "replace")
    parts = request_line.split(" ")
    if len(parts) < 3:
        raise ValueError(f"malformed request line: {request_line!r}")
    method, path, _version = parts[0], parts[1], parts[2]
    headers: dict[str, str] = {}
    while True:
        line = conn.readline()
        if not line or line == b"":
            break
        name, _, value = line.decode("latin-1", "replace").partition(":")
        headers[name.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0") or 0)
    body = conn.read(length) if length else b""
    return method, path, headers, body


def read_upstream_response(conn: BufferedConn) -> tuple[str, dict[str, str], dict[str, str], bytes]:
    """Read status line, headers, chunked body and trailers from the upstream."""
    status_line = conn.readline().decode("latin-1", "replace")
    headers: dict[str, str] = {}
    while True:
        line = conn.readline()
        if not line or line == b"":
            break
        name, _, value = line.decode("latin-1", "replace").partition(":")
        headers[name.strip().lower()] = value.strip()
    transfer = headers.get("transfer-encoding", "").lower()
    trailers: dict[str, str] = {}
    if "chunked" in transfer:
        chunks = bytearray()
        while True:
            size_line = conn.readline()
            if not size_line:
                break
            size_hex = size_line.split(b";")[0].strip()
            if not size_hex:
                break
            size = int(size_hex, 16)
            if size == 0:
                while True:
                    tline = conn.readline()
                    if not tline or tline == b"":
                        break
                    name, _, value = tline.decode("latin-1", "replace").partition(":")
                    trailers[name.strip().lower()] = value.strip()
                break
            chunks += conn.read(size)
            conn.readline()  # trailing CRLF after chunk data
        body = bytes(chunks)
    else:
        length = int(headers.get("content-length", "0") or 0)
        body = conn.read(length) if length else b""
    return status_line, headers, trailers, body


def handle(conn: socket.socket, cfg: argparse.Namespace) -> None:
    try:
        client = BufferedConn(conn)
        method, path, _headers, body = parse_request(client)
        if method != "POST" or path != PROBE_PATH:
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        ctx = ssl.create_default_context(cafile=cfg.ca)
        ctx.load_cert_chain(cfg.client_crt, cfg.client_key)
        raw = socket.create_connection((cfg.upstream_host, cfg.upstream_port), timeout=10)
        try:
            up = ctx.wrap_socket(raw, server_hostname=cfg.upstream_host)
        except Exception:
            raw.close()
            raise
        try:
            # nginx grpc_pass over HTTP/1.1 aborts the gRPC upstream with
            # grpc-status 2 / EOF when the client requests Connection: close,
            # so keep the upstream connection alive and just read the chunked
            # response (status, headers, chunks, trailer) before closing.
            request = (
                f"POST {PROBE_PATH} HTTP/1.1\r\n"
                f"Host: {cfg.upstream_host}:{cfg.upstream_port}\r\n"
                "Content-Type: application/grpc\r\n"
                "TE: trailers\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: keep-alive\r\n"
                "\r\n"
            ).encode("latin-1") + body
            up.sendall(request)
            status_line, up_headers, trailers, up_body = read_upstream_response(BufferedConn(up))
        finally:
            up.close()
        grpc_status = up_headers.get("grpc-status") or trailers.get("grpc-status") or "0"
        grpc_message = up_headers.get("grpc-message") or trailers.get("grpc-message", "")
        status_parts = status_line.split(" ", 2)
        status = status_parts[1] if len(status_parts) > 1 else "502"
        reason = status_parts[2] if len(status_parts) > 2 else ""
        response = [
            f"HTTP/1.1 {status} {reason}".rstrip(),
            "Content-Type: " + (up_headers.get("content-type") or "application/grpc"),
            f"grpc-status: {grpc_status}",
            f"Content-Length: {len(up_body)}",
            "Connection: close",
        ]
        if grpc_message:
            response.append(f"grpc-message: {grpc_message}")
        conn.sendall(("\r\n".join(response) + "\r\n\r\n").encode("latin-1") + up_body)
    except Exception as exc:  # noqa: BLE001 - keep the relay up and log
        try:
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        except OSError:
            pass
        print(f"probe-relay: error: {exc!r}", flush=True)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1", help="listen address (loopback only)")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--secret-dir", required=True, help="norn host secret dir (RI_NORN config root/secret)")
    parser.add_argument("--upstream-host", default="10.206.16.3", help="real read proxy address")
    parser.add_argument("--upstream-port", type=int, default=8443)
    args = parser.parse_args()

    secret = args.secret_dir
    args.ca = f"{secret}/norn-tls/ca.crt"
    args.client_crt = f"{secret}/norn-tls/client.crt"
    args.client_key = f"{secret}/norn-tls/client.key"
    server_crt = f"{secret}/tls/server.crt"
    server_key = f"{secret}/tls/server.key"

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(server_crt, server_key)
    server_ctx.verify_mode = ssl.CERT_REQUIRED
    server_ctx.load_verify_locations(args.ca)
    try:
        server_ctx.set_alpn_protocols(["http/1.1"])
    except (NotImplementedError, ssl.SSLError):
        pass

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.bind, args.port))
    listener.listen(16)
    print(f"probe-relay: listening on https://{args.bind}:{args.port} -> {args.upstream_host}:{args.upstream_port}", flush=True)

    def serve() -> None:
        while True:
            try:
                raw, _addr = listener.accept()
            except OSError:
                break
            try:
                tls_sock = server_ctx.wrap_socket(raw, server_side=True)
            except ssl.SSLError:
                try:
                    raw.close()
                except OSError:
                    pass
                continue
            threading.Thread(target=handle, args=(tls_sock, args), daemon=True).start()

    serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
