from __future__ import annotations

import asyncio
from collections.abc import Callable

from resolver_identity.wrapper.metrics import RuntimeMetrics


async def start_monitoring_server(
    host: str,
    port: int,
    metrics: RuntimeMetrics,
    readiness_check: Callable[[], object] | None = None,
) -> asyncio.AbstractServer:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=2.0)
            parts = request_line.decode("ascii", errors="replace").split()
            path = parts[1] if len(parts) >= 2 else ""
            if path == "/metrics":
                body = metrics.render().encode("utf-8")
                status = "200 OK"
                content_type = "text/plain; version=0.0.4; charset=utf-8"
            elif path == "/healthz":
                body = b'{"ok":true}\n'
                status = "200 OK"
                content_type = "application/json"
            elif path == "/readyz":
                try:
                    if readiness_check is not None:
                        await asyncio.to_thread(readiness_check)
                    body = b'{"ok":true}\n'
                    status = "200 OK"
                except Exception:
                    body = b'{"ok":false}\n'
                    status = "503 Service Unavailable"
                content_type = "application/json"
            else:
                body = b'{"detail":"not found"}\n'
                status = "404 Not Found"
                content_type = "application/json"
            writer.write(
                f"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii") + body
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    return await asyncio.start_server(handle, host, port)
