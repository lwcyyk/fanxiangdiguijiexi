from __future__ import annotations

import asyncio
import socket


async def query_udp(query: bytes, host: str, port: int = 53, timeout: float = 3.0) -> bytes:
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_sendto(sock, query, (host, port))
        data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 4096), timeout)
        return data
    finally:
        sock.close()


async def query_tcp(query: bytes, host: str, port: int = 53, timeout: float = 3.0) -> bytes:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        writer.write(len(query).to_bytes(2, "big") + query)
        await writer.drain()
        size_bytes = await asyncio.wait_for(reader.readexactly(2), timeout)
        size = int.from_bytes(size_bytes, "big")
        return await asyncio.wait_for(reader.readexactly(size), timeout)
    finally:
        writer.close()
        await writer.wait_closed()
