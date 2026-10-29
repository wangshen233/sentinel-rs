# -*- coding: utf-8 -*-
"""字节计数的 TCP 中继：listen -> upstream，实时把累计字节写进 JSON。

用法：python byte_relay.py 10809 127.0.0.1 10808 stats.json
然后让注册工具走 socks5h://127.0.0.1:10809。
"""
import asyncio
import json
import os
import sys

stats = {"up": 0, "down": 0, "conns": 0}
lock = asyncio.Lock()
STATS_PATH = "relay_stats.json"


async def flush():
    while True:
        await asyncio.sleep(0.5)
        try:
            with open(STATS_PATH + ".tmp", "w", encoding="utf-8") as fh:
                json.dump(stats, fh)
            os.replace(STATS_PATH + ".tmp", STATS_PATH)
        except Exception:
            pass


async def pipe(reader, writer, key):
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            async with lock:
                stats[key] += len(chunk)
            writer.write(chunk)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle(creader, cwriter, host, port):
    async with lock:
        stats["conns"] += 1
    try:
        sreader, swriter = await asyncio.open_connection(host, port)
    except Exception:
        cwriter.close()
        return
    await asyncio.gather(
        pipe(creader, swriter, "up"),
        pipe(sreader, cwriter, "down"),
    )


async def main():
    global STATS_PATH
    lport = int(sys.argv[1])
    host = sys.argv[2]
    port = int(sys.argv[3])
    STATS_PATH = sys.argv[4] if len(sys.argv) > 4 else "relay_stats.json"
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, host, port), "127.0.0.1", lport
    )
    print(f"relay 127.0.0.1:{lport} -> {host}:{port}, stats={STATS_PATH}", flush=True)
    async with server:
        await asyncio.gather(server.serve_forever(), flush())


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
