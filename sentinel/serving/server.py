"""
Stdlib HTTP server wrapping `MinerHandler`.

Kept deliberately thin — all behaviour lives in the handler, so this file has
nothing worth testing and can be replaced by FastAPI/uvicorn (or anything else)
without touching the logic. Threaded so a slow tool call cannot block a
validator's challenge, which is the difference between a low score and no score.
"""

from __future__ import annotations

import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .handler import MinerHandler, Request

logger = logging.getLogger("sentinel.serving")

MAX_BODY_BYTES = 1 << 20  # 1 MiB — tool arguments, not uploads


def _make_request_handler(handler: MinerHandler) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "sentinel-miner"

        def _dispatch(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY_BYTES:
                self._write(413, b'{"error":"body too large"}')
                return
            body = self.rfile.read(length) if length else b""
            path = self.path.split("?", 1)[0]

            response = handler.handle(
                Request(method=method, path=path, headers=dict(self.headers.items()), body=body)
            )
            self._write(response.status, response.to_bytes())

        def do_GET(self) -> None:  # noqa: N802 - stdlib naming
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch("POST")

        def _write(self, status: int, payload: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            # Attested responses are per-request and must never be cached:
            # a cached body would be served without its matching proof.
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt: str, *args: Any) -> None:
            logger.debug("%s - %s", self.address_string(), fmt % args)

    return _Handler


def make_server(handler: MinerHandler, host: str = "127.0.0.1", port: int = 8091) -> ThreadingHTTPServer:
    """Build (but do not start) a threaded server. Port 0 picks a free one."""
    return ThreadingHTTPServer((host, port), _make_request_handler(handler))


def serve(handler: MinerHandler, host: str = "127.0.0.1", port: int = 8091) -> None:
    """Run until interrupted."""
    server = make_server(handler, host, port)
    logger.info("miner serving on http://%s:%d (hotkey %s)", host, server.server_port, handler.hotkey_ss58)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
