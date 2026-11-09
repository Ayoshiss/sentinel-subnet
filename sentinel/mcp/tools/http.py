"""
`<scope>.request`: call an HTTPS API with a key the agent never sees.

Many agents do not hold database passwords, they hold API keys: Stripe, a card
processor, a bank feed. The same question applies: who at the agent vendor can
use that key? This tool keeps the key inside the enclave. The agent asks for a
method and a path; the enclave adds the key and makes the call.

What the customer controls, and the operator does not:

  * the key itself, released sealed by the customer's key server;
  * the one host it may be sent to;
  * which methods and paths may be called.

All three arrive together in the sealed secret, so they come from the key
server, not from the machine's configuration. That matters: if the operator
could set the host, they could point it at a server of their own and collect
the key from the first request. Upstream TLS is checked against the CA store in
the measured image, redirects are never followed, and proxy settings from the
environment are ignored, so the key only ever leaves for the customer's host.

The request is echoed in the result, so the chip-signed proof covers what was
called as well as what came back.

The secret is JSON:

    {
      "kind": "http",
      "base_url": "https://api.stripe.com",
      "auth": {"header": "Authorization", "value": "Bearer sk_test_..."},
      "allow": [
        {"method": "GET", "path": "/v1/balance"},
        {"method": "GET", "path": "/v1/charges/*"}
      ]
    }

A path ending in `/*` allows anything below it; any other path must match
exactly. Read-only by default in the sense that matters: only the methods the
customer lists are callable, and the example lists only GET.
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from ..server import ToolError

KIND = "http"
METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})
#: Headers an agent may set. Everything else, above all anything that could
#: carry or replace credentials, is dropped.
AGENT_HEADERS = frozenset({"accept", "content-type", "idempotency-key"})
DEFAULT_MAX_RESPONSE = 1 << 20
DEFAULT_TIMEOUT = 20.0
REDACTED = "[redacted]"
# Encoded separators and dots let `/v1/charges/%2e%2e/admin` reach a path the
# allow list never named, so the path must be plain.
_ENCODED_TRICKS = re.compile(r"%(2e|2f|5c|00)", re.IGNORECASE)


@dataclass(frozen=True)
class Rule:
    method: str
    path: str

    def matches(self, method: str, path: str) -> bool:
        if method != self.method:
            return False
        if self.path.endswith("/*"):
            prefix = self.path[:-1]  # keeps the trailing slash
            return path.startswith(prefix) and len(path) > len(prefix)
        return path == self.path


@dataclass(frozen=True)
class HttpSpec:
    """What the customer's key server released. Never logged."""

    base_url: str
    host: str
    auth_header: str
    auth_value: str = field(repr=False)
    rules: tuple[Rule, ...]
    max_response_bytes: int = DEFAULT_MAX_RESPONSE
    timeout: float = DEFAULT_TIMEOUT

    def __repr__(self) -> str:
        return f"HttpSpec(base_url={self.base_url!r}, auth=<redacted>, rules={len(self.rules)})"


def is_http_secret(secret: str) -> bool:
    """True when a released secret is an HTTP spec rather than a database DSN."""
    if not secret.lstrip().startswith("{"):
        return False
    try:
        return json.loads(secret).get("kind") == KIND
    except (ValueError, AttributeError):
        return False


def parse_spec(secret: str) -> HttpSpec:
    """Validate a released HTTP secret. Errors never quote the key."""
    try:
        raw = json.loads(secret)
    except ValueError as exc:
        raise ToolError(f"the HTTP secret is not valid JSON: {exc.msg}") from None
    if not isinstance(raw, dict) or raw.get("kind") != KIND:
        raise ToolError('the HTTP secret must be a JSON object with "kind": "http"')

    base = raw.get("base_url")
    if not isinstance(base, str):
        raise ToolError("base_url is required")
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme != "https":
        raise ToolError("base_url must be https: the key must not cross the network readable")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ToolError("base_url must name a host and carry no credentials")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ToolError("base_url is the origin only, e.g. https://api.example.com; "
                        "put paths in the allow list")
    origin = f"https://{parsed.netloc}"

    auth = raw.get("auth")
    if not isinstance(auth, dict):
        raise ToolError('auth is required: {"header": "...", "value": "..."}')
    header, value = auth.get("header"), auth.get("value")
    if not isinstance(header, str) or not header.strip() or not isinstance(value, str) or not value:
        raise ToolError("auth needs a header name and a non-empty value")
    if any(c in header + value for c in "\r\n"):
        raise ToolError("auth header and value must be single-line")

    rules_raw = raw.get("allow")
    if not isinstance(rules_raw, list) or not rules_raw:
        raise ToolError("allow must list at least one {method, path}")
    rules = []
    for item in rules_raw:
        if not isinstance(item, dict):
            raise ToolError("each allow entry is {method, path}")
        method = str(item.get("method", "")).upper()
        path = item.get("path")
        if method not in METHODS:
            raise ToolError(f"allow: unsupported method {method!r}")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ToolError(f"allow: path must start with '/', got {path!r}")
        if "*" in path[:-1] or (path.endswith("*") and not path.endswith("/*")):
            raise ToolError(f"allow: only a trailing '/*' wildcard is supported, got {path!r}")
        _check_path(path.removesuffix("*"))
        rules.append(Rule(method, path))

    max_bytes = int(raw.get("max_response_bytes", DEFAULT_MAX_RESPONSE))
    timeout = float(raw.get("timeout", DEFAULT_TIMEOUT))
    if not 0 < max_bytes <= 16 * DEFAULT_MAX_RESPONSE or not 0 < timeout <= 120:
        raise ToolError("max_response_bytes or timeout out of range")
    return HttpSpec(origin, parsed.hostname, header.strip(), value, tuple(rules), max_bytes, timeout)


def _check_path(path: str) -> None:
    if not path.startswith("/") or "\\" in path or "?" in path or "#" in path:
        raise ToolError("path must start with '/' and carry no query or fragment; "
                        "use `query` for parameters")
    if "//" in path or _ENCODED_TRICKS.search(path):
        raise ToolError("path must not contain '//' or encoded dots or slashes")
    if any(seg in (".", "..") for seg in path.split("/")):
        raise ToolError("path must not contain '.' or '..' segments")
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in path):
        raise ToolError("path must not contain spaces or control characters")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect could send the request, key included, to another host."""

    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


class HttpRequestTool:
    """One tool per HTTP scope, named `<scope>.request`."""

    def __init__(self, spec: HttpSpec, scope: str, *, ssl_context: ssl.SSLContext | None = None) -> None:
        self.spec = spec
        self.name = f"{scope}.request"
        allowed = ", ".join(f"{r.method} {r.path}" for r in spec.rules)
        self.description = (
            f"Call {spec.base_url} from inside a confidential enclave. The API key "
            f"is added inside the enclave and never returned. Allowed: {allowed}. "
            "The response is attested."
        )
        # Tests pass a context trusting a local CA. In the image this is the
        # default: the CA store in the measured root filesystem.
        context = ssl_context or ssl.create_default_context()
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),  # ignore *_PROXY from the environment
            urllib.request.HTTPSHandler(context=context),
            _NoRedirect(),
        )

    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "method": {"type": "string", "enum": sorted({r.method for r in self.spec.rules})},
                "path": {"type": "string", "description": "path on the allowed host, e.g. /v1/balance"},
                "query": {"type": "object", "description": "query parameters"},
                "json": {"type": "object", "description": "JSON body"},
                "form": {"type": "object", "description": "form-encoded body"},
                "headers": {"type": "object", "description": "Accept, Content-Type or Idempotency-Key only"},
            },
            "required": ["path"],
        }

    def call(self, arguments: dict[str, Any]) -> dict[str, Any]:
        method = str(arguments.get("method", "GET")).upper()
        path = arguments.get("path")
        if not isinstance(path, str):
            raise ToolError("`path` is required and must be a string")
        _check_path(path)
        if not any(rule.matches(method, path) for rule in self.spec.rules):
            raise ToolError(f"{method} {path} is not on this scope's allow list")

        query = arguments.get("query") or {}
        if not isinstance(query, dict):
            raise ToolError("`query` must be an object")
        url = self.spec.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode(query, doseq=True)

        headers = {"Accept": "application/json"}
        for key, value in (arguments.get("headers") or {}).items():
            if str(key).lower() in AGENT_HEADERS and isinstance(value, str) and "\n" not in value:
                headers[str(key)] = value
        data = None
        if arguments.get("json") is not None and arguments.get("form") is not None:
            raise ToolError("send `json` or `form`, not both")
        if arguments.get("json") is not None:
            data = json.dumps(arguments["json"]).encode()
            headers["Content-Type"] = "application/json"
        elif arguments.get("form") is not None:
            if not isinstance(arguments["form"], dict):
                raise ToolError("`form` must be an object")
            data = urllib.parse.urlencode(arguments["form"], doseq=True).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if data is not None and method in ("GET", "HEAD"):
            raise ToolError(f"{method} takes no body")

        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        # Added last, so nothing the agent sent can replace it.
        request.add_unredirected_header(self.spec.auth_header, self.spec.auth_value)

        try:
            with self._opener.open(request, timeout=self.spec.timeout) as response:
                status, response_headers = response.status, response.headers
                body = response.read(self.spec.max_response_bytes + 1)
        except urllib.error.HTTPError as exc:  # 4xx and 5xx still carry an answer
            status, response_headers = exc.code, exc.headers
            body = exc.read(self.spec.max_response_bytes + 1) if exc.fp else b""
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ToolError(self._redact(f"request to {self.spec.host} failed: {exc}")) from None

        truncated = len(body) > self.spec.max_response_bytes
        body = body[: self.spec.max_response_bytes]
        content_type = response_headers.get("Content-Type", "") if response_headers else ""
        text = self._redact(body.decode("utf-8", errors="replace"))
        parsed: Any = text
        if "json" in content_type and not truncated:
            try:
                parsed = json.loads(text)
            except ValueError:
                pass
        result: dict[str, Any] = {
            "request": {"method": method, "url": url},
            "status": status,
            "content_type": content_type,
            "body": parsed,
        }
        if 300 <= status < 400:
            result["redirect_not_followed"] = self._redact(response_headers.get("Location", ""))
        if truncated:
            result["truncated"] = True
        return result

    def _redact(self, text: str) -> str:
        """An API that echoes the key back must not hand it to the agent."""
        value = self.spec.auth_value
        text = text.replace(value, REDACTED)
        # The bare token as well, for a value like "Bearer sk_..."
        token = value.split(" ", 1)[-1]
        if len(token) >= 8:
            text = text.replace(token, REDACTED)
        return text
