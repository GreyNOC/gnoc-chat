"""Small HTTP helpers for the adapters: JSON in, JSON out, a timeout on every call, tokens kept out of errors."""
import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request

UA = "gnoc-gateway/1"


class NetError(Exception):
    """An adapter call failed. The text never carries the URL, because the Telegram token lives in the URL."""

    def __init__(self, msg, status=None, retry_after=None):
        super().__init__(msg)
        self.status = status
        self.retry_after = retry_after


def is_loopback(host):
    host = (host or "").strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_base(url, what):
    """https, or plain http only to this machine (the in-process fakes the tests start)."""
    p = urllib.parse.urlsplit(url or "")
    if p.scheme == "https" and p.hostname:
        return url.rstrip("/")
    if p.scheme == "http" and is_loopback(p.hostname or ""):
        return url.rstrip("/")
    raise ValueError(f"{what} must be an https:// URL (plain http is allowed only to this machine)")


def post_json(url, body, headers=None, timeout=30.0):
    """POST a JSON body, return the decoded JSON reply. HTTP errors with a JSON body are returned, not raised,
    so the caller can read the platform's own `ok: false` description."""
    data = json.dumps(body if body is not None else {}).encode()
    h = {"Content-Type": "application/json; charset=utf-8", "User-Agent": UA}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
            got = json.loads(raw.decode("utf-8", "replace"))
            if isinstance(got, dict):
                got.setdefault("_http_status", e.code)
                return got
        except (ValueError, OSError):
            pass
        raise NetError(f"HTTP {e.code}", status=e.code,
                       retry_after=_int(e.headers.get("Retry-After") if e.headers else None)) from None
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        reason = getattr(e, "reason", e)
        raise NetError(f"network: {type(reason).__name__}") from None
    try:
        got = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        raise NetError("the reply was not JSON") from None
    if not isinstance(got, dict):
        raise NetError("the reply was not a JSON object")
    return got


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
