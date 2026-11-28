"""gnoc_web.py - reading the public web (vendor docs, advisories, prior art) and checking Burp's Proxy history.

fetch(url)          GET a public page and return readable text. Refuses private, loopback and link-local
                    addresses; a URL on the ACTIVE program's scope is not fetched here (the agent must use
                    http_request so it is captured, rate-limited and identified as research traffic).
search(query)       DuckDuckGo's HTML endpoint, no API key: [(title, url, snippet)].
burp_history(method, url)  is this exchange in Burp's Proxy history? (raw Burp panels for a filing come from
                    Proxy history; Repeater normalises paths and fakes negatives on path-shape claims).
"""
import html
import ipaddress
import os
import re
import socket
import time
import urllib.parse

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"


def public_host(host):
    """True only when every address the host resolves to is public."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    cgnat = ipaddress.ip_network("100.64.0.0/10")  # carrier NAT: not "private" to ipaddress, not public either
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast \
                or ip.is_unspecified or (ip.version == 4 and ip in cgnat) \
                or (ip.version == 6 and ip.ipv4_mapped is not None and not public_ip4(ip.ipv4_mapped)):
            return False
    return bool(infos)


def public_ip4(ip):
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
                or ip.is_unspecified or ip in ipaddress.ip_network("100.64.0.0/10"))


def to_text(body, ctype=""):
    if "html" not in (ctype or "").lower() and not re.search(r"(?i)<html|<body|<div", body[:2000]):
        return body
    body = re.sub(r"(?is)<(script|style|noscript|svg|nav|footer)\b.*?</\1>", " ", body)
    body = re.sub(r"(?i)<(br|/p|/div|/li|/h\d|/tr|/pre)\s*/?>", "\n", body)
    body = re.sub(r"(?i)<li\b[^>]*>", "\n- ", body)
    body = re.sub(r"(?s)<[^>]+>", " ", body)
    body = html.unescape(body)
    lines = [" ".join(ln.split()) for ln in body.splitlines()]
    return "\n".join(ln for ln in lines if ln)


def _get(url, timeout=25):
    from curl_cffi import requests as creq
    # redirects are NOT followed: the destination of a hop was only checked after it had been fetched. A 3xx
    # comes back as its status + Location and the caller (or the model) decides whether to fetch that URL,
    # which then goes through the same public-host check as any other.
    return creq.get(url, impersonate="chrome124", timeout=timeout, allow_redirects=False, headers={"User-Agent": UA})


def fetch(url, in_scope=None):
    """(ok, text). in_scope(host) -> bool says whether the host belongs to the active program."""
    u = urllib.parse.urlparse(url or "")
    if u.scheme not in ("http", "https") or not u.hostname:
        return False, "only http(s) URLs"
    if in_scope and in_scope(u.hostname):
        return False, (f"{u.hostname} is in the active program's scope: use http_request (captured, rate-limited, "
                       "identified) instead of web_fetch")
    if not public_host(u.hostname):
        return False, f"refused: {u.hostname} does not resolve to public addresses only"
    try:
        r = _get(url)
        if r.status_code in (429, 503):
            # one polite retry: Wikimedia answered a single fetch with 429 and the model gave the source up
            # (2026-10-24); a minute later the same request was a 200
            ra = str(r.headers.get("retry-after") or "")
            time.sleep(min(8.0, float(ra)) if ra.replace(".", "", 1).isdigit() else 3.0)
            r = _get(url)
    except Exception as e:
        return False, f"fetch failed: {type(e).__name__}: {e}"
    if 300 <= r.status_code < 400:
        loc = r.headers.get("location", "")
        return True, f"{r.status_code} redirect to {loc[:300]} (not followed; web_fetch that URL if you want it)"
    text = to_text(r.text or "", r.headers.get("content-type", ""))
    return True, f"{r.status_code} {r.url}\n\n{text}"


def search(query, n=8):
    try:
        r = _get("https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(query))
    except Exception as e:
        return None, f"search failed: {type(e).__name__}: {e}"
    out = []
    for m in re.finditer(r'(?s)<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>.*?'
                         r'class="result__snippet"[^>]*>(.*?)</a>', r.text or ""):
        href = html.unescape(m.group(1))
        q = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
        url = q.get("uddg", [href])[0]
        strip = lambda x: " ".join(html.unescape(re.sub(r"(?s)<[^>]+>", "", x)).split())
        out.append((strip(m.group(2)), url, strip(m.group(3))))
        if len(out) >= n:
            break
    return out, "" if out else "no results (or the search page changed shape / rate-limited)"


# Burp's MCP extension serves the legacy SSE transport at its root; BURP_MCP overrides the address.
BURP_MCP = os.environ.get("BURP_MCP", "http://127.0.0.1:9876").rstrip("/")


def _burp_call(tool, arguments, timeout=15.0):
    """One tool call on Burp's MCP server, returning the tools/call result. It used to load
    scripts/burp-mcp-cli.py, which only the operator's workspace has, so on any other install the import failed
    and the caller reported it as "Burp MCP unreachable", sending the user to check a Burp that was fine. The SSE
    client now lives in gnoc_mcp; a session per lookup, because a cached one held a reader thread and a server
    session open for the life of the chat and died silently on the stream's idle timeout."""
    import gnoc_mcp
    # handshake + call stay inside the 30 s deadline the tool layer puts around this lookup
    t = gnoc_mcp._session({"transport": "sse", "url": BURP_MCP}, timeout=min(timeout, 8.0))
    try:
        return t.request("tools/call", {"name": tool, "arguments": arguments}, timeout=timeout)
    finally:
        t.close()


def burp_history(method, url):
    """(found, detail). Looks up 'METHOD /path' (exact bytes) in Burp's Proxy history over its MCP server."""
    u = urllib.parse.urlsplit(url)
    target = (u.path or "/") + (("?" + u.query) if u.query else "")
    rx = re.escape(f"{method.upper()} {target} HTTP") + r"[\s\S]*?" + re.escape(f"Host: {u.netloc}")
    try:
        res = _burp_call("get_proxy_http_history_regex", {"regex": rx, "count": 3, "offset": 0})
    except Exception as e:  # noqa: BLE001 - the panel check reports, it never takes the turn down
        return None, (f"Burp MCP unreachable at {BURP_MCP} ({type(e).__name__}: {str(e)[:160]}); is Burp running "
                      "with the MCP Server extension enabled? (BURP_MCP=<url> if it listens elsewhere)")
    text = " ".join(str(c.get("text", "")) for c in (res.get("content") or []) if isinstance(c, dict))
    found = bool(text.strip()) and "no " not in text.strip().lower()[:12] and target in text
    return found, ("in Proxy history" if found else "NOT in Proxy history")
