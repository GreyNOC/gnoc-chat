#!/usr/bin/env python3
"""ja3_forward_proxy - mitmproxy addon that re-issues every request through curl_cffi's
Chrome TLS/JA3 fingerprint, so Burp Suite (whose Java TLS is fingerprint-blocked by
Akamai / DataDome / PerimeterX) can reach a bot-managed origin from Repeater/Intruder.

Chain:
  Burp Repeater --(upstream proxy)--> mitmdump:8083 --(this addon)--> curl_cffi(chrome120) --> origin

The addon sets flow.response inside the request hook, so mitmproxy NEVER opens its own
upstream socket - the only ClientHello that reaches the origin is curl_cffi's spoofed
Chrome one. Burp keeps full Repeater editing; the cookies/headers Burp sends are forwarded
verbatim (only hop-by-hop headers are dropped).

Run:
  mitmdump -s scripts/bbtools/ja3_forward_proxy.py --listen-host 127.0.0.1 -p 8083 \
           --ssl-insecure --set connection_strategy=lazy

Burp: Settings > Network > Connections > Upstream Proxy Servers > Add
        Destination host: *        Proxy host: 127.0.0.1        Proxy port: 8083
      If Burp flags the cert, import ~/.mitmproxy/mitmproxy-ca-cert.der (Burp already
      ignores cert errors in Repeater by default, so this is usually optional).

Change IMPERSONATE below to match the target's expected browser (chrome124, safari17_0, etc).
"""
from mitmproxy import http
from curl_cffi import requests as R

IMPERSONATE = "chrome120"
_DROP_REQ = {"host", "content-length", "proxy-connection", "connection", "proxy-authorization"}
_DROP_RESP = {"content-encoding", "transfer-encoding", "content-length", "connection"}


def request(flow: http.HTTPFlow) -> None:
    rq = flow.request
    headers = {k: v for k, v in rq.headers.items() if k.lower() not in _DROP_REQ}
    body = rq.raw_content or None
    try:
        resp = R.request(
            rq.method, rq.url, headers=headers, data=body,
            impersonate=IMPERSONATE, timeout=40, allow_redirects=False, verify=True,
        )
    except Exception as e:  # surface the failure to Burp instead of hanging the tab
        flow.response = http.Response.make(
            502, f"ja3_forward_proxy error: {e}".encode(), {"content-type": "text/plain"}
        )
        return
    out_headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in _DROP_RESP]
    flow.response = http.Response.make(resp.status_code, resp.content, out_headers)
