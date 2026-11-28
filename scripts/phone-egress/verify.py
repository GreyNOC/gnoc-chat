#!/usr/bin/env python3
"""Verify the phone SOCKS egress: IP + org via the proxy vs the laptop's direct egress.
Usage: verify.py [socks_url]   (default socks5h://127.0.0.1:1081)"""
import sys
from curl_cffi import requests

PROXY = sys.argv[1] if len(sys.argv) > 1 else "socks5h://127.0.0.1:1081"
URL = "https://ipinfo.io/json"


def get(proxy):
    try:
        r = requests.get(URL, proxies={"http": proxy, "https": proxy} if proxy else None,
                         timeout=25, impersonate="chrome124")
        j = r.json()
        return j.get("ip"), j.get("org"), j.get("city"), j.get("country")
    except Exception as e:
        return "ERR", str(e)[:150], None, None


phone, direct = get(PROXY), get(None)
print("phone  :", phone)
print("laptop :", direct)
sys.exit(0 if phone[0] not in (None, "ERR") else 1)
