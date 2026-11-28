#!/usr/bin/env python3
"""Robustness check: concurrent burst through the phone SOCKS, serial control, and exposure check."""
import socket, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
from curl_cffi import requests

P = "socks5h://127.0.0.1:1081"
U = "https://ipinfo.io/ip"


def one(_):
    try:
        return requests.get(U, proxies={"http": P, "https": P}, timeout=30, impersonate="chrome124").text.strip()
    except Exception as e:
        return "ERR:" + str(e)[:60]


serial = [one(0) for _ in range(4)]
with ThreadPoolExecutor(24) as ex:
    burst = list(ex.map(one, range(24)))
print("serial ", serial)
print("burst  ok=%d/24 distinct=%s" % (sum(not b.startswith("ERR") for b in burst), sorted(set(burst))))
# exposure: the phone's wlan address must NOT accept the proxy port
ip = subprocess.run(["adb", "shell", "ip -4 addr show wlan0"], capture_output=True, text=True).stdout
ip = ip.split("inet ")[1].split("/")[0] if "inet " in ip else None
if ip:
    s = socket.socket(); s.settimeout(3)
    print("wlan %s:1081 reachable from LAN:" % ip, s.connect_ex((ip, 1081)) == 0)
