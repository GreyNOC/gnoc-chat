#!/usr/bin/env python3
"""immunefi-fetch.py <slug> [--stdin] [--json] [--self-check]

Pull an Immunefi program's RULES and ASSETS with ZERO auth. Immunefi is a Next.js
App-Router SPA: the program data streams inline in the page as RSC flight chunks
(self.__next_f.push([1,"..."])). This joins+unescapes those chunks and extracts the
in-scope asset list (contract addresses + chains), the payout table, KYC flag,
primacy, launch date, and the out-of-scope prose. No API token, no key, no login.

Usage:
  scripts/immunefi-fetch.py veda                 # fetch live + print JSON
  curl -s <page> | scripts/immunefi-fetch.py veda --stdin
  scripts/immunefi-fetch.py --self-check         # offline parse test

immunefi-scope.sh calls this to auto-fill targets/<slug>/SCOPE.txt + PROGRAM.md.
"""
import sys, re, json, urllib.request

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

# explorer host -> (chain name, a public archive RPC you can fork from). Extend as needed.
EXPLORER = {
    "etherscan.io": ("ethereum", "https://eth.llamarpc.com"),
    "app.example.com": ("ink", "https://app.example.com"),
    "scrollscan.com": ("scroll", "https://rpc.scroll.io"),
    "basescan.org": ("base", "https://mainnet.base.org"),
    "arbiscan.io": ("arbitrum", "https://arb1.arbitrum.io/rpc"),
    "polygonscan.com": ("polygon", "https://polygon-rpc.com"),
    "optimistic.etherscan.io": ("optimism", "https://mainnet.optimism.io"),
    "snowtrace.io": ("avalanche", "https://api.avax.network/ext/bc/C/rpc"),
    "bscscan.com": ("bsc", "https://bsc-dataseed.binance.org"),
    "lineascan.build": ("linea", "https://rpc.linea.build"),
    "blastscan.io": ("blast", "https://rpc.blast.io"),
    "berascan.com": ("berachain", "https://rpc.berachain.com"),
    "gnosisscan.io": ("gnosis", "https://rpc.gnosischain.com"),
    "celoscan.io": ("celo", "https://forno.celo.org"),
}


def rsc_blob(html):
    """Join + unescape every self.__next_f.push([1,"..."]) string arg into one blob."""
    chunks = re.findall(r'self\.__next_f\.push\(\[1,"((?:[^"\\]|\\.)*)"\]\)', html)
    return "".join(json.loads('"' + c + '"') for c in chunks)


def _grab_array(s, key):
    """Return the JSON array value of "key":[ ... ] via bracket matching, or None."""
    i = s.find(f'"{key}":[')
    if i < 0:
        return None
    j = s.find('[', i)
    depth = 0
    for k in range(j, len(s)):
        c = s[k]
        if c == '[':
            depth += 1
        elif c == ']':
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(s[j:k + 1])
                except json.JSONDecodeError:
                    return None
    return None


def parse(html):
    blob = rsc_blob(html)
    src = blob if '"assets":[' in blob else html  # fall back to raw if not chunked
    assets_raw = _grab_array(src, "assets") or []
    rewards_raw = _grab_array(src, "rewards") or []

    ONCHAIN = {"smart_contract", "blockchain_dlt"}
    assets, chains = [], {}
    for a in assets_raw:
        url = a.get("url", "") or ""
        typ = a.get("type")
        host_m = re.search(r'https?://([^/]+)', url)
        host = host_m.group(1) if host_m else ""
        is_source = bool(re.search(r'(github\.com|gitlab\.com|/tree/|/blob/)', url))
        onchain = (not is_source) and (typ in ONCHAIN or "0x" in url or "/address/" in url or "/account" in url)
        # address: EVM 0x, else the explorer path tail (Solana/Stacks/etc. base58/other ids)
        addr_m = re.search(r'0x[a-fA-F0-9]{40}', url)
        if addr_m:
            address = addr_m.group(0)
        elif onchain:
            tail = re.sub(r'[?#].*$', '', url).rstrip("/").split("/")[-1]
            address = tail if re.fullmatch(r'[A-Za-z0-9._:-]{25,}', tail or "") else None
        else:
            address = None
        chain, rpc = (EXPLORER.get(host, (host.replace("scan", "").replace("explorer.", "").split(".")[0], ""))
                      if onchain else (None, ""))
        assets.append({
            "address": address,
            "name": a.get("description"),
            "type": typ,
            "chain": chain,
            "url": url,
            "onchain": onchain,
            "primacyOfImpact": a.get("isPrimacyOfImpact", False),
        })
        if chain and address:
            chains.setdefault(chain, {"rpc": rpc, "count": 0})
            chains[chain]["count"] += 1

    payouts = []
    for r in rewards_raw:
        if "maxReward" in r:
            payouts.append({
                "severity": r.get("severity"),
                "assetType": r.get("assetType"),
                "min": r.get("minReward"),
                "max": r.get("maxReward"),
                "model": r.get("rewardModel"),
                "pctFunds": r.get("rewardCalculationPercentage"),
            })

    def sfind(key, cast=str):
        m = re.search(re.escape(f'"{key}":') + r'("(?:[^"\\]|\\.)*"|true|false|null|-?\d+(?:\.\d+)?)', src)
        if not m:
            return None
        v = m.group(1)
        try:
            return json.loads(v)
        except json.JSONDecodeError:
            return v

    return {
        "kyc": sfind("kyc"),
        "primacyOfImpact": sfind("primacyOfImpact"),
        "launchDate": sfind("launchDate"),
        "maxReward": sfind("maxReward"),
        "chains": chains,
        "payouts": payouts,
        "assets": assets,
        "asset_count": len(assets),
    }


def fetch(slug):
    url = f"https://immunefi.com/bug-bounty/{slug}/information/"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace"), url


FIXTURE = (
    'self.__next_f.push([1,"3:{\\"assets\\":[{\\"id\\":\\"x\\",\\"url\\":\\"https://etherscan.io/'
    'address/0xcaAE49fB7f74Ccfbe8a05E6104b01c097a78789f\\",\\"type\\":\\"smart_contract\\",'
    '\\"description\\":\\"Vault\\",\\"isPrimacyOfImpact\\":true}],\\"rewards\\":[{\\"severity\\":'
    '\\"critical\\",\\"assetType\\":\\"smart_contract\\",\\"maxReward\\":1000000,\\"minReward\\":'
    '100000,\\"rewardModel\\":\\"range\\",\\"rewardCalculationPercentage\\":10}],\\"kyc\\":true,'
    '\\"launchDate\\":\\"2026-01-21T15:00:08.000Z\\"}"])\n'
)


def _self_check():
    d = parse(FIXTURE)
    assert d["asset_count"] == 1, d
    assert d["assets"][0]["address"].lower() == "0xcaae49fb7f74ccfbe8a05e6104b01c097a78789f", d
    assert d["assets"][0]["chain"] == "ethereum", d
    assert d["chains"]["ethereum"]["rpc"].startswith("https://"), d
    assert d["payouts"][0]["max"] == 1000000 and d["payouts"][0]["severity"] == "critical", d
    assert d["kyc"] is True and d["launchDate"].startswith("2026-01-21"), d
    print("self-check OK")


def main():
    args = sys.argv[1:]
    if "--self-check" in args:
        _self_check()
        return
    slug = next((a for a in args if not a.startswith("--")), None)
    if not slug:
        print(__doc__)
        sys.exit(2)
    if "--stdin" in args:
        html = sys.stdin.read()
    else:
        try:
            html, _ = fetch(slug)
        except Exception as e:  # network / 403 -> let caller pipe curl in via --stdin
            print(json.dumps({"error": f"fetch failed: {e}. Retry: "
                              f"curl -sL -A '{UA}' 'https://immunefi.com/bug-bounty/{slug}/information/' "
                              f"| scripts/immunefi-fetch.py {slug} --stdin"}))
            sys.exit(1)
    print(json.dumps(parse(html), indent=2))


if __name__ == "__main__":
    main()
