#!/usr/bin/env python3
"""
onchain.py - EVM read + proof-integrity helpers for on-chain hunts (Immunefi). Read any view
fn, detect a proxy impl, read raw storage, and GATE a PoC's success on the terminal EVENT being
present (not a print) - the on-chain proof-integrity discipline. Keyless drpc RPCs. A fork PoC
still uses scaffold-fork-poc.sh; this is the read/verify layer that keeps a claim honest.

  connect(chain='eth')                   web3 on a keyless drpc RPC ('eth'/'base'/'arbitrum'/... or a url)
  call(w3, address, 'name(uint)(uint)', *args)   eth_call a view fn by human signature
  impl_slot(w3, address)                 EIP-1967 implementation address (proxy detection)
  storage(w3, address, slot)             raw storage read (hex)
  event_in_receipt(receipt, topic0)      is a terminal event present - gate a PoC on THIS, not a print
  positive_control(fn, *a)               run a known true-positive first (prove the harness can observe)

CLI: onchain.py selfcheck            offline: sig-parse, selector, event-gate
     onchain.py read <chain> <addr> <sig> [args...]   live view-fn read
"""
import re, sys

CHAINS = {"eth": "https://eth.drpc.org", "base": "https://base.drpc.org",
          "arbitrum": "https://arbitrum.drpc.org", "optimism": "https://optimism.drpc.org",
          "polygon": "https://polygon.drpc.org", "bsc": "https://bsc.drpc.org",
          "berachain": "https://berachain.drpc.org", "avalanche": "https://avalanche.drpc.org",
          "gnosis": "https://gnosis.drpc.org", "blast": "https://blast.drpc.org"}
EIP1967_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"


def connect(chain="eth"):
    from web3 import Web3
    url = CHAINS.get(chain, chain)
    return Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 25}))


def _read_group(s, open_idx):
    """s[open_idx] == '('; return (top-level types list, index after the matching ')').
    Depth-aware so tuple/struct types like (uint160,int24,uint16) are kept whole."""
    depth, out, cur = 0, [], ""
    for i in range(open_idx, len(s)):
        c = s[i]
        if c == "(":
            depth += 1
            if depth == 1:
                continue
        if c == ")":
            depth -= 1
            if depth == 0:
                if cur.strip():
                    out.append(cur.strip())
                return out, i + 1
        if depth == 1 and c == ",":
            out.append(cur.strip())
            cur = ""
            continue
        if depth >= 1:
            cur += c
    raise ValueError(f"unbalanced parens in {s!r}")


def _parse_sig(sig):
    """'transfer(address,uint256)(bool)' -> ('transfer', ['address','uint256'], ['bool']).
    Handles tuple types: 'slot0()((uint160,int24,uint16))' -> ('slot0', [], ['(uint160,int24,uint16)'])."""
    sig = sig.strip()
    m = re.match(r"^(\w+)\s*\(", sig)
    if not m:
        raise ValueError(f"bad signature: {sig}")
    name = m.group(1)
    args, j = _read_group(sig, sig.index("("))
    rets = []
    rest = sig[j:].strip()
    if rest.startswith("("):
        rets, _ = _read_group(sig, j + sig[j:].index("("))
    return name, args, rets


def _selector(name_and_args):
    from eth_utils import keccak
    return keccak(text=name_and_args)[:4]


def call(w3, address, sig, *args):
    """eth_call a view fn by human signature. Returns the decoded value (or tuple)."""
    from eth_abi import encode, decode
    name, argtypes, rettypes = _parse_sig(sig)
    data = _selector(f"{name}({','.join(argtypes)})") + (encode(argtypes, list(args)) if argtypes else b"")
    raw = w3.eth.call({"to": w3.to_checksum_address(address), "data": "0x" + data.hex()})
    out = decode(rettypes, raw) if rettypes else raw
    return out[0] if isinstance(out, (list, tuple)) and len(out) == 1 else out


def impl_slot(w3, address):
    """EIP-1967 implementation address (0x0 if not that proxy shape) - proxy detection."""
    raw = w3.eth.get_storage_at(w3.to_checksum_address(address), EIP1967_IMPL)
    return w3.to_checksum_address("0x" + raw.hex()[-40:])


def storage(w3, address, slot):
    raw = w3.eth.get_storage_at(w3.to_checksum_address(address), slot)
    return "0x" + raw.hex()


def event_in_receipt(receipt, topic0):
    """Is a log with topics[0] == topic0 present. Gate a PoC's success on THIS (the terminal
    event emitted), never on a print() - the on-chain proof-integrity rule."""
    t = (topic0 if topic0.startswith("0x") else "0x" + topic0).lower()
    for log in (receipt.get("logs") if isinstance(receipt, dict) else receipt.logs) or []:
        topics = log.get("topics") if isinstance(log, dict) else log.topics
        if topics:
            first = topics[0]
            first = first if isinstance(first, str) else "0x" + bytes(first).hex()
            if first.lower() == t:
                return True
    return False


def positive_control(fn, *args, **kw):
    """Run a known true-positive first; raise if it does NOT fire (proves the harness can
    observe a real positive on this surface before you trust a DEAD)."""
    r = fn(*args, **kw)
    if not r:
        raise AssertionError("positive control did NOT fire - harness cannot observe a true positive")
    return r


def _selfcheck():
    name, at, rt = _parse_sig("transfer(address,uint256)(bool)")
    assert name == "transfer" and at == ["address", "uint256"] and rt == ["bool"], (name, at, rt)
    # tuple / struct types must parse (Uniswap-v3 slot0, struct args)
    n2, a2, r2 = _parse_sig("slot0()((uint160,int24,uint16))")
    assert n2 == "slot0" and a2 == [] and r2 == ["(uint160,int24,uint16)"], (n2, a2, r2)
    n3, a3, r3 = _parse_sig("exactInput((bytes,address,uint256))(uint256)")
    assert a3 == ["(bytes,address,uint256)"] and r3 == ["uint256"], (a3, r3)
    assert _selector("transfer(address,uint256)").hex() == "a9059cbb", _selector("transfer(address,uint256)").hex()
    topic = "0x" + "ab" * 32
    rcpt = {"logs": [{"topics": [topic, "0x00"]}]}
    assert event_in_receipt(rcpt, topic) and not event_in_receipt(rcpt, "0x" + "cd" * 32)
    assert event_in_receipt(rcpt, "ab" * 32), "bare-hex topic must normalize + match"
    assert positive_control(lambda: True) is True
    try:
        positive_control(lambda: False)
        raise SystemExit("positive_control failed to raise on a false positive")
    except AssertionError:
        pass
    print("SELFCHECK OK  sig-parse, selector(transfer=a9059cbb), event-gate, positive-control pass")


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return
    if argv[0] == "selfcheck":
        return _selfcheck()
    if argv[0] == "read":
        w3 = connect(argv[1])
        val = call(w3, argv[2], argv[3], *argv[4:])
        print(val)
        return
    print("unknown cmd:", argv[0])
    print(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
