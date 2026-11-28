#!/usr/bin/env python3
"""
lib_auth.py - pluggable login strategies -> ready session/creds for the authed
2nd-account default. Fulfils the login half of the planned lib_auth.py.

  wallet_login_evm(challenge, priv=None)   EIP-191 personal_sign a login challenge
                                           (the class that PAID: hibachi #84332 replay ATO).
                                           priv=None -> a fresh disposable attacker wallet.
  siwe_message(...)                        build a canonical EIP-4361 SIWE string
  recover_evm(challenge, signature)        the verifier's ecrecover (and the self-test)
  wallet_login_substrate(challenge, seed)  SR25519/ED25519 sign-in (Substrate wallets)
  session_from_state(state.json)           curl_cffi session preloaded with a
                                           lib_browser storage_state - clear the wall / log
                                           in with the browser, then probe fast with curl
  form_login(session, url, fields, csrf_from=...)   cookie/CSRF form login

Do not hardcode a real private key; these mint disposable wallets. Timestamps: pass
issued_at explicitly (the clock is not readable here).

CLI:  lib_auth.py evm-sign <challenge> [priv] | substrate-sign <challenge> | selfcheck
"""
import json, os, re, sys


def _0x(b):
    if isinstance(b, str):
        return b if b.startswith("0x") else "0x" + b
    return "0x" + bytes(b).hex()


def wallet_login_evm(challenge, priv=None):
    """Sign an EIP-191 (personal_sign) login challenge. Returns {address, signature,
    priv, challenge}. challenge = the exact string the server issued."""
    from eth_account import Account
    from eth_account.messages import encode_defunct
    acct = Account.from_key(priv) if priv else Account.create()
    sig = Account.sign_message(encode_defunct(text=challenge), acct.key)
    return {"address": acct.address, "signature": _0x(sig.signature),
            "priv": _0x(acct.key), "challenge": challenge}


def recover_evm(challenge, signature):
    """Recover the signer of an EIP-191 sig - what the verifier runs; if it returns an
    address the attacker controls but the server binds to the victim, that is the replay."""
    from eth_account import Account
    from eth_account.messages import encode_defunct
    return Account.recover_message(encode_defunct(text=challenge), signature=signature)


def siwe_message(domain, address, uri, nonce, statement="Sign in with Ethereum",
                 chain_id=1, version="1", issued_at="1970-01-01T00:00:00.000Z"):
    """Canonical EIP-4361 SIWE message. Missing a bound field (domain, uri, nonce,
    chainId) in what the server actually signs is the replay seam - build both the
    honest and the tampered message to prove it."""
    return (f"{domain} wants you to sign in with your Ethereum account:\n{address}\n\n"
            f"{statement}\n\nURI: {uri}\nVersion: {version}\nChain ID: {chain_id}\n"
            f"Nonce: {nonce}\nIssued At: {issued_at}")


def wallet_login_substrate(challenge, seed=None, crypto="sr25519"):
    """SR25519/ED25519 sign-in for Substrate wallets. seed=None mints a fresh keypair."""
    from substrateinterface import Keypair, KeypairType
    kt = KeypairType.SR25519 if crypto == "sr25519" else KeypairType.ED25519
    if seed is None:
        mn = Keypair.generate_mnemonic()
        kp, minted = Keypair.create_from_mnemonic(mn, crypto_type=kt), mn
    elif isinstance(seed, str) and seed.strip().lower().startswith("0x"):
        kp, minted = Keypair.create_from_seed(seed.strip(), crypto_type=kt), None    # hex seed
    elif isinstance(seed, str) and len(seed.split()) in (12, 15, 18, 21, 24):
        kp, minted = Keypair.create_from_mnemonic(seed, crypto_type=kt), None        # BIP39 phrase
    else:
        kp, minted = Keypair.create_from_uri(seed, crypto_type=kt), None             # //Alice style
    payload = challenge.encode() if isinstance(challenge, str) else challenge
    sig = kp.sign(payload)
    return {"address": kp.ss58_address, "signature": _0x(sig),
            "public_key": _0x(kp.public_key),
            "mnemonic": minted,  # only a minted throwaway is echoed; a provided secret is never returned
            "verified": kp.verify(payload, sig)}


def session_from_state(state_json, impersonate="chrome124"):
    """curl_cffi session preloaded with cookies from a lib_browser storage_state.json.
    Bridges the browser (clears the bot-wall / logs in) to curl (fast probing)."""
    from curl_cffi import requests as creq
    s = creq.Session(impersonate=impersonate)
    data = json.load(open(state_json)) if isinstance(state_json, str) else state_json
    for c in data.get("cookies", []):
        try:
            s.cookies.set(c["name"], c["value"], domain=c.get("domain"), path=c.get("path", "/"))
        except Exception:
            pass
    for o in data.get("origins", []):
        pass  # localStorage is not a cookie; the caller re-injects it in-browser if needed
    return s


def authed_session(account, scope_file=None, bearer=None, cookies=None,
                   header_name="Authorization", impersonate="chrome124"):
    """Build a session carrying an account's auth - the bridge from provision to BOLA.
    account = a provision_pair / simple_register / load_account dict. Uses the scope-gated
    lib_egress session when scope_file is given (every request scope-checked), else a plain
    curl_cffi session. Attaches a bearer (account token or `bearer`) + cookies."""
    if scope_file:
        # the hunter asked for scope-gating; a failure must RAISE, never silently downgrade to
        # an ungated session (that would probe out of scope believing it is gated).
        import os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from bbtools.lib_egress import make_session
        s = make_session(scope_file)
    else:
        from curl_cffi import requests as creq
        s = creq.Session(impersonate=impersonate)
    acct = account if isinstance(account, dict) else {}
    tok = bearer or acct.get("token") or acct.get("auth_token") or acct.get("idToken")
    if tok:
        val = tok if str(tok).lower().startswith("bearer") or header_name != "Authorization" else f"Bearer {tok}"
        s.headers.update({header_name: val})
    for k, v in (cookies or acct.get("cookies") or {}).items():
        try:
            s.cookies.set(k, v)
        except Exception:
            pass
    return s


def form_login(session, url, fields, csrf_from=None, csrf_field="csrf", csrf_regex=None):
    """POST a login form. If csrf_from is a URL, GET it and lift the token first
    (csrf_regex group 1, else a hidden input named csrf_field)."""
    if csrf_from:
        html = session.get(csrf_from, timeout=20).text
        m = (re.search(csrf_regex, html) if csrf_regex
             else re.search(r'name=["\']%s["\'][^>]*value=["\']([^"\']+)' % re.escape(csrf_field), html))
        if m:
            fields = {**fields, csrf_field: m.group(1)}
    return session.post(url, data=fields, timeout=20)


def _selfcheck():
    # EVM sign -> recover round-trip (proves the signature is valid)
    ch = "example.com wants you to sign in\nNonce: abc123"
    w = wallet_login_evm(ch)
    assert recover_evm(ch, w["signature"]).lower() == w["address"].lower(), "evm recover"
    w2 = wallet_login_evm("x", priv=w["priv"])
    assert w2["address"] == w["address"], "priv reuse deterministic"
    # SIWE shape
    m = siwe_message("app.example.com", w["address"], "https://app.example.com", "deadbeef",
                     issued_at="2026-01-01T00:00:00Z")
    assert "wants you to sign in" in m and "Nonce: deadbeef" in m and w["address"] in m
    # Substrate sign/verify (optional backend - skip cleanly if not installed)
    try:
        sv = wallet_login_substrate("challenge-xyz")
        assert sv["verified"] is True, "substrate verify"
        # a provided mnemonic reproduces the address (the seed path, not just mint) + no secret echo
        sv2 = wallet_login_substrate("x", seed=sv["mnemonic"])
        assert sv2["address"] == sv["address"] and sv2["mnemonic"] is None, "substrate seed path"
        sub = "substrate-verify"
    except ImportError:
        sub = "substrate-SKIP(no substrateinterface)"
    # storage_state cookie load
    import tempfile
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".json").name
    json.dump({"cookies": [{"name": "sid", "value": "V", "domain": "x.com", "path": "/"}]}, open(f, "w"))
    try:
        s = session_from_state(f)
        assert s.cookies.get("sid") == "V", "state cookie load"
    finally:
        os.remove(f)
    # authed_session bridges an account dict -> a session with the bearer attached
    a = authed_session({"token": "T123"})
    assert a.headers.get("Authorization") == "Bearer T123", "authed_session bearer"
    a2 = authed_session({"auth_token": "bearer xyz"})
    assert a2.headers.get("Authorization") == "bearer xyz", "authed_session preserves prefix"
    print(f"SELFCHECK OK  evm sign/recover, siwe, {sub}, state-load, authed_session pass")


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return
    if argv[0] == "selfcheck":
        return _selfcheck()
    if argv[0] == "evm-sign":
        print(json.dumps(wallet_login_evm(argv[1], argv[2] if len(argv) > 2 else None), indent=2))
        return
    if argv[0] == "substrate-sign":
        print(json.dumps(wallet_login_substrate(argv[1]), indent=2))
        return
    print("unknown cmd:", argv[0])
    print(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
