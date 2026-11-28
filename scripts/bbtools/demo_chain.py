#!/usr/bin/env python3
"""
demo_chain.py - the unauth -> authed 2nd-account -> BOLA chain, runnable end to end on
mocks (no network, no target). Copy the real calls into a hunt; run it as-is to prove the
libs still compose (it imports all four, so an interface drift fails here). This is the
workflow most hunts skip - only ~42% ever provision the authed 2nd account where High/Crit live.

Run: python3 scripts/bbtools/demo_chain.py
"""
import os, shutil, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from bbtools.lib_unauth import classify                       # noqa: E402
from bbtools.lib_auth import wallet_login_evm, recover_evm    # noqa: E402
from bbtools.lib_provision import save_account, load_account  # noqa: E402
from bbtools.bola_discriminant import run as bola_run, _MockSess  # noqa: E402


def main():
    print("STAGE 1  unauth strip-auth diff (SPA-200 discipline)")
    # hunt: strip_auth_diff(routes, make_session(SCOPE))  -- here, sample responses:
    shell = {"status": 200, "len": 5000, "ctype": "text/html", "body": "<html>"}
    data = {"status": 200, "len": 700, "ctype": "application/json", "body": "{...}"}
    r404 = {"status": 404, "len": 10, "ctype": "text/html", "body": ""}
    print("  /app/foo (html==sibling)  ->", classify(shell, shell), "(SPA shell, NOT a lead)")
    print("  /api/user/9 (json,sib404) ->", classify(data, r404), "(the lead -> hunt authed)")

    print("STAGE 2  provision + log in the authed 2nd account")
    # hunt: A,B = provision_pair(handle, lambda ib: simple_register(url, inbox=ib))
    ch = "app.example.com wants you to sign in\nNonce: n1"
    w = wallet_login_evm(ch)                                   # disposable attacker wallet
    assert recover_evm(ch, w["signature"]).lower() == w["address"].lower(), "sig must recover"
    print("  wallet A signed; verifier ecrecover ==", w["address"][:12], "OK")
    save_account("_demo", "A", {"email": "a@x", "addr": w["address"]})
    save_account("_demo", "B", {"email": "b@x", "addr": "0xBBB"})
    print("  stored targets/_demo/accounts/{A,B}.json; reload A ->", load_account("_demo", "A")["email"])

    print("STAGE 3  BOLA distinct-gate + paired cross-user read/write")
    store = {"https://api/obj/B": "B-private-ssn-123"}
    A, B = _MockSess("A-id", store), _MockSess("B-id", store)
    cap = bola_run(A, B, lambda s: s.id, "https://api/obj/B",
                   write_body={"name": "x"}, read_b_url="https://api/obj/B",
                   expect_field="ssn", revert_body={"name": "orig"})
    print("  distinct-gate:", cap["distinct"],
          "| A-read-B private field:", cap["read"]["has_field"],
          "| A-write changed B's view:", cap["write"]["changed"],
          "| reverted:", cap.get("reverted"))

    shutil.rmtree("targets/_demo", ignore_errors=True)
    assert cap["distinct"] and cap["read"]["has_field"] and cap["write"]["changed"]
    print("\nCHAIN OK  unauth-lead -> authed A/B -> cross-user read+write receipt.")
    print("Replace the mocks with make_session(SCOPE) + real routes/objects to run it for real.")


if __name__ == "__main__":
    main()
