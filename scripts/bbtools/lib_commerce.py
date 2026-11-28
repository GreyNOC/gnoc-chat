#!/usr/bin/env python3
"""
lib_commerce.py - test-payment primitives + checkout walk for commerce BOLA/race hunting.

WHY: the authed + 2nd-account + PAID-TRANSACTION state is where commerce High/Crit bugs live
(order BOLA, price-tamper, coupon-race, seller-authz drift) but provisioning stopped at two
identical buyers.  This fills three gaps:
  1. TEST CARD / PM - Stripe + PayPal sandbox instruments (never a real PAN, never a real charge)
  2. CHECKOUT WALK  - add-to-cart -> checkout -> pay on an existing authed session
  3. CALLER-USABLE  - constants + one thin walk; no speculative multi-gateway framework

SECURITY: sandbox/test values ONLY.  Never pass a real PAN, a real amount, or a real
customer identifier.  reach_checkout scope-gates every URL before it sends a byte.

CLI:
  lib_commerce.py test-pms              print the canonical test instruments as JSON
  lib_commerce.py paypal-buyer          print the PayPal sandbox buyer login shape
  lib_commerce.py selfcheck             run the offline assertion suite (no network)

Import:
  from bbtools.lib_commerce import stripe_test_pm, paypal_sandbox_buyer, reach_checkout
"""

import json, os, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _ensure_bbtools_path():
    p = str(ROOT / "scripts")
    if p not in sys.path:
        sys.path.insert(0, p)


# ---------------------------------------------------------------------------
# 1. TEST PAYMENT INSTRUMENTS
# ---------------------------------------------------------------------------

def stripe_test_pm():
    """Return the canonical PUBLIC Stripe test payment instruments as a dict.

    These are Stripe's own published test values; no secrets, no real charges.
    Use the dict key as `pm` in reach_checkout() or inline in a PoC:
      pm = stripe_test_pm()["success"]
      pm["number"]          -> "4242424242424242"
      pm["exp_month"]       -> "12"
      pm["exp_year"]        -> "2034"
      pm["cvc"]             -> "123"
      pm["label"]           -> human-readable label for evidence logs

    Keys
    ----
    success         Visa 4242 - succeeds every time; the default for order-object probing.
    threeds         Visa 4000 0025 0000 3155 - requires 3DS authentication; tests the
                    3DS challenge path and whether a race can skip the auth step.
    insufficient    Visa 4000 0000 0000 9995 - declined insufficient-funds; proves the
                    decline path so a race-win is not a false positive from a retry.
    sepa            DE89 SEPA test IBAN - for EUR-denominated targets using SEPA debit.
    """
    return {
        "success": {
            "number": "4242424242424242",
            "exp_month": "12",
            "exp_year": "2034",
            "cvc": "123",
            "brand": "visa",
            "label": "Stripe test Visa (always succeeds)",
        },
        "threeds": {
            "number": "4000002500003155",
            "exp_month": "12",
            "exp_year": "2034",
            "cvc": "123",
            "brand": "visa",
            "label": "Stripe test Visa (3DS required)",
        },
        "insufficient": {
            "number": "4000000000009995",
            "exp_month": "12",
            "exp_year": "2034",
            "cvc": "123",
            "brand": "visa",
            "label": "Stripe test Visa (insufficient funds - declined)",
        },
        "sepa": {
            "iban": "DE89370400440532013000",
            "label": "Stripe test SEPA IBAN (EUR debit)",
        },
    }


def paypal_sandbox_buyer():
    """Return the PayPal sandbox buyer login shape.

    These are placeholder values.  Replace sb-buyer@example.com with the
    sandbox buyer email from the PayPal Developer Dashboard for the target's
    sandbox account.  The password field is a sentinel so callers know to
    fill it in before use.

    Returns a dict:
      {email, password, note, dashboard_url}
    """
    return {
        "email": "sb-buyer@personal.example.com",
        "password": "REPLACE_WITH_SANDBOX_BUYER_PASSWORD",
        "note": (
            "Replace email+password from the PayPal Developer Dashboard "
            "(developer.paypal.com -> Sandbox -> Accounts -> buyer email)."
        ),
        "dashboard_url": "https://developer.paypal.com/dashboard/accounts",
    }


# ---------------------------------------------------------------------------
# 2. CHECKOUT WALK
# ---------------------------------------------------------------------------

def reach_checkout(session, add_to_cart_url, checkout_url, pm, scope_file=None,
                   cart_method="POST", cart_body=None, cart_headers=None,
                   pay_method="POST", pay_body=None, pay_headers=None,
                   extract_order_id=None):
    """Walk add-to-cart -> checkout -> pay on an existing authed session.

    This is intentionally THIN: it fires the three calls in sequence and returns
    the raw captured bytes.  Target-specific logic (the exact cart body, the
    payment-token field name, the order-id extraction path) belongs in the
    caller's probe script, not here.

    Parameters
    ----------
    session         curl_cffi (or requests) session carrying attacker-A's auth.
                    Must already be authenticated (from authed_session / session_from_state).
    add_to_cart_url URL for the add-to-cart step (POST by default).
                    Pass None to skip (for targets where the cart is pre-filled).
    checkout_url    URL for the payment / place-order step.
    pm              Payment-method dict; use stripe_test_pm()["success"] for a Stripe target.
                    Only the dict keys the target's API actually reads are sent (caller
                    passes them via pay_body / pay_headers).
    scope_file      Path to SCOPE.txt; if set, both URLs are scope-gated before any request
                    is sent.  Omit only inside a tight PoC that already verified scope.
    cart_method     HTTP method for the cart step (default "POST").
    cart_body       dict / str body for the cart POST; target-specific.
    cart_headers    extra headers for the cart step.
    pay_method      HTTP method for the checkout step (default "POST").
    pay_body        dict / str body for the pay step.  Merge test PM fields here:
                    pay_body = {"payment_method": pm["number"], "cvv": pm["cvc"], ...}
    pay_headers     extra headers for the pay step.
    extract_order_id  callable(response) -> str | None; extracts the order ID from the
                    pay response.  Default: looks for "order_id", "orderId", "id" keys
                    in a JSON response body.

    Returns
    -------
    {
      "order_id":        str | None,
      "payment_status":  HTTP status int of the pay step,
      "receipt_bytes":   raw response body bytes of the pay step (the terminal receipt),
      "cart_status":     HTTP status int of the cart step (None if skipped),
      "cart_bytes":      raw response body bytes of the cart step (None if skipped),
    }

    Raises
    ------
    ValueError  if scope_file is set and either URL is out of scope.
    """
    _ensure_bbtools_path()
    from bbtools.lib_scope import in_scope

    if scope_file:
        for url in filter(None, [add_to_cart_url, checkout_url]):
            if not in_scope(url, scope_file):
                raise ValueError(f"OUT_OF_SCOPE {url} (scope_file={scope_file})")

    result = {
        "order_id": None,
        "payment_status": None,
        "receipt_bytes": None,
        "cart_status": None,
        "cart_bytes": None,
    }

    # Step 1: add-to-cart (optional)
    if add_to_cart_url:
        kw = {}
        if cart_body:
            if isinstance(cart_body, dict):
                kw["json"] = cart_body
            else:
                kw["data"] = cart_body
        if cart_headers:
            kw["headers"] = cart_headers
        r = session.request(cart_method, add_to_cart_url, **kw)
        result["cart_status"] = r.status_code
        result["cart_bytes"] = getattr(r, "content", None) or (r.text.encode() if hasattr(r, "text") else b"")

    # Step 2: pay / place-order
    kw2 = {}
    if pay_body:
        if isinstance(pay_body, dict):
            kw2["json"] = pay_body
        else:
            kw2["data"] = pay_body
    if pay_headers:
        kw2["headers"] = pay_headers
    r2 = session.request(pay_method, checkout_url, **kw2)
    result["payment_status"] = r2.status_code
    receipt = getattr(r2, "content", None) or (r2.text.encode() if hasattr(r2, "text") else b"")
    result["receipt_bytes"] = receipt

    # Step 3: extract order ID
    if extract_order_id:
        result["order_id"] = extract_order_id(r2)
    else:
        try:
            body = json.loads(receipt)
            for key in ("order_id", "orderId", "order", "id"):
                if key in body and isinstance(body[key], (str, int)):
                    result["order_id"] = str(body[key])
                    break
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# SELFCHECK
# ---------------------------------------------------------------------------

def _selfcheck():
    # 1. stripe_test_pm returns all four instruments with expected card number
    pms = stripe_test_pm()
    assert pms["success"]["number"] == "4242424242424242", pms["success"]
    assert pms["threeds"]["number"] == "4000002500003155", pms["threeds"]
    assert pms["insufficient"]["number"] == "4000000000009995", pms["insufficient"]
    assert pms["sepa"]["iban"] == "DE89370400440532013000", pms["sepa"]
    assert all(k in pms for k in ("success", "threeds", "insufficient", "sepa")), pms.keys()

    # 2. paypal_sandbox_buyer returns the expected shape
    ppb = paypal_sandbox_buyer()
    assert "email" in ppb and "password" in ppb and "dashboard_url" in ppb, ppb

    # 3. reach_checkout scope-gates an off-scope URL and refuses
    _ensure_bbtools_path()
    import tempfile
    sfp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt").name
    open(sfp, "w").write("example.com\n")
    try:
        class _FakeSess:
            def request(self, *a, **k):
                raise AssertionError("should not reach network")
        reach_checkout(_FakeSess(), "https://evil.org/cart", "https://evil.org/pay",
                       pms["success"], scope_file=sfp)
        assert False, "reach_checkout should have raised OUT_OF_SCOPE"
    except ValueError as e:
        assert "OUT_OF_SCOPE" in str(e), str(e)
    finally:
        os.remove(sfp)

    # 4. reach_checkout walks cart -> pay on a mock session (no network)
    sfp2 = tempfile.NamedTemporaryFile(delete=False, suffix=".txt").name
    open(sfp2, "w").write("shop.example.com\n")
    try:
        class _Resp:
            status_code = 200
            content = b'{"order_id":"ORD-42","status":"paid"}'
            text = '{"order_id":"ORD-42","status":"paid"}'

        class _MockSess:
            calls = []
            def request(self, method, url, **kw):
                _MockSess.calls.append((method, url))
                return _Resp()

        ms = _MockSess()
        out = reach_checkout(
            ms,
            "https://shop.example.com/cart",
            "https://shop.example.com/checkout",
            pms["success"],
            scope_file=sfp2,
            cart_body={"product_id": "1"},
            pay_body={"number": pms["success"]["number"]},
        )
        assert out["payment_status"] == 200, out
        assert out["order_id"] == "ORD-42", out
        assert out["cart_status"] == 200, out
        assert len(_MockSess.calls) == 2, _MockSess.calls
        assert _MockSess.calls[0][1].endswith("/cart"), _MockSess.calls
        assert _MockSess.calls[1][1].endswith("/checkout"), _MockSess.calls
    finally:
        os.remove(sfp2)

    # 5. reach_checkout skips cart step when add_to_cart_url is None
    sfp3 = tempfile.NamedTemporaryFile(delete=False, suffix=".txt").name
    open(sfp3, "w").write("shop.example.com\n")
    try:
        class _MockSess2:
            calls = []
            def request(self, method, url, **kw):
                _MockSess2.calls.append((method, url))
                class _R:
                    status_code = 201
                    content = b'{"id":"ORD-99"}'
                    text = '{"id":"ORD-99"}'
                return _R()

        ms2 = _MockSess2()
        out2 = reach_checkout(ms2, None, "https://shop.example.com/checkout",
                              pms["success"], scope_file=sfp3)
        assert out2["cart_status"] is None, out2
        assert out2["payment_status"] == 201, out2
        assert out2["order_id"] == "ORD-99", out2
        assert len(_MockSess2.calls) == 1, _MockSess2.calls
    finally:
        os.remove(sfp3)

    print("SELFCHECK OK  stripe_test_pm, paypal_sandbox_buyer, reach_checkout scope-gate+walk ok")


def _main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return
    cmd = argv[0]
    if cmd == "test-pms":
        print(json.dumps(stripe_test_pm(), indent=2))
    elif cmd == "paypal-buyer":
        print(json.dumps(paypal_sandbox_buyer(), indent=2))
    elif cmd == "selfcheck":
        _selfcheck()
    else:
        print(f"unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    _main(sys.argv[1:])
