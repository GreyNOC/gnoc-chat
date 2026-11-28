#!/usr/bin/env python3
"""
commerce_tamper.py - price/currency/quantity confirm-call tamper matrix.

WHY: the client-supplied price/amount/quantity on the CONFIRM/capture call (not the display
call) is the most-skipped commerce gate. Targets that hard-code a price on the add-to-cart
often trust the client's amount on the final charge call. This matrix makes the systematic
probe trivial.

FUNCTIONS

  tamper_matrix(body, price_keys=(...)) -> [(label, mutated_body)]
      Given a request body dict, return a list of (label, mutated_body) pairs covering
      the canonical tamper set for every key matching price_keys:
        - negative (-1)
        - zero (0)
        - one-cent (0.01)
        - overflow (99999999999 and 1e308)
        - currency-swap (INR, JPY - high-face-value currencies holding the same integer amount)
        - string-vs-int (send "10" where an int was expected, send 10 where a string was)
        - extra-precision (9.999 for a value that was 10 - rounds down on some backends)
      Quantity keys get: -1, 0, 1, 99999 (no currency-swap).
      Discount keys get: 0, 100, 101, -1 (full discount, over-discount, negative).

  confirm_diff(session, confirm_url, matrix, receipt_read_url=None,
               scope_file=None, method="POST") -> list
      Fire each tamper variant against confirm_url, capturing the HTTP status and response
      body. If receipt_read_url is given, capture the settled server state after each call
      via commerce_receipt.snapshot so the buyer can see whether the tamper landed.
      Returns a list of row dicts {label, status, body_excerpt, settled_state, delta}.
      Scope-gates confirm_url and receipt_read_url before sending any bytes.

SECURITY: sandbox/test bodies only. confirm_diff is scope-gated.

CLI:
  commerce_tamper.py selfcheck    run offline assertion suite (no network)
"""
import copy
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from lib_scope import in_scope, extract_host  # noqa: E402


# ---------------------------------------------------------------------------
# Default price/amount/currency/quantity key patterns
# ---------------------------------------------------------------------------

_DEFAULT_PRICE_KEYS = ("price", "amount", "total", "subtotal", "unit_price",
                       "unitPrice", "charge", "fee", "cost")
_DEFAULT_CURRENCY_KEYS = ("currency", "currency_code", "currencyCode")
_DEFAULT_QUANTITY_KEYS = ("quantity", "qty", "count", "units")
_DEFAULT_DISCOUNT_KEYS = ("discount", "discount_amount", "discountAmount",
                          "coupon_amount", "promo_amount")

# All recognized price-like keys (the default for tamper_matrix's price_keys param)
DEFAULT_PRICE_KEYS = _DEFAULT_PRICE_KEYS + _DEFAULT_CURRENCY_KEYS + _DEFAULT_QUANTITY_KEYS + _DEFAULT_DISCOUNT_KEYS


# ---------------------------------------------------------------------------
# 1. tamper_matrix
# ---------------------------------------------------------------------------

def tamper_matrix(body: dict,
                  price_keys: tuple = DEFAULT_PRICE_KEYS) -> list:
    """Generate the canonical tamper variant list for a request body.

    Parameters
    ----------
    body        The original request body dict (will NOT be mutated).
    price_keys  Tuple of key names to tamper. Defaults to the union of price,
                currency, quantity, and discount key names. Pass a custom tuple
                to target only specific keys.

    Returns
    -------
    List of (label: str, mutated_body: dict) pairs. The label is human-readable
    and copy-paste ready for a capture.log entry. The original body is returned
    as the first entry ("baseline") so callers can compare against it.
    """
    variants = [("baseline", copy.deepcopy(body))]

    for key in list(body.keys()):
        original_val = body[key]

        # Determine which category this key belongs to
        key_lower = key.lower()
        is_currency = any(k in key_lower for k in ("currency",))
        is_quantity = any(k in key_lower for k in ("qty", "quantity", "count", "units"))
        is_discount = any(k in key_lower for k in ("discount", "promo", "coupon"))
        is_price_like = any(k in key_lower for k in ("price", "amount", "total",
                                                       "subtotal", "fee", "cost",
                                                       "charge", "unit_price", "unitprice"))

        # Only tamper keys that match price_keys
        if key not in price_keys and not any(
            pk.lower() in key_lower or key_lower in pk.lower()
            for pk in price_keys
        ):
            continue

        if is_currency:
            # Currency-swap: hold the same integer amount but change the currency
            # to a high-face-value currency so the backend charges the wrong amount.
            for cur in ("INR", "JPY", "KRW", "IDR", "VND"):
                if str(original_val).upper() != cur:
                    m = copy.deepcopy(body)
                    m[key] = cur
                    variants.append((f"currency-swap-{key}->{cur}", m))
            # Empty / null currency
            for sentinel, label in [("", "currency-empty"), (None, "currency-null")]:
                m = copy.deepcopy(body)
                m[key] = sentinel
                variants.append((f"{label}-{key}", m))
            continue

        if is_quantity:
            for val, label in [(-1, "negative"), (0, "zero"), (1, "one"),
                                (99999, "overflow-qty")]:
                m = copy.deepcopy(body)
                m[key] = val
                variants.append((f"qty-{label}-{key}", m))
            # String coercion
            if isinstance(original_val, int):
                m = copy.deepcopy(body)
                m[key] = str(original_val)
                variants.append((f"qty-string-coerce-{key}", m))
            continue

        if is_discount:
            for val, label in [(0, "zero-discount"), (100, "full-discount"),
                                (101, "over-discount"), (-1, "negative-discount")]:
                m = copy.deepcopy(body)
                m[key] = val
                variants.append((f"discount-{label}-{key}", m))
            continue

        if is_price_like:
            # Numeric tamper set
            for val, label in [
                (-1, "negative"),
                (0, "zero"),
                (0.01, "one-cent"),
                (99999999999, "overflow-large"),
                (1e308, "overflow-float"),
            ]:
                m = copy.deepcopy(body)
                m[key] = val
                variants.append((f"price-{label}-{key}", m))

            # Extra precision: slightly below a round number (rounds down on some backends)
            if isinstance(original_val, (int, float)) and original_val > 0:
                extra_prec = round(float(original_val) - 0.001, 3)
                if extra_prec != original_val:
                    m = copy.deepcopy(body)
                    m[key] = extra_prec
                    variants.append((f"price-extra-precision-{key}", m))

            # String-vs-int coercion
            if isinstance(original_val, (int, float)):
                m = copy.deepcopy(body)
                m[key] = str(original_val)
                variants.append((f"price-string-coerce-{key}", m))
            elif isinstance(original_val, str):
                try:
                    m = copy.deepcopy(body)
                    m[key] = float(original_val)
                    variants.append((f"price-int-coerce-{key}", m))
                except (ValueError, TypeError):
                    pass

            # Scientific notation (some validators reject "1e-5" but some parsers accept)
            m = copy.deepcopy(body)
            m[key] = 1e-5
            variants.append((f"price-sci-notation-{key}", m))

            # Null / missing field
            m = copy.deepcopy(body)
            m[key] = None
            variants.append((f"price-null-{key}", m))

            m = copy.deepcopy(body)
            del m[key]
            variants.append((f"price-missing-{key}", m))

    return variants


# ---------------------------------------------------------------------------
# 2. confirm_diff
# ---------------------------------------------------------------------------

def confirm_diff(session, confirm_url: str, matrix: list,
                 receipt_read_url: "str | None" = None,
                 scope_file: "str | None" = None,
                 method: str = "POST") -> list:
    """Fire each tamper variant and capture the settled state.

    Parameters
    ----------
    session         Authed session.
    confirm_url     The payment capture / confirm / place-order endpoint to probe.
    matrix          Output of tamper_matrix(): [(label, mutated_body), ...].
    receipt_read_url If given, GET this URL after each call to capture the settled
                    server state. Passed to commerce_receipt.snapshot.
    scope_file      Scope file for gate enforcement. Both confirm_url and
                    receipt_read_url are checked before any bytes leave.
    method          HTTP method for the confirm call (default "POST").

    Returns
    -------
    List of row dicts:
    {
      "label":         str variant label,
      "body_sent":     dict the mutated body that was sent,
      "status":        int HTTP status of the confirm call,
      "body_excerpt":  str first 400 chars of the response,
      "settled_state": snapshot dict or None,
      "delta":         dict of changed fields vs previous state or None,
    }
    """
    _gate(confirm_url, scope_file)
    if receipt_read_url:
        _gate(receipt_read_url, scope_file)

    # Lazy import to avoid a hard dep at module load time
    _snapshot = None
    if receipt_read_url:
        from commerce_receipt import snapshot as _snap
        _snapshot = _snap

    results = []
    prev_state = None

    for label, mutated_body in matrix:
        r = session.request(method, confirm_url, json=mutated_body, timeout=20)
        raw = getattr(r, "content", None) or (r.text.encode() if hasattr(r, "text") else b"")
        excerpt = raw[:400].decode("utf-8", errors="replace")

        settled = None
        delta = None
        if _snapshot and receipt_read_url:
            settled = _snapshot(session, receipt_read_url, scope_file=scope_file)
            if prev_state is not None:
                delta = {
                    k: (prev_state["fields"].get(k), settled["fields"].get(k))
                    for k in settled["fields"]
                    if prev_state["fields"].get(k) != settled["fields"].get(k)
                }
            prev_state = settled

        results.append({
            "label": label,
            "body_sent": mutated_body,
            "status": r.status_code,
            "body_excerpt": excerpt,
            "settled_state": settled,
            "delta": delta,
        })

    return results


def _gate(url: str, scope_file: "str | None") -> None:
    if scope_file is None:
        return
    if not in_scope(url, scope_file):
        raise ValueError(f"OUT_OF_SCOPE {extract_host(url)} (scope_file={scope_file})")


# ---------------------------------------------------------------------------
# SELFCHECK
# ---------------------------------------------------------------------------

def _selfcheck():
    import tempfile

    # ------------------------------------------------------------------
    # 1. tamper_matrix generates the canonical set for a price field
    # ------------------------------------------------------------------
    body = {"amount": 100, "currency": "USD", "quantity": 2, "product_id": "SKU-001"}
    matrix = tamper_matrix(body)

    labels = [r[0] for r in matrix]
    assert "baseline" in labels, "baseline must be present"
    assert any("negative" in l for l in labels), "negative price variant missing"
    assert any("zero" in l for l in labels), "zero price variant missing"
    assert any("one-cent" in l for l in labels), "one-cent variant missing"
    assert any("overflow" in l for l in labels), "overflow variant missing"
    assert any("currency-swap" in l for l in labels), "currency-swap variant missing"
    assert any("string-coerce" in l for l in labels), "string-coerce variant missing"

    # ------------------------------------------------------------------
    # 2. baseline body is not mutated
    # ------------------------------------------------------------------
    assert body["amount"] == 100, "original body must not be mutated"
    assert body["currency"] == "USD", "original body must not be mutated"

    # ------------------------------------------------------------------
    # 3. currency-swap targets the currency field
    # ------------------------------------------------------------------
    currency_swaps = [(l, b) for l, b in matrix if "currency-swap" in l]
    assert len(currency_swaps) >= 2, f"expected >= 2 currency-swaps, got {len(currency_swaps)}"
    swap_values = {b["currency"] for _, b in currency_swaps}
    assert "INR" in swap_values or "JPY" in swap_values, f"INR/JPY missing from swaps: {swap_values}"

    # ------------------------------------------------------------------
    # 4. no mutation to product_id (not a price key)
    # ------------------------------------------------------------------
    product_variants = [(l, b) for l, b in matrix if "product_id" in l]
    assert len(product_variants) == 0, f"product_id should not be tampered: {product_variants}"

    # ------------------------------------------------------------------
    # 5. quantity key gets qty-specific variants
    # ------------------------------------------------------------------
    qty_variants = [(l, b) for l, b in matrix if l.startswith("qty-")]
    assert any("overflow-qty" in l for l, _ in qty_variants), "overflow-qty missing"
    assert any("negative" in l for l, _ in qty_variants), "negative qty missing"
    assert any("zero" in l for l, _ in qty_variants), "zero qty missing"

    # ------------------------------------------------------------------
    # 6. extra-precision variant (9.999 for amount=10)
    # ------------------------------------------------------------------
    body2 = {"price": 10}
    m2 = tamper_matrix(body2)
    ep = [(l, b) for l, b in m2 if "extra-precision" in l]
    assert len(ep) >= 1, "extra-precision variant missing for price=10"
    assert ep[0][1]["price"] < 10, f"extra-precision should be < 10, got {ep[0][1]['price']}"

    # ------------------------------------------------------------------
    # 7. missing-field and null-field variants present
    # ------------------------------------------------------------------
    m3 = tamper_matrix({"amount": 50})
    labels3 = [l for l, _ in m3]
    assert any("null" in l for l in labels3), "null-field variant missing"
    assert any("missing" in l for l in labels3), "missing-field variant missing"

    # ------------------------------------------------------------------
    # 8. confirm_diff scope-gates off-scope confirm_url
    # ------------------------------------------------------------------
    sf = tempfile.NamedTemporaryFile(delete=False, suffix=".txt").name
    with open(sf, "w") as fh:
        fh.write("shop.example.com\n")
    try:
        class _FakeSess:
            def request(self, *a, **k):
                raise AssertionError("should not reach network")
        try:
            confirm_diff(_FakeSess(), "https://evil.org/checkout",
                         [("test", {"amount": 1})], scope_file=sf)
            raise SystemExit("scope gate FAILED for confirm_url")
        except ValueError as e:
            assert "OUT_OF_SCOPE" in str(e), str(e)
    finally:
        os.unlink(sf)

    # ------------------------------------------------------------------
    # 9. confirm_diff fires each variant and captures status
    # ------------------------------------------------------------------
    sf2 = tempfile.NamedTemporaryFile(delete=False, suffix=".txt").name
    with open(sf2, "w") as fh:
        fh.write("shop.example.com\n")
    try:
        calls = []

        class _MockResp:
            status_code = 200
            content = b'{"ok": true}'
            text = '{"ok": true}'

        class _MockSess2:
            def request(self, method, url, json=None, **k):
                calls.append(json)
                return _MockResp()

        mini_matrix = [("baseline", {"amount": 100}), ("price-zero-amount", {"amount": 0})]
        rows = confirm_diff(_MockSess2(), "https://shop.example.com/pay",
                            mini_matrix, scope_file=sf2)
        assert len(rows) == 2, f"expected 2 rows, got {len(rows)}"
        assert rows[0]["label"] == "baseline"
        assert rows[1]["label"] == "price-zero-amount"
        assert rows[1]["body_sent"]["amount"] == 0
        assert len(calls) == 2, f"expected 2 network calls, got {len(calls)}"
    finally:
        os.unlink(sf2)

    print("SELFCHECK OK  tamper_matrix canonical set, currency-swap/qty/precision/missing, confirm_diff scope-gate+fire")


def main(argv):
    if argv and argv[0] == "selfcheck":
        return _selfcheck()
    print(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
