#!/usr/bin/env python3
"""
test_commerce_chain.py - OFFLINE integration test for the commerce chain.

Proves that commerce_tamper, commerce_receipt, commerce_webhook, and bh all
wire together correctly. No real socket is opened; all network is stubbed.

Usage:
    python3 scripts/bbtools/test_commerce_chain.py
    -> prints "COMMERCE CHAIN TEST OK" when all assertions pass.

Added to selfcheck-all.sh so it runs with every bbtools self-check sweep.
"""

import os
import sys
import json
import hashlib
import hmac

# Resolve bbtools on sys.path regardless of cwd.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


# ---------------------------------------------------------------------------
# (a) commerce_tamper.tamper_matrix - canonical mutation labels
# ---------------------------------------------------------------------------

def _test_tamper_matrix():
    import commerce_tamper

    body = {
        "price": 100,
        "currency": "USD",
        "quantity": 2,
        "discount": 10,
    }
    matrix = commerce_tamper.tamper_matrix(body)
    # matrix is a list of (label, mutated_body) pairs
    labels = [label for label, _ in matrix]

    # The canonical tamper set must include negative, zero, and currency-swap mutations
    # for the price key, and must include quantity and discount mutations.
    # Check that the four documented categories are present.
    assert any("negative" in l.lower() for l in labels), \
        f"tamper_matrix missing 'negative' mutation; got labels: {labels}"
    assert any("zero" in l.lower() or "0" in l for l in labels), \
        f"tamper_matrix missing zero/0 mutation; got labels: {labels}"
    assert any("currency" in l.lower() or "swap" in l.lower() or "inr" in l.lower()
               or "jpy" in l.lower() for l in labels), \
        f"tamper_matrix missing currency-swap mutation; got labels: {labels}"
    assert any("overflow" in l.lower() or "9999" in l for l in labels), \
        f"tamper_matrix missing overflow mutation; got labels: {labels}"

    # Every returned body must be a dict (not the original mutated in place)
    for _label, mutated in matrix:
        assert isinstance(mutated, dict), \
            f"tamper_matrix returned non-dict body for label {_label!r}"

    # Original body must not have been mutated
    assert body["price"] == 100, "tamper_matrix mutated the original body in place"


# ---------------------------------------------------------------------------
# (b) commerce_receipt.prove - confirmed=True on real delta, False on no-delta
# ---------------------------------------------------------------------------

class _StubResponse:
    """Minimal requests-like response object for offline testing."""
    def __init__(self, data: dict, status: int = 200):
        self._data = data
        self.status_code = status
        self.text = json.dumps(data)
        self.content = self.text.encode()


class _StubSession:
    """Stub session that cycles through pre-canned response bodies on GET."""
    def __init__(self, responses: list):
        """responses: list of dicts returned by consecutive .get() calls."""
        self._queue = list(responses)
        self._idx = 0

    def get(self, url, **kwargs):
        resp = self._queue[self._idx % len(self._queue)]
        self._idx += 1
        return _StubResponse(resp)


def _test_prove_confirmed_true():
    """prove() returns confirmed=True when the balance field increases."""
    import commerce_receipt

    before_body = {"balance": 100, "currency": "USD"}
    after_body  = {"balance": 150, "currency": "USD"}

    session = _StubSession([before_body, after_body])

    def _action(sess):
        # Simulate an attack call that bumps balance; return a stub response.
        return _StubResponse({"ok": True}, status=200)

    result = commerce_receipt.prove(
        session,
        read_url="https://example.internal/state",  # no scope_file -> no scope gate
        action_fn=_action,
        fields=["balance"],
        expect="increase",
    )
    assert result["confirmed"] is True, \
        f"prove() should be confirmed=True on an increase delta; got {result}"
    assert "balance" in result["delta"], \
        f"prove() delta should contain 'balance'; got {result['delta']}"


def _test_prove_confirmed_false_on_no_delta():
    """prove() returns confirmed=False when before==after (no delta)."""
    import commerce_receipt

    same_body = {"balance": 100, "currency": "USD"}

    session = _StubSession([same_body, same_body])

    def _action(sess):
        return _StubResponse({"ok": True}, status=200)

    result = commerce_receipt.prove(
        session,
        read_url="https://example.internal/state",
        action_fn=_action,
        fields=["balance"],
        expect="increase",
    )
    assert result["confirmed"] is False, \
        f"prove() should be confirmed=False when no delta; got {result}"
    assert result["delta"] == {}, \
        f"prove() delta should be empty on no-change; got {result['delta']}"


# ---------------------------------------------------------------------------
# (c) commerce_webhook - known-answer + forge_ladder empty-secret rung
# ---------------------------------------------------------------------------

def _test_webhook_known_answer():
    """stripe_sig and github_sig produce stable known-answer values."""
    import commerce_webhook

    secret = "test_secret"
    body = b'{"type":"payment_intent.succeeded","data":{"amount":1000}}'
    fixed_ts = 1700000000

    # Stripe sig known-answer
    sig = commerce_webhook.stripe_sig(secret, body, ts=fixed_ts)
    expected_stripe_payload = f"{fixed_ts}.".encode() + body
    expected_v1 = hmac.new(
        secret.encode(), expected_stripe_payload, hashlib.sha256
    ).hexdigest()
    assert sig == f"t={fixed_ts},v1={expected_v1}", \
        f"stripe_sig mismatch: {sig!r} vs expected t={fixed_ts},v1={expected_v1!r}"

    # GitHub sig known-answer
    gh = commerce_webhook.github_sig(secret, body)
    expected_gh = "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()
    assert gh == expected_gh, \
        f"github_sig mismatch: {gh!r} vs expected {expected_gh!r}"


def _test_forge_ladder_empty_secret_first():
    """forge_ladder()[0] is the empty-secret rung (the deterministic public win)."""
    import commerce_webhook

    body = b'{"type":"charge.succeeded"}'
    ladder = commerce_webhook.forge_ladder(body)

    assert len(ladder) >= 1, "forge_ladder returned empty list"
    first_label, first_val = ladder[0]
    assert first_label == "empty-secret", \
        f"forge_ladder()[0] should be 'empty-secret', got {first_label!r}"

    # The value must be a GitHub-style "sha256=<hex>" computed with key=b""
    expected = "sha256=" + hmac.new(b"", body, hashlib.sha256).hexdigest()
    assert first_val == expected, \
        f"forge_ladder empty-secret value mismatch: {first_val!r} vs {expected!r}"


# ---------------------------------------------------------------------------
# (d) bh.req raises OutOfScope on off-scope url with no network
# ---------------------------------------------------------------------------

def _test_bh_raises_out_of_scope():
    """bh.req raises OutOfScope before touching the network when scope_file given."""
    import tempfile

    # Write a minimal SCOPE.txt that allows only example-in-scope.com
    scope_content = "*.example-in-scope.com\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(scope_content)
        scope_path = f.name

    try:
        from bh import req, OutOfScope
        raised = False
        try:
            # This host is NOT in scope - must raise before any network call.
            req(
                "https://off-scope-host.evil.com/api/v1/data",
                scope_file=scope_path,
                via="direct",  # force direct so Burp absence does not matter
            )
        except OutOfScope:
            raised = True
        except Exception as exc:
            # Any network error means the gate did NOT fire before the network call.
            raise AssertionError(
                f"bh.req should have raised OutOfScope before network, "
                f"but got {type(exc).__name__}: {exc}"
            )
        assert raised, "bh.req did not raise OutOfScope for an off-scope URL"
    finally:
        os.unlink(scope_path)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def main():
    tests = [
        ("tamper_matrix canonical mutations",       _test_tamper_matrix),
        ("prove confirmed=True on increase delta",  _test_prove_confirmed_true),
        ("prove confirmed=False on no delta",       _test_prove_confirmed_false_on_no_delta),
        ("webhook stripe_sig known-answer",         _test_webhook_known_answer),
        ("forge_ladder empty-secret is first rung", _test_forge_ladder_empty_secret_first),
        ("bh.req raises OutOfScope off-scope",      _test_bh_raises_out_of_scope),
    ]

    failures = []
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception as exc:
            print(f"  FAIL  {name}: {exc}")
            failures.append((name, exc))

    print()
    if failures:
        print(f"COMMERCE CHAIN TEST FAILED ({len(failures)}/{len(tests)} failed)")
        sys.exit(1)
    else:
        print("COMMERCE CHAIN TEST OK")


if __name__ == "__main__":
    main()
