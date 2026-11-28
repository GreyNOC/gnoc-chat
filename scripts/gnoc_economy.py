#!/usr/bin/env python3
"""gnoc_economy.py - the proof market: a code-adjudicated prediction market for the harness's bots.

Unit RC (receipt credit), 1 RC ~ one live probe. Spec: scripts/learn/SPEC-xbow-intel-economy-20261022.md section 3.

    .claude/state/economy/ledger.jsonl    append-only, HASH-CHAINED and KEYED: prev = sha256 of the previous row's
                                          bytes, sig = HMAC-SHA256(.chainkey, the row without sig)
    .claude/state/economy/lineage.jsonl   who authored / probed / verified / wrote; every row HMAC-signed too
    .claude/state/economy/.chainkey       0600 random key, created once with the ledger, never returned or printed
    .claude/state/economy/econ.log        one line per skipped hook (lock timeout, broken chain, refused event)

Rules the code enforces (a model may bet, post or claim; it can never mint or resolve):
  - balances() is a REPLAY of a VERIFIED ledger: a row without a valid sig or prev raises EconomyBroken, and every
    decision read refuses (hooks catch it and the economy is disabled with a logged reason) until a human repairs it
  - the settler token is derived from the chain key (a planted .settler file is ignored)
  - oracle-pass mints only after re-reading gnoc_oracle's SIGNED verdict row, once per oracle id
  - a floor-met DEAD mints only on probe/burst counts RECOMPUTED from gnoc_hunt state plus a signed burst row
  - a CANDIDATE outcome resolves "lead"; "proven" comes only from an oracle PASS
  - "ready" mints only through `gnoc_economy.py ready-hook` (called by scripts/reports.sh ready once the verdict
    is final), never from a typed ship row
  - every lock waits at most LOCK_TIMEOUT seconds; on timeout the event is skipped with one logged line
Every public hook is on_event(kind, **kw); it never raises, so the economy cannot block a hunt or a ledger write.
"""
import contextlib
import contextvars
import fcntl
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import shutil
import sys
import threading
import time
from datetime import datetime, timezone

# shared helpers (consolidated from the per-module copies)
from gnoc_core.util import _now_z as _now

# WS honours the environment so a sandboxed pipeline run (scripts/test-pipeline-e2e.sh, which copies the
# scripts into a temp root and sets WS) never mints into the real economy ledger. Default unchanged.
WS = os.environ.get("WS") or (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STATE = os.path.join(WS, ".claude/state/economy")
LEDGER = os.path.join(STATE, "ledger.jsonl")
LINEAGE = os.path.join(STATE, "lineage.jsonl")
SETTLER = os.path.join(STATE, ".settler")   # legacy, IGNORED: the settler token is derived from the chain key
CHAINKEY = None                             # None = <STATE>/.chainkey (tests that move STATE get their own key)
MODELS_JSON = os.path.join(WS, ".claude/state/orch/models.json")
FEEDBACK_OUT = os.path.join(WS, "scripts/h1-feedback/out")

ROSTER = ("lead", "worker", "reflector", "brain", "phone-1.7b", "phone-4b", "oss-bot", "orch-bot",
          )
RETIRED = ("claude-opus", "claude-sonnet", "claude-haiku")   # 2026-10-23 standalone GreyNOC build: hidden, balances returned
GENESIS_EACH = 1000
GENESIS_TREASURY = 100000
TREASURY, ESCROW = "treasury", "escrow"
SOURCES = ("genesis", "mint")   # accounts that create RC (never debited)
SINK = "burn"                   # account that destroys RC (never credited in wealth)
KINDS = ("mint", "burn", "stake", "resolve", "royalty", "slash", "bond", "refund")
BROKE = 100
HOUSE = 0.02
BOND = 30
MIN_POST = 10
FLOOR = 8
BUDGET_MIN, BUDGET_MAX = 20, 200
STIPEND, STIPEND_PER_DAY = 100, 5   # treasury top-up for an acting bot that LLM burns drained to 0 (2026-10-23)
BOUNTY_TTL = 72 * 3600
BOUNTY_ABANDON = 2 * 3600       # a claimed bounty with no probe by the claimer for this long forfeits its bond
BOUNTY_MAX = 1000
LOCK_TIMEOUT = 2.0              # seconds; a hook never waits longer than this for the ledger
MINT = {"oracle-prover": 50, "oracle-author": 25, "ready": 100, "dead-floor": 5, "accept": 1000}
SHARES = {"author": 0.30, "prober": 0.40, "verifier": 0.20, "writer": 0.10}
PENALTY = {"duplicate": 200, "not-applicable": 500}   # T-254: dup scores 0, N/A -5 in the H1 signal
RATES = {"small": 1, "9b": 2, "sonnet": 10, "opus": 30, "haiku": 3}   # RC per 10k tokens of an LLM turn (2026-10-23: was per 1k, which bankrupted the lead in ~25 turns)
OUTCOMES = ("proven", "lead", "dead", "unfired")
FILING_SIDES = ("resolved", "duplicate", "n-a")
ZERO = "0" * 64
REQUIRE_TARGET = True   # book only programs with targets/<p>/SCOPE.txt, so a test fixture never reaches the live ledger
ROW_KEYS = ("ts", "seq", "prev", "kind", "from", "to", "amount", "ref", "memo")

_BOT = contextvars.ContextVar("gnoc_econ_bot", default=None)
_LOCK = threading.RLock()
_KEY_CACHE = {}
_ROW_CACHE = {}


class EconomyBroken(RuntimeError):
    """The ledger failed verification (bad sig, bad prev, missing key). Every decision read refuses."""


class EconomyBusy(RuntimeError):
    """The ledger lock was not free within LOCK_TIMEOUT seconds; the event is skipped, never waited on."""


class BudgetExhausted(PermissionError):
    """The hypothesis has spent its probe budget (2 x its LONG pool). Raised by gnoc_agent._send, no probe fired."""




def _epoch(ts):
    try:
        return datetime.strptime(str(ts), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return 0.0


def _log(msg):
    """One line to econ.log. Never raises (the state dir may be read-only)."""
    try:
        os.makedirs(STATE, exist_ok=True)
        with open(os.path.join(STATE, "econ.log"), "a") as f:
            f.write(f"{_now()} {str(msg)[:300]}\n")
    except OSError:
        pass


# ---------------------------------------------------------------- the chain key and the settler token

def _key_path():
    return CHAINKEY or os.path.join(STATE, ".chainkey")


def _ledger_empty():
    try:
        return os.path.getsize(LEDGER) == 0
    except OSError:
        return True


def _key(create=False):
    """The HMAC key. Created 0600 only when the ledger is empty (or by migrate); a missing key under a
    non-empty ledger is a broken economy, never a fresh key that would bless whatever is on disk."""
    p = _key_path()
    if p in _KEY_CACHE and os.path.exists(p):
        return _KEY_CACHE[p]
    if not os.path.exists(p):
        if not create:
            raise EconomyBroken(f"chain key missing ({p}): the ledger cannot be verified")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        try:
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(secrets.token_hex(32))
        except FileExistsError:
            pass
    if os.stat(p).st_mode & 0o077:
        os.chmod(p, 0o600)
    with open(p) as f:
        k = f.read().strip().encode()
    if len(k) < 64:
        raise EconomyBroken("chain key truncated: refusing to sign or verify with it")
    _KEY_CACHE[p] = k
    return k


def _register_secret():
    """The chain key is a secret path for every model-facing read (read_file, grep ...), as the oracle seal is."""
    try:
        import gnoc_secrets as _GS
        p = os.path.join(WS, ".claude/state/economy/.chainkey")
        if p not in _GS.SECRET_DIRS:
            _GS.SECRET_DIRS = tuple(_GS.SECRET_DIRS) + (p,)
    except Exception:  # noqa: BLE001 - the economy works without it
        pass


_register_secret()


def _settler():
    """The token mint() and resolve() demand: HMAC(chain key, constant). Only adjudicating code reads it."""
    if _ledger_empty():
        ensure()
    return hmac.new(_key(), b"gnoc-economy-settler-v1", hashlib.sha256).hexdigest()


def _gate(settler):
    if not settler or not hmac.compare_digest(str(settler), _settler()):
        raise PermissionError("refused: only an adjudicating code path (oracle verify, the floor gate, "
                              "append-outcome, the READY gate, the h1-feedback sync) may mint or resolve")


def _sig(row, key, domain=b"ledger"):
    body = json.dumps({k: v for k, v in row.items() if k != "sig"}, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode()
    return hmac.new(key, domain + b":" + body, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------- the keyed, hash-chained ledger

def _h(line_bytes):
    return hashlib.sha256(line_bytes).hexdigest()


def _genesis_rows():
    names = list(ROSTER)
    for r in _model_roles():
        if r not in names:
            names.append(r)
    rows = [("mint", "genesis", n, GENESIS_EACH, "genesis", "genesis") for n in names]
    rows.append(("mint", "genesis", TREASURY, GENESIS_TREASURY, "genesis", "genesis"))
    return rows


def _model_roles():
    try:
        with open(MODELS_JSON) as f:
            d = json.load(f)
        return [str(k) for k in d] if isinstance(d, dict) else []
    except (OSError, ValueError):
        return []


def _lines():
    """Ledger lines. A last line with no newline is an in-flight write and is not read yet."""
    with open(LEDGER, "rb") as f:
        data = f.read()
    return data.split(b"\n")[:-1]   # drops the empty string after the final newline, or a torn tail


def _verify_lines(lines, key):
    """(ok, why, rows, last_hash) over raw lines: JSON, seq, prev, kind, amount AND the HMAC sig."""
    prev, out = ZERO, []
    for i, line in enumerate(lines):
        try:
            r = json.loads(line)
        except ValueError:
            return False, f"row {i} is not JSON", out, prev
        if not isinstance(r, dict):
            return False, f"row {i} is not an object", out, prev
        if r.get("seq") != i:
            return False, f"row {i} carries seq {r.get('seq')}", out, prev
        if r.get("prev") != prev:
            return False, f"row {i} prev hash does not match row {i - 1}", out, prev
        if r.get("kind") not in KINDS or type(r.get("amount")) is not int or r["amount"] < 0:
            return False, f"row {i} has a bad kind or amount", out, prev
        if set(r) - set(ROW_KEYS) - {"sig"}:
            return False, f"row {i} carries unknown fields", out, prev
        sig = r.get("sig")
        if not isinstance(sig, str) or not hmac.compare_digest(sig, _sig(r, key)):
            return False, f"row {i} has {'no' if not sig else 'a bad'} HMAC sig (appended or edited by hand)", out, prev
        out.append(r)
        prev = _h(line)
    return True, "ok", out, prev


def _verified():
    """(rows, last_hash) of the verified ledger, cached on (size, mtime). Raises EconomyBroken."""
    try:
        st = os.stat(LEDGER)
    except OSError:
        return [], ZERO
    ck = (LEDGER, _key_path(), st.st_size, st.st_mtime_ns)
    hit = _ROW_CACHE.get("v")
    if hit and hit[0] == ck:
        return hit[1], hit[2]
    lines = _lines()
    if not lines:
        return [], ZERO
    ok, why, R, last = _verify_lines(lines, _key())
    if not ok:
        raise EconomyBroken(f"ledger chain broken: {why}")
    _ROW_CACHE["v"] = (ck, R, last)
    return R, last


@contextlib.contextmanager
def _ledger_lock(timeout=None):
    """Thread lock plus an exclusive flock on the ledger, each waited on for at most LOCK_TIMEOUT seconds."""
    timeout = LOCK_TIMEOUT if timeout is None else timeout
    if not _LOCK.acquire(timeout=timeout):
        raise EconomyBusy(f"economy lock busy for {timeout}s (another thread)")
    try:
        os.makedirs(STATE, exist_ok=True)
        with open(LEDGER, "a+b") as f:
            end = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= end:
                        raise EconomyBusy(f"ledger flock held elsewhere for {timeout}s") from None
                    time.sleep(0.02)
            try:
                yield f
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    finally:
        _LOCK.release()


def _append(rows):
    """Append (kind, frm, to, amount, ref, memo) rows atomically, each chained to the previous row's bytes and
    HMAC-signed. Writes genesis first when the ledger is empty. Refuses (EconomyBroken) on a broken chain."""
    out = []
    with _ledger_lock() as f:
        empty = _ledger_empty()
        key = _key(create=empty)
        if empty:
            rows = _genesis_rows() + [r for r in rows if r[4] != "genesis"]
            prev, seq = ZERO, 0
        else:
            R, prev = _verified()
            seq = len(R)
        buf = b""
        for kind, frm, to, amount, ref, memo in rows:
            if kind not in KINDS:
                raise ValueError(f"bad kind {kind}")
            amount = int(amount)
            if amount < 0:
                raise ValueError("amount must be >= 0")
            row = {"ts": _now(), "seq": seq, "prev": prev, "kind": kind, "from": frm, "to": to,
                   "amount": amount, "ref": ref or "", "memo": memo or ""}
            row["sig"] = _sig(row, key)
            line = json.dumps(row, ensure_ascii=True, separators=(",", ":")).encode()
            buf += line + b"\n"
            out.append(row)
            prev, seq = _h(line), seq + 1
        f.seek(0, os.SEEK_END)
        f.write(buf)   # one write per batch
        f.flush()
        os.fsync(f.fileno())
    return out


def ensure():
    """Create the ledger with the genesis roster if it does not exist yet."""
    if _ledger_empty():
        _append([])


def rows():
    """The VERIFIED ledger rows. Raises EconomyBroken on any bad sig, prev, seq or a missing key."""
    return list(_verified()[0])


def verify_chain():
    """(ok, n_rows, why). Any edited, inserted, dropped, reordered or unsigned row breaks the chain."""
    try:
        lines = _lines()
    except OSError:
        return True, 0, "no ledger yet"
    if not lines:
        return True, 0, "empty ledger"
    try:
        key = _key()
    except EconomyBroken as e:
        return False, len(lines), str(e)
    ok, why, _, _ = _verify_lines(lines, key)
    return ok, len(lines), why


def balances(R=None):
    """Wallets by replay of the verified ledger. Escrow is a real account (stakes and bonds sit there)."""
    bal = {}
    for r in rows() if R is None else R:
        a = r["amount"]
        if r["from"] not in SOURCES:
            bal[r["from"]] = bal.get(r["from"], 0) - a
        if r["to"] != SINK:
            bal[r["to"]] = bal.get(r["to"], 0) + a
    return bal


def participants(R=None):
    return [r["to"] for r in (rows() if R is None else R) if r["kind"] == "mint" and r["from"] == "genesis"
            and r["to"] not in RETIRED]


def balance(bot):
    return balances().get(bot, 0)


def broke(bot):
    return balance(bot) < BROKE


def register(name):
    """Add a participant with the genesis grant, once. Code-only: no chat tool reaches it."""
    ensure()
    name = str(name).strip()
    if not re.fullmatch(r"[\w.@:-]{1,64}", name) or name in (TREASURY, ESCROW, SINK) + SOURCES:
        raise ValueError(f"bad participant name {name!r}")
    if name in participants():
        return False
    _append([("mint", "genesis", name, GENESIS_EACH, "genesis", "register")])
    return True


def supply(R=None):
    R = rows() if R is None else R
    minted = sum(r["amount"] for r in R if r["kind"] == "mint")
    burnt = sum(r["amount"] for r in R if r["to"] == SINK)
    return minted, burnt


def migrate():
    """One-time: re-sign an UNSIGNED ledger (the pre-HMAC genesis rows) in place under a new chain key.
    Refuses if the old hash chain is broken, any row is already signed, or a non-genesis row is unsigned.
    Keeps <ledger>.pre-hmac."""
    if _ledger_empty():
        return "migrate: no ledger yet (the first write creates a signed one)"
    backup = LEDGER + ".pre-hmac"
    with _ledger_lock(timeout=10):
        lines = _lines()
        R = [json.loads(x) for x in lines]
        if all("sig" in r for r in R):
            ok, _, why = verify_chain()
            return f"migrate: already signed (chain {'OK' if ok else 'BROKEN: ' + why})"
        if any("sig" in r for r in R):
            return "migrate: REFUSED, the ledger mixes signed and unsigned rows"
        prev = ZERO
        for i, (line, r) in enumerate(zip(lines, R)):
            if r.get("seq") != i or r.get("prev") != prev:
                return f"migrate: REFUSED, the unsigned hash chain is already broken at row {i}"
            prev = _h(line)
        bad = [r.get("seq") for r in R if r.get("from") != "genesis" or r.get("kind") != "mint"]
        if bad:
            return f"migrate: REFUSED, non-genesis unsigned rows {bad[:5]} cannot be vouched for"
        if not os.path.exists(backup):
            shutil.copy2(LEDGER, backup)
        key = _key(create=True)
        prev, buf = ZERO, b""
        for r in R:
            row = {k: r[k] for k in ROW_KEYS}
            row["prev"] = prev
            row["sig"] = _sig(row, key)
            line = json.dumps(row, ensure_ascii=True, separators=(",", ":")).encode()
            buf += line + b"\n"
            prev = _h(line)
        tmp = LEDGER + f".migrate.{os.getpid()}"
        with open(tmp, "wb") as f:
            f.write(buf)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, LEDGER)
    _ROW_CACHE.clear()
    ok, n, why = verify_chain()
    return f"migrate: re-signed {n} genesis rows; chain {'OK' if ok else 'BROKEN: ' + why}; backup {backup}"


# ---------------------------------------------------------------- who is acting

@contextlib.contextmanager
def acting_as(bot):
    """Debits inside this block land on `bot`. A ContextVar, so gnoc_agent._parallel's copied contexts carry it
    into tool threads."""
    tok = _BOT.set(bot)
    try:
        yield
    finally:
        _BOT.reset(tok)


def current_bot(default="worker"):
    return _BOT.get() or os.environ.get("GNOC_ECON_BOT") or default


def bot_for(lane=None, default="worker"):
    """The bot behind a lane name: a roster name inside it wins, gnoc-agent is the lead, else the acting bot."""
    s = str(lane or "").lower()
    for name in sorted(participants() or ROSTER, key=len, reverse=True):
        if name and name in s:
            return name
    if "gnoc-agent" in s or s == "chat":
        return "lead"
    return _BOT.get() or default


def bot_for_model(model, host="", lead=None):
    """Roster name for a routed (model, host): phone-1.7b/phone-4b, lead (desktop), else worker. Standalone build: no cloud bots."""
    m = f"{model or ''} {host or ''}".lower()
    if "phone" in m:
        return "phone-1.7b" if "1.7b" in m else "phone-4b"
    if lead and tuple(lead) == (model, host):
        return "lead"
    if str(host or "").lower() == "desktop":
        return "lead"
    return "worker"


# ---------------------------------------------------------------- mint / burn / slash

def mint(kind, to, amount, ref, memo="", settler=None):
    _gate(settler)
    if amount <= 0:
        return None
    ensure()
    return _append([("mint", "mint", to, amount, ref, memo or kind)])


def _seen(ref, kind=None):
    return any(r["ref"] == ref and (kind is None or r["kind"] == kind) for r in rows())


def _affordable(bot, cost):
    """Clamp a burn to the bot's balance so no wallet goes negative (2026-10-23: the lead replayed to -655 after
    the first rate table); a bot at 0 is `broke` and loses lead duty, it is never stopped from working."""
    try:
        return max(0, min(int(cost), int(balance(bot))))
    except Exception:
        return 0


def debit_probe(program, bot=None, n=1, ref=None):
    """Every gated probe costs 1 RC from the acting bot (burnt)."""
    if not _real(program):
        return None
    ensure()
    bot = bot or current_bot()
    if bot not in participants():
        bot = "worker"
    cost = _affordable(bot, max(0, int(n)))   # a broke bot keeps hunting and burns nothing: wallets floor at 0
    return _append([("burn", bot, SINK, cost, ref or f"probe:{program}", "probe")]) if cost else None


def llm_rate(model):
    m = str(model or "").lower()
    if "opus" in m:
        return RATES["opus"]
    if "sonnet" in m:
        return RATES["sonnet"]
    if "haiku" in m:
        return RATES["haiku"]
    size = re.search(r"(\d+(?:\.\d+)?)\s*b\b", m.replace("-", " ").replace("_", " "))
    if size and float(size.group(1)) <= 4:
        return RATES["small"]
    return RATES["9b"]


def debit_llm(bot, model, tokens):
    """One LLM turn: ceil(tokens/10000) * rate(model) RC burnt. GNOC_ECON_OFF=1 or an unknown bot books nothing."""
    if os.environ.get("GNOC_ECON_OFF") == "1":
        return None
    ensure()
    if bot not in participants():
        return None
    cost = _affordable(bot, math.ceil(max(0, int(tokens)) / 10000) * llm_rate(model))
    return _append([("burn", bot, SINK, cost, "llm", str(model)[:60])]) if cost else None


def slash(bot, amount, ref, memo, settler=None):
    _gate(settler)
    ensure()
    return _append([("slash", bot, TREASURY, amount, ref, memo)])


# ---------------------------------------------------------------- bonds

def _bond_ref(program, hyp_id):
    return f"bond:{program}:{hyp_id}"


def bond_state(ref):
    """(bonder, amount) of an OPEN bond, else None."""
    holder, amt, closed = None, 0, False
    for r in rows():
        if r["ref"] != ref:
            continue
        if r["kind"] == "bond" and r["to"] == ESCROW:
            holder, amt, closed = r["from"], r["amount"], False
        elif r["from"] == ESCROW and r["kind"] in ("refund", "bond"):
            closed = True
    return (holder, amt) if holder and not closed else None


def post_bond(program, hyp_id, bot, amount=BOND, ref=None):
    ref = ref or _bond_ref(program, hyp_id)
    if any(r["ref"] == ref and r["kind"] == "bond" for r in rows()):
        return None
    if balance(bot) < amount:
        return None
    return _append([("bond", bot, ESCROW, amount, ref, "lane bond")])


def refund_bond(program, hyp_id, settler=None, ref=None):
    _gate(settler)
    st = bond_state(ref or _bond_ref(program, hyp_id))
    if not st:
        return None
    return _append([("refund", ESCROW, st[0], st[1], ref or _bond_ref(program, hyp_id), "bond refunded: floor receipt")])


def forfeit_bond(program, hyp_id, settler=None, ref=None):
    _gate(settler)
    st = bond_state(ref or _bond_ref(program, hyp_id))
    if not st:
        return None
    return _append([("bond", ESCROW, TREASURY, st[1], ref or _bond_ref(program, hyp_id), "bond forfeit: abandoned lane")])


# ---------------------------------------------------------------- hypothesis futures

def _mref(program, hyp_id):
    return f"mkt:{program}:{hyp_id}"


def market(ref, R=None):
    """{'stakes': [(bot, side, amount)], 'long', 'short', 'closed': outcome|None} for a market ref."""
    st, closed = [], None
    for r in rows() if R is None else R:
        if r["ref"] != ref:
            continue
        if r["kind"] == "stake" and r["to"] == ESCROW:
            st.append((r["from"], r["memo"].split(":")[0], r["amount"]))
        elif r["kind"] in ("resolve", "refund") and r["memo"].startswith("close:"):
            closed = r["memo"][6:]
    long_ = sum(a for _, s, a in st if s == "long")
    short = sum(a for _, s, a in st if s == "short")
    return {"stakes": st, "long": long_, "short": short, "closed": closed}


def stipend(bot):
    """Treasury pays a broke acting bot STIPEND RC, at most STIPEND_PER_DAY times a day. The lead and worker wallets
    sat at 0 RC from 02:28Z on 2026-10-23 (90 RC burned per 35B call): every post and bet was refused, every
    hypothesis was capped at BUDGET_MIN probes and the budget refusal kept advising 'bet more'. Returns the row
    or None."""
    try:
        if bot not in participants() or bot in (TREASURY, ESCROW) or balance(bot) >= MIN_POST:
            return None
        day = _now()[:10]
        ref = f"stipend:{bot}:{day}"
        paid = sum(1 for r in rows() if r["ref"] == ref)
        if paid >= STIPEND_PER_DAY or balance(TREASURY) < STIPEND:
            return None
        return _append([("refund", TREASURY, bot, STIPEND, ref, "stipend")])[0]
    except (EconomyBroken, EconomyBusy, OSError, PermissionError):
        return None


def post(program, hyp_id, author_bot, stake=MIN_POST):
    """The author opens the market by staking >= MIN_POST LONG."""
    ensure()
    ref = _mref(program, hyp_id)
    stake = int(stake)
    if stake < MIN_POST:
        return f"refused: the author stakes at least {MIN_POST} RC"
    if author_bot not in participants():
        return f"refused: unknown bot {author_bot}"
    if any(r["ref"] == ref and r["kind"] == "stake" for r in rows()):
        return f"refused: market {ref} already posted"
    stipend(author_bot)
    if balance(author_bot) < stake:
        return f"refused: {author_bot} holds {balance(author_bot)} RC"
    _append([("stake", author_bot, ESCROW, stake, ref, "long:post")])
    return f"posted {ref}: {author_bot} long {stake}"


def bet(program, hyp_id, bot, side, stake):
    ensure()
    ref = _mref(program, hyp_id)
    side, stake = str(side).lower(), int(stake)
    if side not in ("long", "short"):
        return "refused: side is long or short"
    if stake < 1:
        return "refused: stake at least 1 RC"
    if bot not in participants():
        return f"refused: unknown bot {bot}"
    m = market(ref)
    if not m["stakes"]:
        if not _hunt_hyp(program, hyp_id):
            return f"refused: no market {ref} and no such hypothesis in the hunt ledger (hunt_hypothesis action=list)"
        # the hypothesis exists but its market was never posted (the author was broke when it was added): the
        # bettor opens it now, as author
        out = post(program, hyp_id, bot, max(MIN_POST, stake))
        if not out.startswith("posted"):
            return out
        return f"{out}; budget now {budget(program, hyp_id)} probes"
    if m["closed"]:
        return f"refused: market {ref} is closed ({m['closed']})"
    stipend(bot)
    if balance(bot) < stake:
        return f"refused: {bot} holds {balance(bot)} RC"
    _append([("stake", bot, ESCROW, stake, ref, f"{side}:bet")])
    return f"{bot} {side} {stake} on {ref}; budget now {budget(program, hyp_id)} probes"


def budget(program, hyp_id):
    """Belief allocates compute: 2 x the LONG pool, clamped to [20, 200]."""
    return max(BUDGET_MIN, min(BUDGET_MAX, 2 * market(_mref(program, hyp_id))["long"]))


def _settle_pool(ref, stakes, winning, outcome, house=HOUSE):
    """Rows that pay a closed pool: winners get stake back plus a pro rata share of the losers' pool minus the
    house cut; dust and the house cut go to treasury; no winners -> the losers' pool goes to treasury."""
    win = [(b, a) for b, s, a in stakes if s in winning]
    lose = sum(a for _, s, a in stakes if s not in winning)
    wpool = sum(a for _, a in win)
    out = []
    if not win:
        return [("resolve", ESCROW, TREASURY, lose, ref, f"close:{outcome}")]
    cut = int(math.ceil(lose * house))   # the house takes at least 1 RC of any non-empty losing pool
    dist = lose - cut
    paid = 0
    for b, a in win:
        share = a + (dist * a) // wpool
        paid += share
        out.append(("resolve", ESCROW, b, share, ref, f"{outcome}:payout"))
    rest = wpool + lose - paid
    out.append(("resolve", ESCROW, TREASURY, rest, ref, f"close:{outcome}"))
    return out


def resolve(program, hyp_id, outcome, settler=None):
    """Close a hypothesis market. Only adjudicating code (settler token) may call it."""
    _gate(settler)
    outcome = str(outcome).lower()
    if outcome not in OUTCOMES:
        raise ValueError(f"outcome must be one of {OUTCOMES}")
    ref = _mref(program, hyp_id)
    m = market(ref)
    if not m["stakes"] or m["closed"]:
        return None
    if outcome == "unfired":
        out = [("refund", ESCROW, b, a, ref, "unfired:refund") for b, _, a in m["stakes"]]
        out.append(("refund", ESCROW, TREASURY, 0, ref, "close:unfired"))
    else:
        out = _settle_pool(ref, m["stakes"], ("long",) if outcome in ("proven", "lead") else ("short",), outcome)
    return _append(out)


def brier(bot, R=None):
    """Mean squared error of the bot's implied P(proven-or-lead) over resolved (non-unfired) markets."""
    R = rows() if R is None else R
    refs = {r["ref"] for r in R if r["ref"].startswith("mkt:")}
    errs = []
    for ref in sorted(refs):
        m = market(ref, R)
        if m["closed"] not in ("proven", "lead", "dead"):
            continue
        lo = sum(a for b, s, a in m["stakes"] if b == bot and s == "long")
        sh = sum(a for b, s, a in m["stakes"] if b == bot and s == "short")
        if lo + sh == 0:
            continue
        p, o = lo / (lo + sh), 1.0 if m["closed"] in ("proven", "lead") else 0.0
        errs.append((p - o) ** 2)
    return round(sum(errs) / len(errs), 4) if errs else None


def routing_weights(candidates=None, R=None):
    """{bot: weight} over non-broke bots, weight ~ wealth x (1 - brier), summing to 1. Unscored bots get 0.25."""
    R = rows() if R is None else R
    bal = balances(R)
    names = list(candidates) if candidates else [p for p in participants(R) if p != TREASURY]
    raw = {}
    for n in names:
        w = bal.get(n, 0)
        if w < BROKE:
            continue
        b = brier(n, R)
        raw[n] = w * (1.0 - (0.25 if b is None else b))
    tot = sum(raw.values())
    if tot <= 0:
        return {n: 1.0 / len(raw) for n in raw} if raw else {}
    return {n: v / tot for n, v in raw.items()}


def route_role(role, roles=("lead", "worker", "hunter", "chat", "brain")):
    """For gnoc_agent.resolve under GNOC_ECONOMY_ROUTING=1: a broke role hands its seat to the richest
    calibrated non-broke role; otherwise the role is unchanged."""
    if role not in participants() or not broke(role):
        return role
    w = routing_weights([r for r in roles if r != role])
    return max(w, key=w.get) if w else role


# ---------------------------------------------------------------- filing futures (the dupe estimator)

def _fref(program, key):
    return f"fil:{program}:{key}"


def filing_market(action, program, key, bot=None, side=None, stake=0, cls="", settler=None, outcome=None):
    """open | bet | resolve a filing market on resolved|duplicate|n-a. Resolve needs the settler token."""
    ensure()
    ref = _fref(program, key)
    if action == "open":
        if any(r["ref"] == ref for r in rows()):
            return f"{ref} already open"
        _append([("stake", bot or "lead", ESCROW, 0, ref, f"open:{str(cls)[:40]}")])
        return f"opened {ref}"
    if action == "bet":
        side = str(side).lower()
        if side not in FILING_SIDES:
            return f"refused: side is one of {', '.join(FILING_SIDES)}"
        if bot not in participants():
            return f"refused: unknown bot {bot}"
        m = _filing(ref)
        if m["closed"]:
            return f"refused: {ref} is closed"
        if not m["opened"]:
            return f"refused: no filing market {ref}"
        stake = int(stake)
        if stake < 1 or balance(bot) < stake:
            return f"refused: stake must be 1..{balance(bot)}"
        _append([("stake", bot, ESCROW, stake, ref, f"{side}:filing")])
        return f"{bot} {side} {stake} on {ref}"
    if action == "resolve":
        _gate(settler)
        m = _filing(ref)
        if not m["opened"] or m["closed"]:
            return None
        return _append(_settle_pool(ref, m["stakes"], (outcome,), outcome))
    return "action is open, bet or resolve"


def _filing(ref, R=None):
    st, closed, opened, cls = [], None, False, ""
    for r in rows() if R is None else R:
        if r["ref"] != ref:
            continue
        if r["kind"] == "stake" and r["memo"].startswith("open:"):
            opened, cls = True, r["memo"][5:]
        elif r["kind"] == "stake" and r["to"] == ESCROW:
            st.append((r["from"], r["memo"].split(":")[0], r["amount"]))
        elif r["memo"].startswith("close:"):
            closed = r["memo"][6:]
    return {"stakes": st, "closed": closed, "opened": opened, "cls": cls}


def dupe_odds(cls="", program=""):
    """P(duplicate) from resolved filing-market history, Laplace-smoothed; matches class and/or program."""
    R = rows()
    n = d = 0
    for ref in {r["ref"] for r in R if r["ref"].startswith("fil:")}:
        m = _filing(ref, R)
        if not m["closed"]:
            continue
        if program and ref.split(":")[1] != program and not cls:
            continue
        if cls and cls.lower() not in m["cls"].lower():
            continue
        n += 1
        d += m["closed"] == "duplicate"
    return round((d + 1) / (n + 2), 3), n


def budget_refusal(program, hyp_id):
    """None, or the refusal line when the hypothesis has spent its probe budget. The probe count is the one
    gnoc_hunt.log_probe keeps (the sender drives it). Never raises: a broken economy enforces nothing."""
    try:
        if not program or not hyp_id or not _real(program):
            return None
        probes, _ = _hunt_floor(program, hyp_id)
        b = budget(program, hyp_id)
        if probes >= b:
            bot = current_bot("lead")
            if balance(bot) < 1 and stipend(bot) is None:
                return (f"budget exhausted for {hyp_id} ({probes} probes logged, budget {b}) and {bot} holds 0 RC with "
                        "the treasury stipend spent: pivot to the next open hypothesis or add a new one; no bet can "
                        "raise this budget today")
            return (f"budget exhausted for {hyp_id}: bet more or pivot ({probes} probes logged, budget {b} = "
                    f"2 x the LONG pool; econ_bet program={program} id={hyp_id} side=long stake=10 raises it)")
    except Exception as e:  # noqa: BLE001
        _log(f"budget check skipped for {program}/{hyp_id}: {type(e).__name__}: {e}")
    return None


# ---------------------------------------------------------------- non-AI evidence the economy re-reads

def _hunt_hyp(program, hyp_id):
    """The hypothesis row gnoc_hunt keeps (probes counted by log_probe, bursts by mark_burst), or {}."""
    if not program or not hyp_id:
        return {}
    import gnoc_hunt
    return gnoc_hunt._find_hyp(gnoc_hunt.load(program).get("hypotheses", []), hyp_id) or {}


def _hunt_floor(program, hyp_id):
    """(probes, bursts) RECOMPUTED from gnoc_hunt state, never from a typed outcome row."""
    h = _hunt_hyp(program, hyp_id)
    return int(h.get("probes") or 0), int(h.get("bursts") or 0)


def _burst_ref(program, hyp_id):
    return f"burst:{program}:{hyp_id}"


def _floor_met(program, hyp_id):
    """Floor = >= FLOOR probes AND a burst in gnoc_hunt state AND the signed burst debit the race hook wrote."""
    if not program or not hyp_id:
        return False
    probes, bursts = _hunt_floor(program, hyp_id)
    return probes >= FLOOR and bursts >= 1 and _seen(_burst_ref(program, hyp_id), "burn")


def _oracle_pass(program, oracle_id):
    """The oracle COMMIT row when gnoc_oracle holds a SIGNED passed verdict for oracle_id, else None.
    Order: gnoc_oracle.passed_verified(program, oracle_id) if it exists; else gnoc_oracle.oracles(), which folds
    only rows whose seal-key HMAC `sig` verifies (first verdict final); else the sig is checked here. A verdict
    row with no sig is never a pass."""
    if not program or not oracle_id:
        return None
    import gnoc_oracle as O
    try:
        fn = getattr(O, "passed_verified", None)
        if callable(fn):
            if not fn(program, oracle_id):
                return None
            return O.oracles(program).get(oracle_id)
        if callable(getattr(O, "_sig_ok", None)):
            row = O.oracles(program).get(oracle_id)
            return row if row and row.get("status") == "passed" and O._sig_ok(row.get("verdicts", [{}])[0]) else None
        R = O._rows(program)
    except ValueError:
        return None
    commit = next((r for r in R if r.get("id") == oracle_id and "sha256" in r and r.get("event") is None), None)
    if not commit:
        return None
    key = O._secret()
    for r in R:
        if r.get("id") != oracle_id or r.get("event") != "verdict":
            continue
        sig = r.get("sig")   # the FIRST signed verdict is final, as gnoc_oracle folds it
        body = {k: v for k, v in r.items() if k != "sig"}
        enc = json.dumps(body, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        if isinstance(sig, str) and hmac.compare_digest(sig, hmac.new(key, enc.encode(), hashlib.sha256).hexdigest()):
            return commit if r.get("status") == "passed" else None
    return None


def _crown_kinds(crown):
    try:
        import gnoc_oracle as O
        return tuple(O.CROWN_CLASSES.get(crown, ())) + (crown,)
    except Exception:  # noqa: BLE001
        return (crown,)


# ---------------------------------------------------------------- bounty board

def bounties(R=None):
    R = rows() if R is None else R
    B = {}
    for r in R:
        if not r["ref"].startswith("bty:"):
            continue
        b = B.setdefault(r["ref"], {"id": r["ref"][4:], "state": "open", "claimant": None})
        if r["kind"] == "stake" and r["to"] == ESCROW and r["memo"].startswith("{"):
            try:
                meta = json.loads(r["memo"])
            except ValueError:
                meta = {}
            b.update(meta, amount=r["amount"], funder=r["from"], posted=_epoch(r["ts"]))
        elif r["kind"] == "bond" and r["to"] == ESCROW:
            b["claimant"], b["state"], b["claimed"] = r["from"], "claimed", _epoch(r["ts"])
        elif r["memo"] == "reopen:abandoned":
            b["claimant"], b["state"] = None, "open"
        elif r["memo"].startswith("close:"):
            b["state"] = r["memo"][6:]
    return B


def bounty(action, program=None, crown=None, amount=0, id=None, bot=None, poster="orchestrator", settler=None,
           oracle_id=None):
    """post | claim | settle | list. A post is funded from the POSTER's own wallet; only the settler may fund
    one from the treasury. Settle needs the settler token AND an oracle PASS for the bounty's crown whose prober
    is the claimer."""
    ensure()
    if action == "list":
        sweep_expired()
        return bounties()
    if action == "post":
        amount = int(amount)
        if not program or not crown or not 1 <= amount <= BOUNTY_MAX:
            return f"refused: post needs program, crown and 1..{BOUNTY_MAX} RC"
        if settler is not None:
            _gate(settler)
            funder = TREASURY
        else:
            funder = str(poster or "")
            if funder not in participants() or funder == TREASURY:
                return f"refused: {funder or 'poster'} is not a wallet (a bounty is paid from the poster's own RC)"
        if balance(funder) < amount:
            return f"refused: {funder} holds {balance(funder)} RC"
        bid = f"B{len(bounties()) + 1}"
        meta = json.dumps({"program": program, "crown": str(crown)[:60], "poster": str(poster)[:30],
                           "expires": int(time.time()) + BOUNTY_TTL}, separators=(",", ":"))
        _append([("stake", funder, ESCROW, amount, f"bty:{bid}", meta)])
        return f"posted bounty {bid}: {crown} on {program} pays {amount} RC from {funder} (72h)"
    b = bounties().get(f"bty:{id}")
    if not b:
        return f"refused: no bounty {id}"
    if action == "claim":
        if b["state"] != "open":
            return f"refused: bounty {id} is {b['state']}"
        if bot in (b.get("poster"), b.get("funder")):
            return f"refused: {bot} posted bounty {id} and cannot claim it"
        if bot not in participants() or balance(bot) < BOND:
            return f"refused: {bot} cannot bond {BOND} RC"
        _append([("bond", bot, ESCROW, BOND, f"bty:{id}", "bounty claim")])
        return f"{bot} claimed bounty {id} (bond {BOND})"
    if action == "settle":
        _gate(settler)
        if b["state"] != "claimed":
            return f"refused: bounty {id} is {b['state']}"
        commit = _oracle_pass(b.get("program"), oracle_id)
        if not commit:
            return f"refused: no signed oracle PASS {oracle_id} on {b.get('program')}"
        if commit.get("kind") not in _crown_kinds(b.get("crown")):
            return f"refused: oracle {oracle_id} proves {commit.get('kind')}, the bounty crown is {b.get('crown')}"
        if _epoch(str(commit.get("ts", ""))[:19] + "Z") < b.get("posted", 0) - 1:
            return f"refused: oracle {oracle_id} was committed before bounty {id} was posted"
        prober = lineage(b.get("program"), commit.get("hyp_id")).get("prober")
        if prober != b["claimant"]:
            return f"refused: the lineage prober of {commit.get('hyp_id')} is {prober}, not the claimer {b['claimant']}"
        ref = f"bty:{id}"
        if _seen(ref, "royalty"):
            return f"refused: bounty {id} already paid"
        return _append([("royalty", ESCROW, b["claimant"], b["amount"], ref, f"bounty paid: {oracle_id}"),
                        ("refund", ESCROW, b["claimant"], BOND, ref, "close:settled")])
    return "action is post, claim, settle or list"


def _last_probe(bot, program, R):
    t = 0.0
    for r in R:
        if r["kind"] == "burn" and r["from"] == bot and (r["ref"] == f"probe:{program}" or
                                                          r["ref"].startswith(f"burst:{program}:")):
            t = max(t, _epoch(r["ts"]))
    return t


def sweep_expired(now=None):
    """Expire bounties past 72h (escrow back to the funder, a claimer's bond to treasury) and forfeit the bond of
    a claimer with no probe on the program for BOUNTY_ABANDON seconds (the bounty reopens)."""
    now = now or time.time()
    R = rows()
    out = []
    for ref, b in bounties(R).items():
        if b["state"] not in ("open", "claimed"):
            continue
        if b.get("expires") and now > b["expires"]:
            rr = [("refund", ESCROW, b.get("funder") or TREASURY, b.get("amount", 0), ref, "bounty expired")]
            if b["state"] == "claimed":
                rr.append(("bond", ESCROW, TREASURY, BOND, ref, "bond forfeit: bounty expired"))
            rr.append(("refund", ESCROW, TREASURY, 0, ref, "close:expired"))
            out += _append(rr)
        elif b["state"] == "claimed":
            last = max(b.get("claimed", 0), _last_probe(b["claimant"], b.get("program"), R))
            if now - last > BOUNTY_ABANDON:
                out += _append([("bond", ESCROW, TREASURY, BOND, ref, "reopen:abandoned")])
    return out


# ---------------------------------------------------------------- lineage (signed rows; an unsigned row is ignored)

def _lin_append(row):
    os.makedirs(STATE, exist_ok=True)
    ensure()
    row = {k: v for k, v in row.items() if v not in (None, "") and k != "sig"}
    row["ts"] = _now()
    row["sig"] = _sig(row, _key(), b"lineage")
    with open(LINEAGE, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(json.dumps(row, separators=(",", ":")) + "\n")
        f.flush()
        fcntl.flock(f, fcntl.LOCK_UN)


def _lin_rows():
    try:
        with open(LINEAGE) as f:
            raw = f.read().splitlines()
    except OSError:
        return []
    key, out = _key(), []
    for x in raw:
        try:
            r = json.loads(x)
        except ValueError:
            continue
        if isinstance(r, dict) and isinstance(r.get("sig"), str) and \
                hmac.compare_digest(r["sig"], _sig(r, key, b"lineage")):
            out.append(r)
    return out


def lineage(program, hyp_id=None, slug=None, report_id=None):
    """Merged lineage over SIGNED rows: first non-empty author / prober / verifier / writer across linked rows."""
    L = _lin_rows()
    keys = {("hyp_id", hyp_id), ("slug", slug), ("report_id", str(report_id) if report_id else None)}
    keys = {k for k in keys if k[1]}
    for _ in range(3):   # expand through link rows (hyp <-> slug <-> report)
        grp = [r for r in L if r.get("program") == program and any(str(r.get(k)) == v for k, v in keys)]
        new = keys | {(k, str(r[k])) for r in grp for k in ("hyp_id", "slug", "report_id") if r.get(k)}
        if new == keys:
            break
        keys = new
    grp = [r for r in L if r.get("program") == program and any(str(r.get(k)) == v for k, v in keys)]
    out = {"program": program}
    for k in ("hyp_id", "slug", "report_id", "author", "prober", "verifier", "writer"):
        for r in grp:
            if r.get(k):
                out[k] = r[k]
                break
    return out


def link_report(program, report_id, hyp_id=None, slug=None, writer=None):
    _lin_append({"program": program, "report_id": str(report_id), "hyp_id": hyp_id, "slug": slug, "writer": writer})


def _split(total, lin, ref, memo, settler):
    """Mint `total` along lineage shares; an unfilled role's share is not minted."""
    paid, known = {}, set(participants())
    for role, share in SHARES.items():
        b = lin.get(role)
        if b:
            b = b if b in known else "worker"   # an unknown name never gets a genesis grant through lineage
            paid[b] = paid.get(b, 0) + int(round(total * share))
    for b, amt in paid.items():
        mint(memo, b, amt, ref, memo, settler=settler)
    return paid


# ---------------------------------------------------------------- the one public hook

def _real(program):
    if os.environ.get("GNOC_ECON_OFF") == "1":
        return False
    if not REQUIRE_TARGET:
        return True
    p = str(program or "")
    return bool(re.fullmatch(r"[\w][\w.-]*", p)) and not p.startswith(("_", "zz-")) and \
        os.path.isfile(os.path.join(WS, "targets", p, "SCOPE.txt"))


def on_event(kind, **kw):
    """Entry point for every hook. Never raises and never waits more than LOCK_TIMEOUT for a lock: a busy or
    broken economy skips the event with one logged line."""
    try:
        prog = kw.get("program") or (kw.get("row") or {}).get("target") or (kw.get("row") or {}).get("program")
        if not _real(prog):
            return None
        if not _LOCK.acquire(timeout=LOCK_TIMEOUT):
            raise EconomyBusy(f"economy lock busy for {LOCK_TIMEOUT}s (another thread)")
        try:
            try:
                sweep_expired()
            except EconomyBusy:
                raise
            except PermissionError:
                pass
            return _on_event(kind, **kw)
        finally:
            _LOCK.release()
    except EconomyBusy as e:
        _log(f"skipped {kind} for {kw.get('program')}: {e}")
        return f"economy: skipped {kind} ({e})"
    except EconomyBroken as e:
        _log(f"economy DISABLED, skipped {kind}: {e}")
        return f"economy: disabled ({e})"
    except Exception as e:  # noqa: BLE001 - the economy can never block a hunt or a ledger write
        _log(f"skipped {kind}: {type(e).__name__}: {e}")
        return f"economy: {type(e).__name__}: {e}"


def _on_event(kind, **kw):
    ensure()
    tok = _settler()
    program, hyp = kw.get("program"), kw.get("hyp_id")
    if kind == "hyp-add":
        bot = kw.get("bot") or current_bot("lead")
        _lin_append({"program": program, "hyp_id": hyp, "author": bot})
        return post(program, hyp, bot, kw.get("stake", MIN_POST))
    if kind == "probe":
        bot = kw.get("bot") or bot_for(kw.get("lane"))
        lin = lineage(program, hyp)
        if not lin.get("prober"):
            _lin_append({"program": program, "hyp_id": hyp, "prober": bot})
        post_bond(program, hyp, bot)
        n, b = _hunt_floor(program, hyp)[0], budget(program, hyp)
        return f"over budget: {n} probes vs {b}" if n and n > b else None
    if kind == "burst":
        bot = kw.get("bot") or current_bot()
        debit_probe(program, bot, kw.get("n", 1), ref=_burst_ref(program, hyp) if hyp else None)
        if _floor_met(program, hyp):   # recomputed from gnoc_hunt state, never the typed `probes`
            refund_bond(program, hyp, settler=tok)
        return None
    if kind == "edge-proven":
        # non-minting: a model can make an edge "proven" by naming a file it wrote. Lineage only.
        _lin_append({"program": program, "edge": kw.get("edge"), "prober": kw.get("bot") or current_bot()})
        return None
    if kind == "oracle-pass":
        return _oracle_event(program, kw.get("ref"), kw.get("lane"), tok)
    if kind == "ready":
        _gate(kw.get("settler"))   # only `gnoc_economy.py ready-hook` (scripts/reports.sh ready) passes it
        slug = kw.get("slug")
        ref = f"ready:{program}:{slug}"
        if not slug or _seen(ref, "mint"):
            return None
        _split(MINT["ready"], lineage(program, slug=slug), ref, "ready", tok)
        return "minted ready"
    if kind == "outcome":
        return _outcome(dict(kw.get("row") or kw), bool(kw.get("refused")), tok)
    if kind == "ship":
        return _ship(dict(kw.get("row") or kw))
    if kind == "triage":
        _gate(kw.get("settler"))   # only settle_triage (the h1-feedback sync) passes it
        return _triage(program, kw.get("report_id"), kw.get("state"), tok)
    if kind == "line-advance":
        return _line_advance(program, kw, tok)
    return f"economy: unknown event {kind}"


LINE_PROBE_MINT = 5


def _line_probe_hid(program, wo_id):
    """The hypothesis a work order's station 4 (PROBE) passed on, read from gnoc_line's WO history."""
    import gnoc_line
    wo = gnoc_line.load_wo(program, wo_id) or {}
    for h in reversed(wo.get("history") or []):
        if h.get("station") == 4 and h.get("ok") and h.get("hyp_id"):
            return h["hyp_id"]
    return None


def _line_advance(program, kw, tok):
    """gnoc_line station event: lineage (station -> bot), never a charge. The only mint is station 4 PROBE at a
    floor RECOMPUTED here (gnoc_hunt counts + the signed burst row): +5 once per work order and once per
    hypothesis. Station 6 QA READY is paid by the settler-gated "ready" path; every other station only logs."""
    wo = kw.get("wo_id") or kw.get("wo")
    try:
        station = int(kw.get("station"))
    except (TypeError, ValueError):
        station = None
    if not wo or station is None:
        return None
    bot = kw.get("bot") or current_bot()
    bot = bot if bot in participants() else "worker"
    _lin_append({"program": program, "wo": str(wo), "station": station, "bot": bot,
                 "artifact": str(kw.get("artifact") or "")[:200], "ok": bool(kw.get("ok"))})
    if station != 4 or not kw.get("ok"):
        return "line-advance: logged"
    hid = _line_probe_hid(program, wo)
    if not hid or not _floor_met(program, hid):
        return "line-advance: logged (PROBE floor not verified by code, no mint)"
    wref, href = f"line-probe:{program}:{wo}", f"line-probe-hyp:{program}:{hid}"
    if _seen(wref, "mint") or _seen(href, "mint"):
        return "line-advance: logged (already paid)"
    mint("line-probe", bot, LINE_PROBE_MINT, wref, f"line PROBE floor {hid}", settler=tok)
    _append([("mint", "mint", bot, 0, href, "line PROBE hyp marker")])
    return f"line-advance: minted {LINE_PROBE_MINT} for PROBE floor on {hid}"


def _oracle_event(program, oracle_id, lane, tok):
    """Mint for an oracle PASS only after re-reading the SIGNED verdict, once per oracle id."""
    commit = _oracle_pass(program, oracle_id)
    if not commit:
        _log(f"oracle-pass refused for {program}/{oracle_id}: no signed passed verdict")
        return f"refused: no signed oracle PASS {oracle_id} on {program}"
    ref = f"oracle:{program}:{oracle_id}"
    if _seen(ref, "mint"):
        return None
    hyp = commit.get("hyp_id") or None
    lin = lineage(program, hyp) if hyp else {}
    prover = lin.get("prober") or bot_for(lane)
    if hyp and not lin.get("verifier"):
        _lin_append({"program": program, "hyp_id": hyp, "verifier": prover})
    mint("oracle-pass", prover, MINT["oracle-prover"], ref, "oracle-pass prover", settler=tok)
    if lin.get("author"):
        mint("oracle-pass", lin["author"], MINT["oracle-author"], ref, "oracle-pass author", settler=tok)
    if hyp:
        resolve(program, hyp, "proven", settler=tok)
        refund_bond(program, hyp, settler=tok)
    for b in bounties().values():
        if b.get("program") == program and b["state"] == "claimed":
            bounty("settle", id=b["id"], settler=tok, oracle_id=oracle_id)
    return "minted oracle-pass"


def _outcome(row, refused, tok):
    verdict = str(row.get("verdict") or "").upper()
    program = row.get("target") or row.get("program")
    hyp = row.get("hypothesis")
    bot = bot_for(row.get("lane"))
    key = hashlib.sha256(json.dumps(row, sort_keys=True, default=str).encode()).hexdigest()[:16]
    if refused:
        if verdict == "DEAD" and not _seen(f"slash:{key}"):
            slash(bot, 20, f"slash:{key}", "DEAD with no floor receipt", settler=tok)
            return "slashed 20: floorless DEAD"
        return None
    floor_met = _floor_met(program, hyp)   # RECOMPUTED: the row's own probes / burst / floor are not trusted
    note = None
    if verdict == "DEAD" and floor_met and not _seen(f"deadfloor:{program}:{hyp}", "mint"):
        mint("dead-floor", bot, MINT["dead-floor"], f"deadfloor:{program}:{hyp}", "floor-met honest DEAD",
             settler=tok)
        note = "minted dead-floor"
    if hyp and program:
        probes = _hunt_floor(program, hyp)[0]
        if verdict.endswith("CANDIDATE") or verdict == "LEAD":
            res = "lead" if probes >= 1 else "unfired"   # "proven" comes only from an oracle PASS
        elif verdict == "DEAD":
            res = "dead" if floor_met else "unfired"
        elif verdict in ("UNFIRED", "NEEDS"):
            res = "unfired"
        else:
            res = None
        if res:
            resolve(program, hyp, res, settler=tok)
        if (verdict.endswith("CANDIDATE") and probes >= 1) or floor_met:
            refund_bond(program, hyp, settler=tok)
        else:
            forfeit_bond(program, hyp, settler=tok)
    return note


def _ship(row):
    """Lineage only. A typed draft row with status READY mints NOTHING (the READY mint is ready_hook's)."""
    program, path = row.get("program"), str(row.get("path") or "")
    m = re.search(r"reports/(?:drafts|submitted)/[^/]+/([^/]+)", path)
    slug = m.group(1) if m else None
    rid = row.get("report_id") or (re.search(r"report(?: id)?\s*#?(\d{6,9})", str(row.get("notes") or ""), re.I) or [None, None])[1]
    if row.get("kind") == "submission" and rid:
        link_report(program, rid, slug=slug)
    elif row.get("kind") == "draft" and slug:
        _lin_append({"program": program, "slug": slug, "writer": bot_for(row.get("origin"), "lead")})
    return None


def _triage(program, report_id, state, tok):
    state = str(state or "").lower()
    lin = lineage(program, report_id=report_id)
    if len(lin) <= 1:
        return None   # no lineage: a report from before the economy, nothing to pay or charge
    ref = f"triage:{report_id}"
    if _seen(ref):
        return None
    if state in ("resolved", "triaged"):
        _split(MINT["accept"], lin, ref, "accept", tok)
        side = "resolved"
    elif state in PENALTY:
        writer = lin.get("writer") if lin.get("writer") in participants() else "lead"
        slash(writer, PENALTY[state], ref, f"triage {state}", settler=tok)
        side = "duplicate" if state == "duplicate" else "n-a"
    else:
        return None
    filing_market("resolve", program, str(report_id), settler=tok, outcome=side)
    return f"triage {report_id} {state}"


def settle_triage(out_dir=None):
    """Read an h1-feedback pull (the newest by default, always under FEEDBACK_OUT) and settle every
    lineage-linked report once. Called from sync.sh."""
    root = os.path.realpath(FEEDBACK_OUT)
    if not out_dir:
        days = sorted(d for d in os.listdir(FEEDBACK_OUT) if os.path.isdir(os.path.join(FEEDBACK_OUT, d))) \
            if os.path.isdir(FEEDBACK_OUT) else []
        if not days:
            return "no h1-feedback pull"
        out_dir = os.path.join(FEEDBACK_OUT, days[-1])
    if not os.path.realpath(out_dir).startswith(root + os.sep):
        return f"refused: {out_dir} is not an h1-feedback pull under {FEEDBACK_OUT}"
    reps = []
    try:
        with open(os.path.join(out_dir, "reports_list_raw.json")) as f:
            for r in json.load(f):
                a = r.get("attributes") or {}
                prog = (((r.get("relationships") or {}).get("program") or {}).get("data") or {}).get("attributes") or {}
                reps.append((prog.get("handle"), str(r.get("id")), a.get("state")))
    except (OSError, ValueError, AttributeError):
        try:
            with open(os.path.join(out_dir, "triager_analysis.json")) as f:
                reps = [(r.get("program"), str(r.get("id")), r.get("state")) for r in json.load(f)]
        except (OSError, ValueError):
            return f"no readable report list in {out_dir}"
    try:
        tok = _settler()
    except EconomyBroken as e:
        return f"settle_triage: economy disabled ({e})"
    done = [x for x in (on_event("triage", program=p, report_id=i, state=s, settler=tok) for p, i, s in reps
                        if p and i) if x and not x.startswith("economy:")]
    return f"settle_triage: {len(reps)} reports read, {len(done)} settled"


def ready_hook(program, slug):
    """Called ONLY by scripts/reports.sh ready, after the liveness, QAQC and staging gates passed. Re-checks the
    draft on disk (report.md present, no HELD-REASON.md) and mints the READY split once."""
    d = os.path.join(WS, "reports", "drafts", str(program), str(slug))
    if not re.fullmatch(r"[\w][\w.-]*", str(program or "")) or not re.fullmatch(r"[\w][\w.-]*", str(slug or "")):
        return "ready-hook: refused, bad program or slug"
    if not os.path.isfile(os.path.join(d, "report.md")):
        return f"ready-hook: refused, no draft {d}"
    if os.path.exists(os.path.join(d, "HELD-REASON.md")):
        return "ready-hook: refused, the draft is HELD"
    try:
        tok = _settler()
    except EconomyBroken as e:
        return f"ready-hook: economy disabled ({e})"
    return f"ready-hook: {on_event('ready', program=program, slug=slug, settler=tok)}"


# ---------------------------------------------------------------- reporting

def status_text():
    ok, n, why = verify_chain()
    if not ok:
        return (f"ECONOMY  chain BROKEN ({n} rows: {why})\n"
                "         the economy is DISABLED: every read refuses until a human repairs the ledger "
                "(python3 scripts/gnoc_economy.py audit)")
    ensure()
    try:
        sweep_expired()
    except EconomyBusy as e:
        _log(f"status sweep skipped: {e}")
    R = rows()
    minted, burnt = supply(R)
    bal = balances(R)
    lines = [f"ECONOMY  chain OK ({len(R)} rows, HMAC-signed)",
             f"supply   minted {minted}  burnt {burnt}  circulating {minted - burnt}  escrow {bal.get(ESCROW, 0)}",
             "wealth   bot             RC      brier   state"]
    for p in sorted(participants(R), key=lambda x: -bal.get(x, 0)):
        b = brier(p, R)
        lines.append(f"         {p:<14} {bal.get(p, 0):>7}  {'-' if b is None else b:>6}   "
                     f"{'broke' if p != TREASURY and bal.get(p, 0) < BROKE else ''}")
    openm = [(ref, market(ref, R)) for ref in sorted({r['ref'] for r in R if r['ref'].startswith('mkt:')})]
    openm = [(ref, m) for ref, m in openm if not m["closed"]]
    lines.append(f"markets  {len(openm)} open")
    for ref, m in openm[-15:]:
        _, prog, hyp = ref.split(":", 2)
        lines.append(f"         {ref}  long {m['long']}  short {m['short']}  budget {budget(prog, hyp)}")
    B = [b for b in bounties(R).values() if b["state"] in ("open", "claimed")]
    lines.append(f"bounties {len(B)} live")
    for b in B:
        lines.append(f"         {b['id']} {b.get('program')} crown={b.get('crown')} pays {b.get('amount')} "
                     f"{b['state']}{' by ' + b['claimant'] if b.get('claimant') else ''}")
    fil = [ref for ref in {r['ref'] for r in R if r['ref'].startswith('fil:')} if not _filing(ref, R)["closed"]]
    lines.append(f"filing   {len(fil)} open markets; dupe odds (all history) {dupe_odds()[0]}")
    w = routing_weights(R=R)
    on = os.environ.get("GNOC_ECONOMY_ROUTING") == "1"
    lines.append(f"routing  {'ON' if on else 'OFF (advisory)'}: " +
                 "  ".join(f"{k} {v:.2f}" for k, v in sorted(w.items(), key=lambda kv: -kv[1])[:6]))
    return "\n".join(lines)


def audit_text():
    ok, n, why = verify_chain()
    if not ok:
        return f"audit: chain BROKEN over {n} rows ({why}); no replay (a broken chain credits nothing)"
    R = rows()
    bal = balances(R)
    minted, burnt = supply(R)
    total = sum(v for k, v in bal.items())
    cons = total == minted - burnt
    return (f"audit: chain OK over {n} rows ({why}, HMAC + prev); replayed {len(bal)} wallets; "
            f"conservation {'OK' if cons else 'FAILED'} (wallets {total} vs minted-burnt {minted - burnt})")


def main(argv):
    cmd = argv[0] if argv else "status"
    a = argv[1:]
    if cmd == "status":
        print(status_text())
    elif cmd == "audit":
        out = audit_text()
        print(out)
        return 0 if "chain OK" in out and "conservation OK" in out else 1
    elif cmd == "migrate":
        out = migrate()
        print(out)
        return 0 if "REFUSED" not in out and "BROKEN" not in out else 1
    elif cmd == "ready-hook":
        if len(a) < 2:
            print("usage: gnoc_economy.py ready-hook <program> <slug>  (scripts/reports.sh ready only)")
            return 2
        print(ready_hook(a[0], a[1]))
    elif cmd == "bet":
        if len(a) < 4:
            print("usage: gnoc econ bet <program> <hyp_id> long|short <stake> [bot]")
            return 2
        print(bet(a[0], a[1], a[4] if len(a) > 4 else "lead", a[2], int(a[3])))
    elif cmd == "bounty":
        act = a[0] if a else "list"
        if act == "list":
            for b in bounty("list").values():
                print(f"{b['id']} {b.get('program')} {b.get('crown')} {b.get('amount')} {b['state']} {b.get('claimant') or ''}")
        elif act == "post" and len(a) >= 4:   # GreyNOC's command line: funded by the treasury through the settler
            print(bounty("post", program=a[1], crown=a[2], amount=int(a[3]), poster="greynoc", settler=_settler()))
        elif act == "claim" and len(a) >= 3:
            print(bounty("claim", id=a[1], bot=a[2]))
        else:
            print("usage: gnoc econ bounty list | post <program> <crown> <RC> | claim <id> <bot>  "
                  "(settle happens only on an oracle PASS proved by the claimer)")
            return 2
    elif cmd == "settle":
        print(settle_triage(a[0] if a else None))
    else:
        print("usage: gnoc_economy.py status|audit|migrate|bet|bounty|settle|ready-hook")
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (EconomyBroken, EconomyBusy) as e:
        print(f"economy: {e}")
        sys.exit(1)
