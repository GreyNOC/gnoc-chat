"""gnoc_goal.py - the standing goal: one objective the agent keeps working toward, turn after turn, across
restarts, until it is reached or the user clears it.

A goal is not a to-do. It carries:
    text         what the user asked for, verbatim ("achieve zero click ato on gatewayco")
    crown        the capability it reduces to (ato, rce, cross-tenant, money ...), parsed from the text
    constraints  the acceptance criteria parsed from the text (zero-click, unauth, production ...). These GATE
                 the goal: a one-click ATO does not close a zero-click goal, it is recorded as partial progress
    milestones   the capabilities that must be held on the way, seeded from the attack tree when the goal names a
                 crown, each open / done with the receipt that closed it
    acceptance   the DEFINITION OF DONE for any task, hunt or not: the criteria that must be met for the goal to
                 close ("all tests pass", "no public API change", "the doc is updated"), each open / met with the
                 receipt that proves it. This is the general-task generalisation of `constraints` (which are parsed
                 from hunt vocabulary only): `done()` refuses while any criterion is open, so a long task closes on
                 its own stated criteria, not on the model saying so. Every parsed constraint also seeds an
                 acceptance criterion, so a zero-click goal cannot close on a one-click receipt just because the
                 model never mentioned the constraint again.
    log          dated progress notes, each ideally pointing at an artifact on disk
    status       active | paused | achieved. A paused goal keeps its progress but stops steering every turn;
                 `resume()` puts it back. `done()` still refuses while any definition-of-done item is open.

It is injected into the system prompt every turn, so the model cannot drift off it, and into the hunt directive,
so the phase director aims at it. `done()` refuses while a constraint is unmet or a milestone is open: the goal
closes on evidence, not on the model saying so.
"""
import hashlib
import json
import os
import re
import threading
from datetime import datetime, timezone

# shared helpers (consolidated from the per-module copies)
from gnoc_core.util import _now_iso as _now

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# The hunt workspace's standing goal. orch-bot, the company manager and every hunt lane read THIS file, so it
# stays the default. Any OTHER repo the chat opens gets its own goal file (scope_to below), so a goal set while
# coding in one project never shows up in a chat opened in another - the way Claude Code keeps state per project.
_GLOBAL_GOAL = os.path.join(WS, ".claude/state/orch/agent/goal.json")
PATH = _GLOBAL_GOAL  # the ACTIVE goal file; scope_to() repoints it when the chat's working repo is not WS
RECEIPT_BASE = WS  # relative receipts resolve here; scope_to() repoints it to the repo for a non-WS repo


def path_for(repo):
    """The goal file for working repo `repo`. WS (or no repo) -> the single global hunt goal; any other repo
    -> its own file under the managed state dir, keyed by the repo's real path so two repos never collide and
    nothing is written into the user's own tree."""
    if not repo or os.path.realpath(repo) == os.path.realpath(WS):
        return _GLOBAL_GOAL
    h = hashlib.sha1(os.path.realpath(repo).encode()).hexdigest()[:16]
    return os.path.join(WS, ".claude/state/orch/agent/goals", h + ".json")


def scope_to(repo):
    """Point goal storage at `repo`'s own file (WS -> the global goal). The chat calls this whenever its
    working repo changes (launch, change_dir, repo switch) so the goal is per-project, not one global goal
    leaking across every repo. Returns the active path."""
    global PATH, RECEIPT_BASE
    PATH = path_for(repo)
    RECEIPT_BASE = os.path.realpath(repo) if repo and os.path.isdir(repo) else WS
    return PATH

# a constraint is an acceptance criterion: the goal is not met until the captured receipt satisfies it
CONSTRAINTS = {
    # "0 click" / "0-click" too: GreyNOC's "hunt meta until we achieve an RCE or 0 click ato" lost the constraint
    "zero-click": (re.compile(r"\b(zero[- ]?click|0[- ]?click|no[- ]?(user[- ])?interaction|without (any )?(user|victim) "
                              r"(action|click|interaction)|ui:?n)\b", re.I),
                   "the chain must need NO victim action: no click, no visit, no paste. One click makes it partial "
                   "progress, not the goal (CVSS UI:N)."),
    "unauth": (re.compile(r"\b(unauth\w*|zero[- ]credential|without (an? )?(account|login|session|credential)|pr:?n)\b", re.I),
               "the chain must start from an anonymous attacker, holding no account on the target (CVSS PR:N)."),
    "pre-auth": (re.compile(r"\bpre[- ]?auth\b", re.I),
                 "the chain must fire before authentication completes."),
    "one-shot": (re.compile(r"\b(one[- ]shot|single (request|packet)|no (race|burst))\b", re.I),
                 "a single request must do it, with no race or repetition."),
    "production": (re.compile(r"\b(prod(uction)?|live)\b", re.I),
                   "the receipt must be captured on a production host, not staging / UAT / sandbox."),
    "cross-tenant": (re.compile(r"\bcross[- ]tenant\b", re.I),
                     "the crossing must be between two tenants, not two users of one tenant."),
}
CROWNS = ("rce", "ato", "cross-tenant", "money", "mass-pii", "admin", "auth-bypass", "cross-user-write",
          "cross-user-read", "secret")
# One-line versions for acceptance criteria: the long description belongs in the prompt block, not in a
# checkbox the model has to parse every turn.
CONSTRAINT_SHORT = {
    "zero-click": "no victim action (no click, visit or paste)",
    "unauth": "anonymous attacker, no account",
    "pre-auth": "fires before authentication completes",
    "one-shot": "one request, no race or repetition",
    "production": "captured on a production host",
    "cross-tenant": "crosses two tenants, not two users of one tenant",
}
GOAL_STATES = ("active", "paused", "achieved")


def constraint_criterion(name):
    """The acceptance criterion a parsed constraint seeds; stable so resume/done can match it."""
    return f"constraint {name}: {CONSTRAINT_SHORT[name]}"
_CROWN_WORDS = {
    # F1 2026-11-09: "one-click victim token theft or victim bank-credential exfil" parsed as crown=secret and
    # seeded the SSRF trio. Stealing a VICTIM's token / session / credential is ATO vocabulary, not a leaked key.
    "ato": (r"\bato\b|account takeover|take over (an?|the) account|session (theft|hijack\w*|fixation)"
            r"|(token|session|cookie)[- ](theft|steal\w*|hijack\w*|exfil\w*)"
            r"|(steal|hijack)\w* (the |a )?(victim'?s? )?(token|session|cookie|credential)"
            r"|victim'?s? ([\w-]+ ){0,2}(token|session|cookie)s?\b"),
    "rce": r"\brce\b|remote code|command execution|code execution|shell on",
    "cross-tenant": r"cross[- ]tenant|another (tenant|org|workspace)|tenant isolation",
    "money": r"\bmoney\b|payment|payout|refund|balance|double[- ]spend|free (order|purchase)",
    "mass-pii": r"mass[- ]?pii|bulk (pii|data)|every user'?s|all users'? data",
    "admin": r"\badmin\b|privilege escalation|privesc|staff (panel|console)",
    "auth-bypass": r"auth\w* bypass|bypass (the )?(login|auth\w*)",
    "cross-user-write": r"write (to )?another user|modify another user|idor write",
    "cross-user-read": (r"read another user|another user'?s data|idor read"
                        r"|victim'?s? ([\w-]+ ){0,2}(data|pii|[\w-]*credentials?) ?(exfil\w*|theft|read|leak\w*)"),
    # "secret" is a LEAKED key / config / env value, never a victim's credential (that is ato / cross-user-read)
    "secret": (r"\bsecret\b|(leaked|exposed|hard-?coded|embedded|static) ([\w-]+ )?(credential|key|token)s?"
               r"|credential (leak|exposure)|api[- ]?key|token leak|\.env\b|env (file|var)"),
}




MILESTONE_STATES = ("open", "done")
ACCEPTANCE_STATES = ("open", "met")


def _clean(d):
    """The goal as the code below expects it. block() runs inside every system prompt, so a hand-edited or
    half-written file (a milestone without a status, a string where a dict goes, an unknown constraint) used to
    raise on every turn. Malformed parts are dropped or defaulted, never trusted."""
    if not isinstance(d, dict) or not d:
        return {}
    if not isinstance(d.get("text"), str) or not d["text"].strip():
        return {}
    d["created"] = str(d.get("created") or "")
    # A hand-edited status nobody knows used to make the goal invisible to _owned() without saying why.
    d["status"] = d.get("status") if d.get("status") in GOAL_STATES else "active"
    d["constraints"] = [c for c in (d.get("constraints") or []) if c in CONSTRAINTS] \
        if isinstance(d.get("constraints"), list) else []
    ms = []
    for m in d.get("milestones") or [] if isinstance(d.get("milestones"), list) else []:
        if isinstance(m, str):
            m = {"text": m}
        if isinstance(m, dict) and isinstance(m.get("text"), str) and m["text"].strip():
            st = m.get("status") if m.get("status") in MILESTONE_STATES else "open"
            ms.append({**m, "status": st, "receipt": str(m.get("receipt") or "")})
    d["milestones"] = ms
    acc = []
    for a in (d.get("acceptance") or [] if isinstance(d.get("acceptance"), list) else []):
        if isinstance(a, str):
            a = {"text": a}
        if isinstance(a, dict) and isinstance(a.get("text"), str) and a["text"].strip():
            st = a.get("status") if a.get("status") in ACCEPTANCE_STATES else "open"
            acc.append({**a, "status": st, "receipt": str(a.get("receipt") or "")})
    d["acceptance"] = acc
    d["log"] = [n for n in (d.get("log") or []) if isinstance(n, dict) and isinstance(n.get("text"), str)] \
        if isinstance(d.get("log"), list) else []
    for n in d["log"]:
        n["ts"], n["artifact"] = str(n.get("ts") or ""), str(n.get("artifact") or "")
    return d


def load():
    try:
        with open(PATH) as f:
            d = json.load(f)
    except (OSError, ValueError):
        return {}
    return _clean(d)


def save(d):
    os.makedirs(os.path.dirname(PATH), exist_ok=True)
    tmp = f"{PATH}.{os.getpid()}.{threading.get_ident()}.tmp"   # a shared tmp name raced between two writers
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=1)
        os.replace(tmp, PATH)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def _saved(d, ok_msg):
    """save(d) and return ok_msg, or say plainly that it was NOT recorded (the caller is told, nothing raises)."""
    try:
        save(d)
    except OSError as e:
        return f"NOT recorded: the goal file could not be written ({type(e).__name__}: {e})"
    return ok_msg


def parse(text):
    """(crown, [constraint names]) from the goal's own words."""
    t = text or ""
    crown = next((c for c, rx in _CROWN_WORDS.items() if re.search(rx, t, re.I)), None)
    cons = [name for name, (rx, _) in CONSTRAINTS.items() if rx.search(t)]
    if crown == "cross-tenant" and "cross-tenant" in cons:
        cons.remove("cross-tenant")  # it is the crown here, not an extra criterion
    return crown, cons


def _mine(d, owner):
    """True when this goal belongs to `owner` (None = no conversation context). Status is not considered."""
    return bool(d) and (owner is None or d.get("sid") == owner)


def _owned(d, owner):
    """The goal steers a conversation only when THAT conversation set it (owner == its sid). A fresh chat
    (a new sid) never inherits the goal a previous chat left behind; `gnoc chat -c` resumes the same sid and
    keeps it. This is what makes /goal per-conversation instead of one globally-persistent objective
    (the user 2026-10-23: a new chat still showed the last chat's goal).

    owner=None means "no conversation context" (a non-chat caller, or a test): behave as before and show any
    active goal, so only the chat - which always passes its sid - gets the per-conversation gate."""
    if not d or d.get("status") != "active":
        return False
    if owner is None:
        return True
    return d.get("sid") == owner


def set_goal(text, program=None, milestones=None, owner=None, acceptance=None):
    text = " ".join((text or "").split())
    if len(text) < 6:
        return None, "give the goal in a sentence, e.g. /goal achieve zero click ato on gatewayco"
    if isinstance(acceptance, str):
        acceptance = [c.strip() for c in re.split(r"[;\n]", acceptance) if c.strip()]
    if isinstance(milestones, str):
        milestones = [m.strip() for m in re.split(r"[;\n]", milestones) if m.strip()]
    crown, cons = parse(text)
    # A CONSTRAINT MUST GATE SOMETHING. Before this, zero-click/unauth/production were displayed and then
    # ignored by done(): the goal closed on any existing receipt. Each parsed constraint now seeds an
    # acceptance criterion, so the model has to close it with evidence before the goal can be achieved.
    acc, seen = [], set()
    for a in list(acceptance or []) + [constraint_criterion(c) for c in cons]:
        t = " ".join(str(a).split())[:200]
        if not t or t.lower() in seen:
            continue
        seen.add(t.lower())
        acc.append({"text": t, "status": "open", "receipt": "",
                    "kind": "constraint" if t.startswith("constraint ") else "user"})
    ms, seen_ms = [], set()
    for m in milestones or []:
        t = " ".join(str(m).split())[:200]
        if t and t.lower() not in seen_ms:
            seen_ms.add(t.lower())
            ms.append({"text": t, "status": "open", "receipt": ""})
    d = {"text": text, "program": program, "crown": crown, "constraints": cons, "status": "active",
         "created": _now(), "sid": owner, "log": [], "milestones": ms, "acceptance": acc}
    try:
        save(d)
    except OSError as e:
        return None, f"the goal could not be saved ({type(e).__name__}: {e})"
    return d, None


def seed_milestones(d, leaves):
    """Fill an empty milestone list from the attack tree's leaves (the capabilities to prove)."""
    if d.get("milestones") or not leaves:
        return d
    d["milestones"] = [{"text": l if " " in l else f"hold {l}", "status": "open", "receipt": ""} for l in leaves[:8]]
    _saved(d, "")
    return d


def _foreign(d, owner):
    """The one-line refusal when `owner` tries to write onto a goal another conversation set, else "".

    There is ONE goal file per repo, and note/milestone/done/clear took no owner at all, so a second chat
    in the same repo could record notes onto, close, or drop the first chat's objective - and _owned() then
    hid that goal from its own banner, so nothing on screen said it had happened (measured 2026-11-03:
    note() and done() both acted on sidA's goal from sidB). owner=None still means "no conversation
    context" (a non-chat caller or a test) and is allowed, exactly as _owned() treats it."""
    if owner is None or not d or d.get("status") not in ("active", "paused"):
        return ""
    if d.get("sid") in (None, owner):      # sid None is a legacy goal nobody owns
        return ""
    return (f"refused: the {d['status']} goal was set by another conversation in this repo - {d['text'][:90]!r}. "
            "Work toward it, or clear it there; /goal clear --force drops it from here.")


def pause(owner=None):
    """Keep the goal and its progress, but stop it steering every turn until resume()."""
    d = load()
    if not d:
        return "no goal set"
    if d.get("status") == "paused":
        return "the goal is already paused (/goal resume to continue it)"
    if d.get("status") != "active":
        return f"the goal is {d.get('status')}, not active"
    foreign = _foreign(d, owner)
    if foreign:
        return foreign
    d["status"], d["paused"] = "paused", _now()
    return _saved(d, f"goal paused: {d['text'][:120]}  (progress is kept; /goal resume continues)")


def resume(owner=None):
    d = load()
    if not d:
        return "no goal set"
    if d.get("status") == "active":
        return "the goal is already active"
    if d.get("status") != "paused":
        return f"the goal is {d.get('status')}, not paused (/goal <new objective> sets a new one)"
    foreign = _foreign(d, owner)
    if foreign:
        return foreign
    d["status"], d["resumed"] = "active", _now()
    return _saved(d, f"goal resumed: {d['text'][:120]}")


def _active_or_paused(d):
    """Return the reason a mutation cannot touch this goal, else "". Paused progress is read-only."""
    if not d:
        return "no active goal"
    if d.get("status") == "paused":
        return "the goal is paused; /goal resume before recording progress or closing it"
    if d.get("status") != "active":
        return f"the goal is {d.get('status')}, not active"
    return ""


def _norm(s):
    return " ".join(str(s or "").split()).lower()


def _bare(s):
    """Normalize a milestone name across the verbs either side may use, and drop the '(unlocks ...)' tail."""
    return re.sub(r"^(hold|prove|get|reach|obtain)\s+", "", _norm(s)).split(" (unlocks")[0].strip()


def _match_items(items, text, bare=False):
    """(item, error). Exact first, then a SAFE short form. A strict prefix must never close a longer item:
    'hold ssrf' closed 'hold ssrf to internal admin' in the old substring match. Only an item that ENDS with
    the named text ('tests pass' -> 'all tests pass'), or a label followed by ':', or an exact bare form
    ('prove oauth-code' -> 'hold oauth-code') is accepted. More than one candidate is refused, not guessed."""
    want = _norm(text)
    exact = [x for x in items if _norm(x.get("text")) == want]
    if len(exact) == 1:
        return exact[0], ""
    if len(exact) > 1:
        return None, f"refused: {text!r} matches {len(exact)} identical items; remove the duplicate first"
    cand = []
    for x in items:
        other = _norm(x.get("text"))
        if (len(want.split()) >= 2 and other.endswith(" " + want)) or \
                (want and other.startswith(want + ":")):
            cand.append(x)
    if bare:
        b = _bare(text)
        for x in items:
            if b and _bare(x.get("text")) == b and x not in cand:
                cand.append(x)
    if len(cand) == 1:
        return cand[0], ""
    if len(cand) > 1:
        names = "; ".join(str(x.get("text"))[:80] for x in cand[:4])
        return None, f"refused: {text!r} is ambiguous - it matches {len(cand)} items ({names}). Name it exactly."
    return None, ""


def note(text, artifact="", owner=None):
    d = load()
    why = _active_or_paused(d)
    if why:
        return why
    foreign = _foreign(d, owner)
    if foreign:
        return foreign
    text = " ".join((text or "").split())[:400]
    if not text:
        return "refused: a progress note needs text (what changed, or what you learned)"
    artifact = (artifact or "").strip()
    if artifact and "://" not in artifact:   # a note may cite a URL; a path must actually exist
        missing = _receipt_missing(artifact)
        if missing:
            return "refused: " + missing + " (cite the artifact that exists, or omit artifact=)"
    d.setdefault("log", []).append({"ts": _now(), "text": text, "artifact": artifact})
    d["log"] = d["log"][-40:]
    return _saved(d, f"recorded against the goal ({len(d['log'])} notes)")


def milestone(text, status="done", receipt="", owner=None):
    d = load()
    why = _active_or_paused(d)
    if why:
        return why
    foreign = _foreign(d, owner)
    if foreign:
        return foreign
    text = " ".join((text or "").split())[:200]
    if not text:
        return "refused: name the milestone"
    # done() only counts "open" ones as open, so any other word ("skipped", "n/a") silently unblocked the goal
    if status not in MILESTONE_STATES:
        return f"refused: a milestone is {' or '.join(MILESTONE_STATES)}, not {status!r}"
    receipt = (receipt or "").strip()   # a blank receipt is no receipt
    # the receipt gate applies to a NEW milestone too, or the goal could be closed with invented done ones
    if status == "done" and not receipt:
        return "refused: closing a milestone needs a receipt (the artifact path or the captured bytes)"
    if status == "done":
        why = _receipt_missing(receipt)
        if why:
            return "refused: " + why + " (a milestone closes on a real artifact, not a path you typed)"
    m, err = _match_items(d.setdefault("milestones", []), text, bare=True)
    if err:
        return err
    if m is not None:
        m["status"], m["receipt"] = status, receipt
        if status == "done":
            m["closed"] = _now()
        return _saved(d, f"milestone {status}: {m['text']}")
    d["milestones"].append({"text": text, "status": status, "receipt": receipt})
    return _saved(d, f"milestone added ({status}): {text}")


def accept(text, status="met", receipt="", owner=None):
    """Add or resolve an ACCEPTANCE criterion - the general-task definition of done. Unlike a milestone (a
    capability to pass through, often hunt-seeded), an acceptance criterion is what makes THIS goal finished:
    "all tests pass", "no public API change", "the doc is updated". done() refuses while any is open, so a
    long task closes on its stated criteria, not on the model saying so. Marking one met needs a receipt that
    exists on disk (the test log, the diff, the page), the same gate a milestone passes. status=open just
    adds or re-opens a criterion and needs no receipt."""
    d = load()
    why = _active_or_paused(d)
    if why:
        return why
    foreign = _foreign(d, owner)
    if foreign:
        return foreign
    text = " ".join((text or "").split())[:200]
    if not text:
        return "refused: name the acceptance criterion"
    if _norm(text) in CONSTRAINTS:   # /goal accept zero-click is the seeded criterion's short name
        text = f"constraint {_norm(text)}"
    if status not in ACCEPTANCE_STATES:
        return f"refused: an acceptance criterion is {' or '.join(ACCEPTANCE_STATES)}, not {status!r}"
    receipt = (receipt or "").strip()   # a blank receipt is no receipt
    if status == "met" and not receipt:
        return "refused: marking a criterion met needs a receipt (the test log, diff or artifact that proves it)"
    if status == "met":
        why = _receipt_missing(receipt)
        if why:
            return "refused: " + why + " (a criterion is met by a real artifact, not a path you typed)"
    a, err = _match_items(d.setdefault("acceptance", []), text)
    if err:
        return err
    if a is not None:
        if status == "open" and a.get("status") == "open":
            # "accept status=open" on a criterion that is ALREADY open changes nothing. The lead sent it six
            # times, the last three with receipt='test/slug.test.js', read "criterion open" each time, and the
            # goal could never close: 430 s and a timeout (/goal drives 2026-11-21). A receipt names the proof,
            # so with one this call is what it was meant to be; without one it is told the call that closes it.
            if receipt:
                why = _receipt_missing(receipt)
                if why:
                    return "refused: " + why + " (a criterion is met by a real artifact, not a path you typed)"
                a["status"], a["receipt"], a["closed"] = "met", receipt, _now()
                return _saved(d, f"criterion met: {a['text']} (it was already open, and this call named its "
                                 f"receipt {receipt})")
            return (f"nothing changed: the criterion {a['text']!r} is already open. To mark it MET, name what "
                    f"proves it: goal(action='accept', text={a['text']!r}, status='met', receipt='<the test file, "
                    "log or diff that shows it>'). Then goal(action='done').")
        a["status"], a["receipt"] = status, receipt
        if status == "met":
            a["closed"] = _now()
        return _saved(d, f"criterion {status}: {a['text']}")
    d["acceptance"].append({"text": text, "status": status, "receipt": receipt})
    return _saved(d, f"criterion added ({status}): {text}")


def _receipt_missing(receipt):
    """The receipt must be something that EXISTS on disk: a path that does not resolve is a claim, not evidence.
    Caught 2026-10-28: done('/nope/x') closed the goal, so the gate only checked that the string was non-empty.
    Relative receipts resolve against the goal's repo (RECEIPT_BASE), which scope_to() keeps in step with PATH."""
    r = (receipt or "").strip()
    if not r:
        return "the receipt is empty"
    cand = r if os.path.isabs(r) else os.path.join(RECEIPT_BASE, r)
    if not os.path.exists(cand):
        return f"the receipt {r!r} does not exist on disk"
    return ""


def done(receipt="", force=False, owner=None):
    """Close the goal. Refused while a constraint has no acceptance evidence, or a milestone/criterion is open,
    unless forced."""
    d = load()
    if not d:
        return "no goal set"
    if d.get("status") == "paused":
        return "refused: the goal is paused; /goal resume before closing it (or /goal clear to drop it)"
    if d.get("status") != "active":
        return f"the goal is already {d.get('status')}"
    foreign = _foreign(d, owner)
    if foreign and not force:
        return foreign
    receipt = (receipt or "").strip()
    if not receipt and not force:
        return "refused: closing the goal needs the receipt (the draft dir, or the artifact holding the terminal)"
    if receipt and not force:
        why = _receipt_missing(receipt)
        if why:
            return ("refused: " + why + ". Point it at the draft dir or the raw file holding the terminal "
                    "(/goal done --force only if the goal turned out not to be needed).")
    open_ms = [m["text"] for m in d.get("milestones", []) if m["status"] == "open"]
    if open_ms and not force:
        return ("refused: " + str(len(open_ms)) + " milestone(s) still open (" + ", ".join(open_ms[:4])
                + "). Close them with their receipts, or /goal done --force if they turned out not to be needed.")
    open_acc = [a["text"] for a in d.get("acceptance", []) if a["status"] == "open"]
    if open_acc and not force:
        return ("refused: " + str(len(open_acc)) + " acceptance criterion/criteria still open ("
                + ", ".join(open_acc[:4]) + "). Meet each with its receipt via goal(action='accept', text=<the criterion>, "
                "status='met', receipt=<the file that proves it>), "
                "or /goal done --force if they turned out not to be needed.")
    # Legacy goals (written before set_goal seeded constraint criteria) must not bypass the constraints they
    # were created with. New goals always have these criteria, so this branch is a migration guard only.
    acc_text = " | ".join(_norm(a.get("text")) for a in d.get("acceptance", []))
    uncovered = [c for c in d.get("constraints", [])
                 if constraint_criterion(c).lower() not in acc_text
                 and f"constraint {c}".lower() not in acc_text]
    if uncovered and not force:
        return ("refused: constraint(s) " + ", ".join(uncovered) + " have no acceptance criterion. Add each "
                "with goal(action=accept, text='constraint <name>', status=open) and close it with a receipt, "
                "or /goal done --force if the constraint no longer applies.")
    d["status"], d["closed"], d["receipt"] = "achieved", _now(), receipt
    return _saved(d, f"goal ACHIEVED: {d['text']}  (receipt {receipt})")


def clear(owner=None, force=False):
    d = load()
    if not d:
        return "no goal set"
    foreign = _foreign(d, owner)
    if foreign and not force:
        return foreign
    return _saved({}, f"goal cleared: {d.get('text', '')[:120]}")


def block(program=None, cap=1900, owner=None):   # the preamble is ~450 chars; the rest is milestones + progress
    """The standing-goal block injected into the system prompt every turn (only for the conversation that owns
    the goal; a fresh chat is told it may set one)."""
    d = load()
    paused = bool(d and d.get("status") == "paused" and _mine(d, owner))
    achieved = bool(d and d.get("status") == "achieved" and _mine(d, owner))
    if not _owned(d, owner) and not paused:
        # No goal: say so, because an empty block left the agent with no idea it may set one itself.
        if achieved:
            return (f"NO STANDING GOAL is set (the last goal was ACHIEVED: {d.get('text', '')[:120]!r}). "
                    "When the user asks for something CONTINUOUS (\"keep doing X\", \"from now on\", \"until you "
                    "find Y\", \"work on X until it is done\") or tells you to set a goal, set it yourself in that "
                    "same turn with goal(action=set, text=<the objective in one sentence>) and start on it "
                    "immediately. A one-off question or a single task is not a goal.")
        return ("NO STANDING GOAL is set. When the user asks for something CONTINUOUS (\"keep doing X\", "
                "\"from now on\", \"until you find Y\", \"work on X until it is done\") or tells you to set "
                "a goal, set it yourself in that same turn with goal(action=set, text=<the objective in one "
                "sentence>) and start on it immediately. Do not wait for them to type /goal. A one-off question "
                "or a single task is not a goal.")
    if paused:
        out = [f"STANDING GOAL (PAUSED {str(d.get('paused') or d.get('created') or '')[:10]}"
               + (f", program {d['program']}" if d.get("program") else "") + f"): {d['text']}",
               "PAUSED: do not work toward it until the user resumes it (/goal resume). Answer their questions "
               "directly; a pause is not permission to replace or clear the objective."]
    else:
        out = [f"STANDING GOAL (set {d['created'][:10]}"
               + (f", program {d['program']}" if d.get("program") else "") + f"): {d['text']}",
               "Work toward this every turn. Answer their questions directly first: a question never starts work the user "
               "did not ask for. THEIR instruction this turn outranks this goal - if the user names another program "
               "or direction, do that, then set the goal to their words (action=set force=true) or clear it; "
               "your own preference is not their instruction. Never drift; never close it without the captured "
               "receipt. Before you stop - turn end, hunt pause, NEEDS - say where this goal stands and what "
               "the next milestone needs."]
    if d.get("crown"):
        out.append(f"Crown: {d['crown']}. Reaching anything weaker is partial progress, not the goal.")
    for c in d.get("constraints", []):
        out.append(f"CONSTRAINT {c}: {CONSTRAINTS[c][1]}")
    ms = d.get("milestones") or []
    if ms:
        out.append("Milestones: " + "; ".join(
            ("[x] " if m["status"] == "done" else "[ ] ") + m["text"] for m in ms[:10]))
    acc = d.get("acceptance") or []
    if acc:
        out.append("Definition of done (acceptance criteria): " + "; ".join(
            ("[x] " if a["status"] == "met" else "[ ] ") + a["text"] for a in acc[:10]))
    elif not ms and not d.get("constraints"):
        out.append("No definition of done yet: state the acceptance criteria that will make this goal DONE with "
                   "goal(action=accept, status=open, text=<criterion>) - the goal closes only when each is met "
                   "with a receipt, so you do not declare victory early on a long task.")
    log = d.get("log") or []
    if log:
        out.append("Progress so far:")
        out += [f"  {n['ts'][5:10]} {n['text']}" + (f"  ({n['artifact']})" if n.get("artifact") else "")
                for n in log[-6:]]
    else:
        out.append("No progress recorded yet: record each real step with the goal tool (action=note) so the next "
                   "turn does not repeat it.")
    if paused:
        out.append("Paused: progress is read-only; /goal resume puts the goal back in force.")
    else:
        out.append("Record progress with goal(action=note); close a milestone with goal(action=milestone, "
                   "receipt=...); meet an acceptance criterion with goal(action=accept, receipt=...); only call "
                   "goal(action=done) when the captured receipt satisfies the crown, every constraint AND every "
                   "acceptance criterion.")
    # Fit the cap by dropping the OLDEST progress lines, never by slicing the tail: the tail is the most
    # RECENT progress and the closing instruction, and a blind s[:cap] silently deleted the newest note
    # the moment the preamble grew (caught 2026-10-22). Older notes are the cheapest thing to lose.
    first_log = next((i for i, ln in enumerate(out) if ln.startswith("Progress so far")), None)
    while len("\n".join(out)) > cap and first_log is not None and len(out) > first_log + 2:
        del out[first_log + 1]          # the oldest shown note
        out[first_log] = "Progress so far (older steps cut):"
    # If the checklist itself is what is too long, shorten those lines rather than cut the closing rule.
    if len("\n".join(out)) > cap:
        out = [ln if len(ln) <= 320 else ln[:317].rstrip() + "..." for ln in out]
    s = "\n".join(out)
    if len(s) <= cap:
        return s
    # Last resort: keep the header and the rule, state that the middle was cut. Never return a block that
    # ends mid-sentence with the close gate missing.
    head, tail = out[:3], out[-1]
    room = max(200, cap - len("\n".join(head + [tail])) - 80)
    return "\n".join(head + ["[... goal details cut to fit the prompt cap; /goal shows the full state ...]"[:room]]
                     + [tail])[:cap]


def one_line(width=0, owner=None):
    """The goal in one line for the chat UI (banner, status line): "✓ 3/5 · text", "paused · text", or ""
    when there is no goal this conversation owns."""
    d = load()
    paused = bool(d and d.get("status") == "paused" and _mine(d, owner))
    if not _owned(d, owner) and not paused:
        return ""
    ms = d.get("milestones") or []
    acc = d.get("acceptance") or []
    total = len(ms) + len(acc)
    done = sum(1 for m in ms if m.get("status") == "done") + sum(1 for a in acc if a.get("status") == "met")
    parts = ["paused"] if paused else []
    if total:
        parts.append(f"✓ {done}/{total}" if done >= total else f"{done}/{total}")
    txt = " · ".join(parts + [" ".join(str(d.get("text") or "").split())])
    if width and len(txt) > width:
        txt = txt[:max(8, width - 1)].rstrip() + "…"
    return txt


def fingerprint(owner=None):
    """Cheap identity of the current goal, so the chat can notice it CHANGED without re-reading it. An
    achieved goal keeps a fingerprint too: otherwise announce_goal_change() reported a win as 'cleared'."""
    d = load()
    if not d:
        return ""
    ms = d.get("milestones") or []
    acc = d.get("acceptance") or []
    counts = (f"{sum(1 for m in ms if m.get('status') == 'done')}/{len(ms)}"
              f"|{sum(1 for a in acc if a.get('status') == 'met')}/{len(acc)}")
    if d.get("status") == "achieved" and _mine(d, owner):
        return f"{d.get('text')}|achieved|{d.get('closed')}|{counts}"
    if d.get("status") == "paused" and _mine(d, owner):
        return f"{d.get('text')}|paused|{d.get('paused')}|{counts}"
    if not _owned(d, owner):
        return ""
    return f"{d.get('text')}|{d.get('status')}|{counts}"


def status_text():
    d = load()
    if not d:
        return "no goal set  (/goal <what you want achieved>)"
    ms = d.get("milestones") or []
    done_n = sum(1 for m in ms if m["status"] == "done")
    out = [f"goal [{d.get('status')}]: {d['text']}"]
    if d.get("status") == "paused":
        out.append("  paused; /goal resume continues it, /goal clear drops it")
    if d.get("program"):
        out.append(f"  program: {d['program']}")
    if d.get("crown"):
        out.append(f"  crown: {d['crown']}")
    if d.get("constraints"):
        out.append(f"  constraints: {', '.join(d['constraints'])}  (each is an acceptance criterion)")
    if ms:
        out.append(f"  milestones: {done_n}/{len(ms)}")
        out += [("    [x] " if m["status"] == "done" else "    [ ] ") + m["text"]
                + (f"   {m['receipt']}" if m.get("receipt") else "") for m in ms[:12]]
    acc = d.get("acceptance") or []
    if acc:
        met_n = sum(1 for a in acc if a["status"] == "met")
        out.append(f"  acceptance: {met_n}/{len(acc)}")
        out += [("    [x] " if a["status"] == "met" else "    [ ] ") + a["text"]
                + (f"   {a['receipt']}" if a.get("receipt") else "") for a in acc[:12]]
    if d.get("status") == "active":
        nxt = next((m["text"] for m in ms if m["status"] == "open"), None) \
            or next((a["text"] for a in acc if a["status"] == "open"), None)
        if nxt:
            out.append(f"  next: {nxt}")
    log = d.get("log") or []
    if log:
        out.append(f"  progress ({len(log)} notes, newest last):")
        out += [f"    {n['ts'][:16]}  {n['text']}" + (f"   ({n['artifact']})" if n.get("artifact") else "")
                for n in log[-8:]]
    if d.get("status") == "achieved":
        out.append(f"  achieved {d.get('closed', '')[:16]}  receipt {d.get('receipt', '')}")
    return "\n".join(out)


USAGE = """  /goal <objective> [--no-start] [--force] [--accept "criterion; ..."] [--milestone "step"]
                           set a standing objective and work it UNTIL IT IS ACHIEVED (Ctrl-C holds it; NEEDS: waits
                           for your answer, then it resumes). A parsed constraint (zero-click, unauth,
                           production, one-shot, cross-tenant) also becomes an acceptance criterion, so the goal
                           cannot close while it is unproven. --no-start sets it without starting.
  /goal show|status        the goal, its milestones, its definition of done and its progress
  /goal note <progress> [--artifact PATH]        record a real step against the goal
  /goal milestone <text> [--receipt PATH] [--open]   close a milestone with evidence (or add/re-open one)
  /goal accept <criterion> [--receipt PATH] [--open] add, meet or re-open an acceptance criterion
  /goal pause|resume       keep the progress but stop/resume the goal steering every turn
  /goal done <receipt> [--force]   close it; refused while a milestone or criterion is open
  /goal clear [--force]    drop it (and its progress)
  /goal help               this list"""
