"""gnoc_ident.py - the research identities gnoc chat probes WITH (account A, account B ...), by name only.

File: targets/<program>/identities.json   (mode 0600, never read into a model; read_file / grep refuse it)
    {"A": {"headers": {"Cookie": "..."}, "note": "attacker, owns org X", "saved": "<iso>", "source": "raw path"},
     "B": {...}}
ACCOUNTS.md stays the human notes (how the account was made, where its password lives). This file holds only what
a request needs: the headers that make it that account.

The model names an identity ("A"); code puts the header values on the wire. Every value is registered with
gnoc_secrets as an EXTRA redaction, so a response that echoes a token comes back as [REDACTED:identity:A] - but
an outbound request carrying it is allowed (it is a research account, not the user's own credential).
"""
import json
import os
import re
from datetime import datetime, timezone

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NAME = re.compile(r"^[A-Za-z][\w-]{0,23}$")



def accounts_on_disk(program, root=None):
    """What targets/<program>/ACCOUNTS.md actually holds, as [(heading, [field lines])].

    The empty-identity message used to say "(ACCOUNTS.md has how)" and name nothing, so an agent with a
    fully provisioned account sitting on disk went on hunting unauth. Measured 2026-10-28 on program-72:
    ACCOUNTS.md carried account A with a username, an e-mail and a password, the identity store was empty,
    and the agent 403'd its way around an authenticated purchase endpoint instead.

    PASSWORDS ARE DELIBERATELY NOT RETURNED. The point is to tell the agent the account EXISTS and where to
    read it; it has read_file for the rest. A secret does not need to transit a tool result to be used.
    """
    root = root or os.environ.get("WS") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "targets", program, "ACCOUNTS.md")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    out, cur = [], None
    for ln in text.splitlines():
        t = ln.strip()
        if t.startswith("## "):
            cur = (t[3:].strip(), [])
            out.append(cur)
        elif cur is not None and t.startswith("-"):
            key = t.lstrip("- ").split(":", 1)[0].strip().lower()
            if key in ("username", "user", "email", "e-mail", "login", "account", "handle", "phone",
                       "tag", "name"):
                cur[1].append(t.lstrip("- ").strip()[:90])
    rows = [(h, f) for h, f in out if f]
    if rows:
        return rows
    # SECOND FORMAT: a markdown TABLE. 1vault's file is "| tag | team | host | email | role |" with no
    # "## " field lists at all, so a headings-only parser reported ZERO accounts for a programme that has
    # three. The hint has to work on the files we actually keep, not on one house style.
    hdr, cols = None, []
    for ln in text.splitlines():
        t = ln.strip()
        if not t.startswith("|"):
            hdr = None
            continue
        cells = [c.strip() for c in t.strip("|").split("|")]
        if hdr is None:
            low = [c.lower() for c in cells]
            if any(k in low for k in ("tag", "account", "user", "username", "email", "e-mail", "name")):
                hdr, cols = cells, low
            continue
        if all(set(c) <= set("-: ") for c in cells):      # the |---|---| separator
            continue
        keep = [f"{cols[i]}: {c}" for i, c in enumerate(cells)
                if i < len(cols) and c and cols[i] in ("tag", "account", "user", "username", "email",
                                                       "e-mail", "host", "team", "role", "name")]
        if keep:
            rows.append((keep[0].split(": ", 1)[-1][:60], keep[1:5] or keep))
    return rows

def path(program):
    return os.path.join(WS, "targets", program, "identities.json")


def load(program):
    if not program:
        return {}
    try:
        with open(path(program)) as f:
            d = json.load(f)
    except (OSError, ValueError):
        return {}
    d = {k: v for k, v in d.items() if isinstance(v, dict) and isinstance(v.get("headers"), dict)}
    _register(d)
    return d


def _register(d):
    try:
        import gnoc_secrets
    except ImportError:
        return
    for name, row in d.items():
        for h, v in row["headers"].items():
            # every piece on its own: a response that echoes ONE cookie (Set-Cookie: sessionid=...) or just the
            # token of "Bearer <token>" was never redacted while only the whole header string was known (QAQC r2)
            for piece in gnoc_secrets._value_pieces(str(v), "COOKIE" if h.lower() == "cookie" else h) or [v]:
                gnoc_secrets.register_extra(f"identity:{name}:{h}", piece)
            for k, tok in (row.get("tokens") or {}).items() if isinstance(row.get("tokens"), dict) else ():
                gnoc_secrets.register_extra(f"identity:{name}:{k}", tok)


def register_all():
    """Register every saved identity of every program for redaction, at import: values used to be registered only
    after load() ran in this process, so a raw capture read before that went out unredacted (QAQC r2)."""
    import glob
    for p in glob.glob(os.path.join(WS, "targets", "*", "identities.json")):
        try:
            with open(p) as f:
                d = json.load(f)
            if isinstance(d, dict):
                _register({k: v for k, v in d.items() if isinstance(v, dict) and isinstance(v.get("headers"), dict)})
        except (OSError, ValueError):
            continue


def _write(program, d):
    p = path(program)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(d, f, indent=1)
    os.replace(tmp, p)
    os.chmod(p, 0o600)



# A SESSION IS NOT ANY COOKIE. Measured 2026-10-28 on a live /hunt: the agent "logged in", saved identity
# A as Cookie=X-AB=428b79d9... - an A/B TESTING cookie from an anonymous page load - and then sent it
# everywhere. 20 of 20 authenticated requests returned 403 while anonymous requests to the same estate
# returned 200. It read its own broken session as "this endpoint is protected", which is the inverse of
# T-36 ("a 200 is not evidence of authentication") and poisons every verdict downstream. Believing you are
# authenticated when you are not is worse than knowing you are anonymous.
_SESSION_HINTS = ("session", "sess", "sid", "auth", "token", "jwt", "login", "logged", "access",
                  "refresh", "identity", "account", "member", "user_", "_user", "remember", "passport",
                  "phpsessid", "jsessionid", "connect.", "aspnet", "laravel", "csrf")
_TRACKING = ("x-ab", "_ga", "_gid", "_gat", "_fbp", "_fbc", "ajs_", "mp_", "amplitude", "optimizely",
             "hjsession", "_hj", "intercom", "datadome", "cf_bm", "__cf", "incap_", "visid", "utm",
             "consent", "cookieconsent", "locale", "lang", "currency", "timezone", "device", "tz")


def _cookie_names(headers):
    out = []
    for k, v in (headers or {}).items():
        if str(k).lower() != "cookie":
            continue
        for part in str(v).split(";"):
            n = part.split("=", 1)[0].strip().lower()
            if n:
                out.append(n)
    return out


def session_shape(headers):
    """(ok, why): do these headers plausibly carry a LOGGED-IN session?

    Conservative on purpose - it refuses only when there is nothing session-like at all and everything
    present is a known tracker. A bearer token or any session-ish cookie name passes.
    """
    hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    if hdrs.get("authorization") or hdrs.get("x-auth-token") or hdrs.get("x-session-token"):
        return True, ""
    names = _cookie_names(headers)
    if not names:
        return False, ("no Cookie and no Authorization header: these headers carry no session at all")
    hits = [n for n in names if any(h in n for h in _SESSION_HINTS)]
    if hits:
        return True, ""
    trackers = [n for n in names if any(t in n for t in _TRACKING)]
    if trackers and len(trackers) == len(names):
        # ONLY this case is a hard refusal. Every cookie is a KNOWN tracker, so there is nothing here that
        # could be a session under an unusual name - which is the real failure we measured (X-AB, _ga).
        return False, (f"every cookie here is a tracker ({', '.join(sorted(set(names))[:5])}) and none looks "
                       "like a session")
    # An unrecognised name is NOT proof of a bad jar: session cookies are named anything. The existing
    # weak-jar WARNING ("only preference cookies ... verify step is still owed") owns this case, and
    # hard-refusing it here would block a real session whose cookie happens to be called `x7`.
    return True, ""


def save(program, name, headers, note="", source=""):
    if not program:
        return "no program set"
    if not NAME.match(name or ""):
        return "identity name must be a short word like A, B, admin-A"
    headers = {str(k): str(v) for k, v in (headers or {}).items() if str(v).strip()}
    if not headers:
        return "no header values to save"
    ok_sess, why_sess = session_shape(headers)
    if not ok_sess:
        return ("refused: that is not a session. " + why_sess + ".\n"
                "  An anonymous page load sets tracking cookies; saving them as an identity makes every "
                "later request LOOK authenticated while being anonymous, so a 401/403 reads as 'this "
                "endpoint is protected' when it actually means 'I never logged in'.\n"
                "  Log in for real with http_request (POST the credentials from "
                "targets/<program>/ACCOUNTS.md), check the response is a 2xx that sets a session cookie or "
                "returns a token, then identities action=save from_raw=<THAT capture>.")
    if any("[REDACTED" in v for v in headers.values()):
        return ("refused: those values are redaction placeholders, not the token. Save it with from_raw=<the raw "
                "capture of the login response> so code reads the real value")
    d = load(program)
    # AN IDENTITY BELONGS TO THE SITE THAT MINTED IT. Without the origin recorded, a session minted on
    # app.example.com was replayed against app.example.com - a different brand on a different TLD - which can only
    # 403, and which quietly ships one site's session cookies to another. Derived from the capture path we
    # were given, so nothing extra has to be passed in.
    origin = ""
    m = re.search(r"https?://([^/\s\"']+)", str(source or ""))
    if m:
        origin = m.group(1).lower()
    d[name] = {"headers": headers, "note": (note or "")[:200], "origin": origin,
               "saved": datetime.now(timezone.utc).isoformat(timespec="seconds"), "source": source}
    _write(program, d)
    _register({name: d[name]})
    return f"identity {name} saved for {program}: headers {', '.join(sorted(headers))}"


def from_raw(raw_path, token_field=None):
    """Headers that make a request 'this session', read from a saved login exchange: its Set-Cookie cookies, and
    (token_field) a bearer token from the JSON body, e.g. token_field='access_token' or 'data.token'."""
    with open(raw_path) as f:
        try:
            d = json.load(f)
        except ValueError:
            d = None
    if not isinstance(d, dict) or not isinstance(d.get("response"), dict):
        # a bare JSONDecodeError here made the model retry the same call 4x on ACCOUNTS.md (session 2026-10-22)
        raise ValueError(f"{os.path.basename(raw_path)} is not a raw capture (the JSON http_request saves under "
                         "raw/, with a 'response' object). Log in with http_request first and pass that raw= path, "
                         "or pass headers={...} directly. ACCOUNTS.md and other notes cannot be parsed for a session.")
    resp = d.get("response") or {}
    hdrs = resp.get("headers") or {}
    out = {}
    cookies = []
    items = hdrs.items() if isinstance(hdrs, dict) else hdrs
    for k, v in items:
        if str(k).lower() == "set-cookie":
            for one in (v if isinstance(v, list) else re.split(r",(?=\s*[\w.-]+=)", str(v))):
                pair = one.split(";", 1)[0].strip()
                if "=" in pair:
                    cookies.append(pair)
    if cookies:
        out["Cookie"] = "; ".join(cookies)
    if token_field:
        try:
            cur = json.loads(resp.get("body") or "{}")
            for part in token_field.split("."):
                cur = cur[int(part)] if isinstance(cur, list) else cur[part]
            if isinstance(cur, str) and cur:
                out["Authorization"] = f"Bearer {cur}"
        except (ValueError, KeyError, IndexError, TypeError):
            pass
    return out


def remove(program, name):
    d = load(program)
    if name not in d:
        return f"no identity {name}"
    del d[name]
    _write(program, d)
    return f"identity {name} removed"


_PW_LINE = re.compile(r"(?i)^(?:\**[\w-]+\**\s+){0,2}\**pass(word|wd|phrase)?\**\s*[:=]\s*(\S.*)$")
_PW_ELSEWHERE = re.compile(r"(?i)(\.config/gnoc|\.env\b|secrets?\b|not stored|NOT stored|scratchpad|vault|"
                           r"elsewhere|lost|unsaved|redacted|\*{3,}|<[^>]+>)")


def accounts_hold_passwords(program, root=None):
    """F6 2026-11-09: True only when targets/<program>/ACCOUNTS.md itself carries a password VALUE (a
    'password: x' field or table cell), not a pointer to where one lives. listing() told the lead "ACCOUNTS.md holds
    the passwords, read_file it" for program-28, whose file says they live in ~/.config/gnoc/*.env. The value
    is never returned; only whether it is there."""
    root = root or os.environ.get("WS") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        with open(os.path.join(root, "targets", program, "ACCOUNTS.md"), encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return False
    col = None
    for ln in lines:
        t = ln.strip()
        if t.startswith("|"):   # a markdown table: a non-empty cell under a password column
            cells = [c.strip() for c in t.strip("|").split("|")]
            low = [c.lower() for c in cells]
            if col is None:
                col = next((i for i, c in enumerate(low) if re.fullmatch(r"\**pass(word|wd)?\**", c)), -1)
                continue
            if col >= 0 and col < len(cells) and cells[col] and not set(cells[col]) <= set("-: ") \
                    and not _PW_ELSEWHERE.search(cells[col]):
                return True
            continue
        col = None
        m = _PW_LINE.search(t.lstrip("-* "))
        if m and m.group(2).strip() and not _PW_ELSEWHERE.search(m.group(2)):
            return True
    return False


def login_script(program, root=None):
    """targets/<program>/LOGIN.py when it exists (F7), else ""."""
    root = root or WS
    p = os.path.join(root, "targets", str(program or ""), "LOGIN.py")
    return p if program and os.path.isfile(p) else ""


def session_path_hint(program, root=None):
    """F6: the sanctioned way to get a session for `program` WITHOUT the model seeing a secret, one line."""
    if login_script(program, root):
        return (f"get a session without seeing the secret: identities action=login name=<X> (runs "
                f"targets/{program}/LOGIN.py in code).")
    if accounts_hold_passwords(program, root):
        return (f"log in with http_request posting the form values from targets/{program}/ACCOUNTS.md, then "
                "identities action=save name=<X> from_raw=<that capture>.")
    return (f"no LOGIN.py for {program} and ACCOUNTS.md holds no password: add targets/{program}/LOGIN.py "
            "(identities action=login) or provision an account.")


def listing(program):
    d = load(program)
    if not d:
        _acc = accounts_on_disk(program)
        _hint = ""
        if _acc:
            if login_script(program):
                how = ("log in with identities action=login name=<X> (targets/" + program + "/LOGIN.py reads the "
                       "credentials in code; you never see them)")
            elif accounts_hold_passwords(program):
                how = ("read targets/" + program + "/ACCOUNTS.md (read_file) for the passwords and log in with "
                       "http_request, then identities action=save name=A from_raw=<that login capture>")
            else:
                how = ("its passwords are NOT in ACCOUNTS.md (it points elsewhere), so do not read_file a credential "
                       "store; " + session_path_hint(program))
            _hint = ("\n  ACCOUNTS.md ALREADY HOLDS " + str(len(_acc)) + " provisioned account(s) for this "
                     "programme - " + how + ". Do NOT provision another one:\n"
                     + "\n".join("    " + h + "  ->  " + "; ".join(f) for h, f in _acc[:4]))
        return (f"no identities saved for {program}.{_hint} MAKE them: provision action=pair signup_url=<signup page> (or action=register tag=A); or log in as an account you own (ACCOUNTS.md has how), then "
                "identities action=save name=A from_raw=<login raw capture>")
    now = datetime.now(timezone.utc)
    rows = []
    for name, r in sorted(d.items()):
        try:
            age = (now - datetime.fromisoformat(r.get("saved"))).total_seconds() / 3600
            age_s = f"{age:.0f}h old"
        except (TypeError, ValueError):
            age_s = "age ?"
        rows.append(f"{name}: headers {', '.join(sorted(r['headers']))}  ({age_s}){'  - ' + r['note'] if r.get('note') else ''}")
    return "\n".join(rows) + "\n(values never shown; name them in identities / as_identity and code sends them)"


def headers_for(program, names):
    """{name: headers} for the names given (a name that does not exist is reported, not skipped silently)."""
    d = load(program)
    missing = [n for n in names if n not in d]
    if missing:
        raise KeyError(f"no saved identity {', '.join(missing)} for {program} (identities action=list); send the "
                       "request WITHOUT as_identity or identities (unauth) now, or provision one first")   # D71
    return {n: dict(d[n]["headers"]) for n in names}


LOGIN_TIMEOUT = 60
_LOGIN_URL = re.compile(r"""(?m)^\s*LOGIN_URL\s*=\s*["'](https?://[^"'\s]+)["']""")


def _in_scope(url, program, root):
    try:
        import sys as _sys
        here = os.path.dirname(os.path.abspath(__file__))
        if here not in _sys.path:
            _sys.path.insert(0, here)
        from bbtools import lib_scope
        ok, _ = lib_scope.program_allows(url, program, root)
        return bool(ok)
    except Exception:  # noqa: BLE001 - no scope check available = not in scope
        return False


def login(program, name, root=None, timeout=None, scope_check=None):
    """F7 2026-11-09: log identity `name` in by running targets/<program>/LOGIN.py IN CODE and save the session.

    The script reads its own credentials (an env file under ~/.config/gnoc/ named inside it), takes --name, and
    prints ONLY {"headers": {...}, "source": "<login url>", "note": "..."} (or {"error": "..."}) on stdout. It must
    declare LOGIN_URL = "https://..." so the host is scope-gated BEFORE it runs. Returns only save()'s line or a
    short refusal: never a header value, never the script's stderr (a traceback could carry a credential)."""
    import subprocess
    import sys as _sys
    root = root or WS
    scope_check = scope_check or _in_scope
    if not program:
        return "no program set"
    if not NAME.match(str(name or "")):
        return "identity name must be a short word like A, B, D"
    script = login_script(program, root)
    if not script:
        return (f"refused: no targets/{program}/LOGIN.py. Add one (reads its own creds, prints the session JSON), "
                "or log in with http_request and identities action=save from_raw=<capture>.")
    try:
        with open(script, encoding="utf-8", errors="replace") as fh:
            m = _LOGIN_URL.search(fh.read())
    except OSError as e:
        return f"refused: LOGIN.py unreadable ({type(e).__name__})"
    if not m:
        return 'refused: LOGIN.py declares no LOGIN_URL = "https://..." line, so its host cannot be scope-gated.'
    login_url = m.group(1)
    if not scope_check(login_url, program, root):
        return f"refused: LOGIN.py's LOGIN_URL host is not in targets/{program}/SCOPE.txt; not run."
    try:
        p = subprocess.run([_sys.executable, script, "--name", str(name)], cwd=os.path.dirname(script),
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                           timeout=float(timeout or LOGIN_TIMEOUT), env=dict(os.environ, HUNT_TARGET=program))
    except subprocess.TimeoutExpired:
        return f"login {name} failed: LOGIN.py ran past {int(timeout or LOGIN_TIMEOUT)}s and was killed"
    except OSError as e:
        return f"login {name} failed: LOGIN.py could not start ({type(e).__name__})"
    res = None
    for ln in reversed((p.stdout or "").strip().splitlines()):
        ln = ln.strip()
        if ln.startswith("{"):
            try:
                res = json.loads(ln)
                break
            except ValueError:
                continue
    if not isinstance(res, dict):
        last = (p.stderr or "").strip().splitlines()[-1:] or [""]
        kind = re.match(r"^([A-Za-z_][\w.]*(Error|Exception|Interrupt))\b", last[0])
        return (f"login {name} failed: LOGIN.py exit {p.returncode}, no session JSON on stdout"
                + (f" ({kind.group(1)})" if kind else "") + ".")
    if res.get("error"):
        return f"login {name} failed: {str(res['error'])[:160]}"
    headers = res.get("headers")
    if not isinstance(headers, dict) or not headers:
        return f"login {name} failed: LOGIN.py printed no headers"
    source = str(res.get("source") or login_url)
    if not scope_check(source, program, root):
        return f"refused: LOGIN.py reported a source host outside targets/{program}/SCOPE.txt; not saved."
    note = str(res.get("note") or f"logged in by targets/{program}/LOGIN.py")
    return save(program, name, headers, note=note, source=source)


register_all()
