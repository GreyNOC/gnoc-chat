#!/usr/bin/env python3
"""
lib_provision.py - reusable account self-provisioning for bug-bounty hunts.

WHY: self-provisioning a 2nd/3rd account is a REFLEX (SPINE aggression ladder) and
the measured yield leak is that only ~42% of hunts ever provisioned a victim account
- because every target reinvented mail.tm + link-extraction in a throwaway
targets/*/*_provision.py. This centralizes the proven, target-agnostic pieces so the
only thing a hunt writes is the target-specific register/login call:

  - TempInbox            disposable mail.tm inbox (create/token/poll/extract)
  - firebase_emaillink   FULLY-generic Firebase EMAIL_LINK passwordless provision
                         (identitytoolkit) -> verified idToken, no human inbox
  - provision_pair       mint TWO accounts (the IDOR/BOLA default) + store them
  - save/load_account    targets/<handle>/accounts/<tag>.json (mint once, reuse)
  - links/codes/unwrap   email body extractors incl. the SendGrid click-wrap 302

CLI:
  lib_provision.py inbox                     mint a temp inbox, print addr + token
  lib_provision.py wait <token> [secs]       poll inbox, print links + codes as they land
  lib_provision.py firebase <api_key> <origin>   full EMAIL_LINK -> idToken JSON
  lib_provision.py register <signup_url> [--handle h --tag A --proxy p --scope f --head]
                                             point at a signup URL -> logged-in account + state.json
  lib_provision.py selfcheck                 verify extractor logic + mint one inbox

Import the building blocks; do not copy-paste mail.tm again:
  from bbtools.lib_provision import TempInbox, firebase_emaillink, provision_pair, save_account
"""
import base64, json, os, re, secrets, sys, tempfile, time
from pathlib import Path

try:
    from curl_cffi import requests            # real-JA3 client, matches the hunt egress
    _IMP = {"impersonate": "chrome124"}
except ImportError:                            # pragma: no cover
    import requests
    _IMP = {}

MAILTM = "https://api.mail.tm"
ROOT = Path(__file__).resolve().parents[2]     # scripts/bbtools/ -> workspace root


def _ensure_bbtools_path():
    # so `from bbtools.lib_browser import ...` resolves even when run as `python lib_provision.py`
    # (that puts scripts/bbtools/ on the path, not scripts/). Matches lib_browser's scope-gate trick.
    p = str(Path(__file__).resolve().parents[1])   # the scripts/ dir
    if p not in sys.path:
        sys.path.insert(0, p)


# Force JSON: mail.tm (API-Platform/Hydra) content-negotiates on Accept, and the
# chrome124 impersonate sends a browser `Accept: text/html` -> it would answer XML.
_JSON_HDR = {"Accept": "application/json"}


def _get(url, **kw):
    kw.setdefault("timeout", 20)
    kw["headers"] = {**_JSON_HDR, **kw.get("headers", {})}
    return requests.get(url, **{**_IMP, **kw})


def _post(url, **kw):
    kw.setdefault("timeout", 20)
    kw["headers"] = {**_JSON_HDR, **kw.get("headers", {})}
    return requests.post(url, **{**_IMP, **kw})


def _retry(fn, tries=3, backoff=1.5):
    """mail.tm free tier rate-limits and occasionally 502s; retry the mint calls."""
    last = None
    for i in range(tries):
        try:
            return fn()
        except Exception as e:
            last = e
            time.sleep(backoff * (i + 1))
    raise last


def _members(data):
    # mail.tm answers a bare array for Accept: application/json, Hydra otherwise
    return data if isinstance(data, list) else data.get("hydra:member", [])


class TempInbox:
    """Disposable mail.tm inbox. .addr/.token; .poll() yields each message once."""

    def __init__(self, addr=None, prefix="dav"):
        doms = _retry(lambda: _members(_get(MAILTM + "/domains").json()))
        dom = doms[0]["domain"]
        self.addr = addr or f"{prefix}{int(time.time())}{os.getpid() % 1000}@{dom}"
        self.password = "Prov!" + str(int(time.time()))
        _retry(lambda: _post(MAILTM + "/accounts",
                             json={"address": self.addr, "password": self.password}))
        self.token = _retry(lambda: _post(MAILTM + "/token",
                            json={"address": self.addr, "password": self.password}).json()["token"])
        self._seen = set()

    @property
    def auth(self):
        return {"Authorization": "Bearer " + self.token}

    def messages(self):
        return _members(_get(MAILTM + "/messages", headers=self.auth).json())

    def poll(self, timeout=150, interval=4):
        end = time.time() + timeout
        while time.time() < end:
            for m in self.messages():
                if m["id"] in self._seen:
                    continue
                self._seen.add(m["id"])
                yield _get(MAILTM + f"/messages/{m['id']}", headers=self.auth).json()
            time.sleep(interval)

    def wait_for(self, pred, timeout=150):
        for msg in self.poll(timeout=timeout):
            if pred(msg):
                return msg
        return None

    @classmethod
    def attach(cls, token):
        """Re-attach to an inbox from a stored token (no new mailbox created)."""
        ib = cls.__new__(cls)
        ib.token, ib.addr, ib.password, ib._seen = token, None, None, set()
        return ib


# ---- email body extractors (pure, testable offline) ----
_LINK_RE = re.compile(r'https?://[^\s"\'<>)]+')


def msg_body(msg):
    html = msg.get("html") or []
    # a provider can return a null HTML part - str-coerce and drop falsy so join never crashes
    joined = "\n".join(str(x) for x in html if x) if isinstance(html, list) else str(html)
    return (msg.get("text") or "") + "\n" + joined


def links(msg):
    return _LINK_RE.findall(msg_body(msg))


def codes(msg, n=6):
    return re.findall(r'(?<!\d)(\d{%d})(?!\d)' % n, msg_body(msg))


def unwrap(url):
    """Follow ONE click-tracking redirect (SendGrid /ls/click, Mailgun, etc.) to the
    real link. Verify links are often wrapped and the raw oobCode/token is only in the
    302 Location. Returns the Location if present, else the original url."""
    try:
        r = _get(url, allow_redirects=False)
        return r.headers.get("location") or r.headers.get("Location") or url
    except Exception:
        return url


def _jwt_claims(tok):
    try:
        p = tok.split(".")[1]
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception:
        return {}


# ---- Firebase EMAIL_LINK: a whole class of targets, self-provisioned ----
def firebase_emaillink(api_key, target_origin, inbox=None, timeout=180):
    """Fully-autonomous Firebase passwordless (EMAIL_LINK) provision -> verified idToken.

    Beats the "the operator-inbox NEEDS" for any Firebase magic-link app (character_ai win).
    api_key       the public Firebase web API key (usually referer-restricted).
    target_origin e.g. 'https://app.example.com' (sent as continueUrl + Referer/Origin).
    Returns the identitytoolkit signInWithEmailLink JSON (idToken + _claims + _inbox),
    or {'error': ...}.
    """
    inbox = inbox or TempInbox()
    origin = target_origin.rstrip("/")
    hdr = {"Referer": origin + "/", "Origin": origin, "Content-Type": "application/json"}
    base = "https://identitytoolkit.googleapis.com/v1/accounts"
    _post(f"{base}:sendOobCode?key={api_key}", headers=hdr,
          json={"requestType": "EMAIL_SIGNIN", "email": inbox.addr,
                "continueUrl": origin + "/", "canHandleCodeInApp": True})

    def has_oob(m):
        return any(("oobCode=" in l or "/ls/click" in l or "apiKey=" in l) for l in links(m))

    msg = inbox.wait_for(has_oob, timeout=timeout)
    if not msg:
        return {"error": "no oob email arrived", "inbox": inbox.addr}
    oob = None
    for l in links(msg):
        u = l if "oobCode=" in l else unwrap(l)
        m = re.search(r'oobCode=([A-Za-z0-9_\-]+)', u)
        if m:
            oob = m.group(1)
            break
    if not oob:
        return {"error": "oobCode not found in email", "inbox": inbox.addr}
    j = _post(f"{base}:signInWithEmailLink?key={api_key}", headers=hdr,
              json={"email": inbox.addr, "oobCode": oob}).json()
    if "idToken" in j:
        j["_claims"] = _jwt_claims(j["idToken"])
        j["_inbox"] = inbox.addr
    return j


# ---- account store: mint once, reuse; 2-account by default ----
def accounts_dir(handle):
    d = ROOT / "targets" / handle / "accounts"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_account(handle, tag, data):
    p = accounts_dir(handle) / f"{tag}.json"
    p.write_text(json.dumps(data, indent=2))
    # Also append a row to targets/<handle>/ACCOUNTS.md (CLAUDE.md mandates it for cross-session
    # reuse; a hunter checks it before re-provisioning). Fail-open: never break provisioning.
    try:
        md = accounts_dir(handle).parent / "ACCOUNTS.md"
        if not md.exists():
            md.write_text(f"# {handle} provisioned accounts\n\n"
                          "| tag | email | role | state_path | json |\n"
                          "|-----|-------|------|------------|------|\n")
        email = data.get("email") or data.get("addr") or (data.get("inbox") or {}).get("addr") or "-"
        with md.open("a") as f:
            f.write(f"| {tag} | {email} | {data.get('role','-')} | {data.get('state_path','-')} | {p} |\n")
    except Exception:
        pass
    return p


def load_account(handle, tag):
    p = accounts_dir(handle) / f"{tag}.json"
    return json.loads(p.read_text()) if p.exists() else None


def simple_register(register_url, email=None, password="Passw0rd!x", session=None,
                    extra=None, as_form=False, verify="auto", inbox=None,
                    email_field="email", password_field="password", timeout=180):
    """The 80%-common signup: POST email+password, poll the inbox, FOLLOW a verify link or
    RETURN a verify code. Most email/password targets need no custom register_fn - just call
    this (pass extra={...} for required fields). Returns a dict with the register + verify
    result; use it directly as a provision_pair register_fn by closing over register_url."""
    if session is None:
        from curl_cffi import requests as creq
        session = creq.Session(impersonate="chrome124")
    inbox = inbox or TempInbox()
    email = email or inbox.addr
    body = {email_field: email, password_field: password, **(extra or {})}
    reg = (session.post(register_url, data=body, timeout=20) if as_form
           else session.post(register_url, json=body, timeout=20))
    out = {"email": email, "inbox_token": getattr(inbox, "token", None),
           "register_status": reg.status_code, "register_body": (getattr(reg, "text", "") or "")[:400],
           "verify_link": None, "verify_code": None, "verify_status": None}
    if verify and verify != "none":
        msg = inbox.wait_for(lambda m: bool(links(m)) or bool(codes(m)), timeout=timeout)
        if msg:
            wanted = ("verif", "confirm", "activ", "token", "signup", "register")
            ls = [l for l in links(msg) if any(k in l.lower() for k in wanted)] or links(msg)
            cs = codes(msg)
            if ls and verify in ("auto", "link"):
                link = ls[0] if any(k in ls[0].lower() for k in ("verif", "confirm", "activ")) else unwrap(ls[0])
                out["verify_link"] = link
                v = session.get(link, timeout=20, allow_redirects=True)
                out["verify_status"] = v.status_code
            if cs:
                out["verify_code"] = cs[0]
    return out


# ---- browser_register: point at a signup URL, get a logged-in account ----
# WHY: simple_register is curl-only and dies on the common cases (a client-side-rendered form
# with no static POST endpoint, a CSRF token, a CF/DataDome wall, a captcha). signup_recon READS
# the form but stops. fill_form fills but the caller hand-wires every selector + verify + session.
# This is the missing workhorse: clear_wall -> selector-aware recon -> heuristic auto-fill ->
# inbox verify -> storage_state. Returns an account whose state_path feeds lib_auth.session_from_state
# straight into the authed 2nd-account BOLA chain.

# selector-aware form extractor (runs post-render so it sees a CSR form curl reports as empty)
_FORM_JS = r"""() => {
  const esc = s => (window.CSS && CSS.escape) ? CSS.escape(s) : String(s).replace(/([^a-zA-Z0-9_-])/g,'\\$1');
  const fields = [...document.querySelectorAll('input,select,textarea')].map(e => {
    const tag = e.tagName.toLowerCase();
    const sel = e.name ? `[name="${e.name}"]` : (e.id ? '#'+esc(e.id) : null);
    const opts = tag === 'select' ? [...e.options].map(o => o.value) : null;
    const lab = (e.labels && e.labels[0]) ? e.labels[0].textContent.trim().slice(0,60) : null;
    return {sel, name: e.name||e.id||null, type: (e.type||tag).toLowerCase(),
            required: !!e.required, placeholder: e.placeholder||null, label: lab, options: opts,
            hidden: (e.type === 'hidden') || (e.offsetParent === null && tag !== 'select')};
  }).filter(f => f.sel);
  let sub = null;
  const b = document.querySelector('button[type=submit],input[type=submit]');
  if (b) sub = b.id ? '#'+esc(b.id) : 'button[type=submit],input[type=submit]';
  const h = document.documentElement.innerHTML;
  const captcha = /hcaptcha|h-captcha/i.test(h) ? 'hcaptcha'
      : /turnstile|challenges\.cloudflare/i.test(h) ? 'turnstile'
      : /recaptcha|gstatic\.com\/recaptcha/i.test(h) ? 'recaptcha'
      : /arkose|funcaptcha/i.test(h) ? 'arkose' : null;
  return {fields, submit: sub, captcha};
}"""

_PHONE_RE = re.compile(r"phone|mobile|\btel\b|whatsapp|sms", re.I)


def _gen_password():
    # guarantees upper+lower+digit+symbol+len>=12 (the common signup policy) regardless of the suffix
    return "Aa1!" + secrets.token_urlsafe(10)


def _gen_username():
    return "dav" + secrets.token_hex(3)


def _plan_fields(fields, email, password, username):
    """Map a recon'd field list to fill actions. PURE + offline-testable (the load-bearing logic).
    Returns (plan, phone_needed); plan = [(action, selector, name, value)], action in
    fill|check|select. Skips hidden fields (CSRF token / honeypot), leaves optional checkboxes
    unchecked, and flags a REQUIRED phone/OTP field (no free temp-SMS -> the caller emits NEEDS)."""
    plan, phone_needed = [], False
    for f in fields:
        t = (f.get("type") or "").lower()
        sel = f.get("sel") or f.get("selector")
        if not sel or f.get("hidden") or t in ("hidden", "submit", "button", "image", "reset", "file"):
            continue
        name = f.get("name")
        req = f.get("required")
        hay = " ".join(str(f.get(k) or "") for k in ("name", "placeholder", "label")).lower()
        # TYPE-based branches FIRST: a checkbox/select/tel named "...email..." must NOT map to the
        # email value (dogfooding reddit caught 'emailPermission', a marketing opt-in, mis-filled).
        if t == "checkbox":
            if req:
                plan.append(("check", sel, name, None))        # TOS / age gate only, never a marketing opt-in
            continue
        if t == "select":
            plan.append(("select", sel, name, f.get("options"))); continue
        if t == "tel" or _PHONE_RE.search(hay):
            if req:
                phone_needed = True
            continue
        if t == "email":
            plan.append(("fill", sel, name, email)); continue
        if t == "password":
            plan.append(("fill", sel, name, password)); continue   # a confirm-password field gets the same value
        # then NAME/placeholder routing for generic text inputs
        if "email" in hay or "e-mail" in hay:
            plan.append(("fill", sel, name, email))
        elif "passw" in hay or "pwd" in hay:
            plan.append(("fill", sel, name, password))
        elif re.search(r"first|given|\bfname\b", hay):
            plan.append(("fill", sel, name, "Alex"))
        elif re.search(r"last|surname|family|\blname\b", hay):
            plan.append(("fill", sel, name, "Rivera"))
        elif re.search(r"user|handle|nick|login|screen", hay):
            plan.append(("fill", sel, name, username))
        elif t == "date" or re.search(r"birth|\bdob\b", hay):
            plan.append(("fill", sel, name, "1990-01-01"))
        elif re.search(r"full.?name|your.?name|\bname\b", hay):
            plan.append(("fill", sel, name, "Alex Rivera"))
        elif t == "number" or re.search(r"\bage\b|zip|postal", hay):
            plan.append(("fill", sel, name, "1990"))
        elif t in ("text", "search", "url", "textarea") and req:
            plan.append(("fill", sel, name, "test"))           # ponytail: benign filler for an unknown required text field
    return plan, phone_needed


def _submit(page, sel):
    if sel:
        try:
            page.click(sel, timeout=4000); return True
        except Exception:
            pass
    for css in ("button[type=submit]", "input[type=submit]"):
        try:
            page.click(css, timeout=2500); return True
        except Exception:
            pass
    try:
        page.get_by_role("button", name=re.compile(r"sign.?up|register|create|join|continue|next|submit", re.I)).first.click(timeout=2500)
        return True
    except Exception:
        pass
    try:
        page.keyboard.press("Enter"); return True
    except Exception:
        return False


def _fill_steps(page, email, password, username, overrides=None, submit_sel=None,
                max_steps=3, settle_ms=2000):
    """Fill + submit across up to max_steps wizard pages (a modern signup splits email -> details
    -> ...). Re-recons each step; stops when a step adds no new field (a validation re-render loops
    the same selectors -> break, never infinite). Returns {steps, status, captcha}; status is ''
    (proceed to verify) | 'needs-captcha' | 'needs-sms' if a wall appears on any step."""
    ov, attempted, steps = overrides or {}, set(), 0
    for step in range(max_steps):
        try:
            rec = page.evaluate(_FORM_JS)
        except Exception:
            page.wait_for_timeout(1000); rec = page.evaluate(_FORM_JS)
        if rec.get("captcha"):
            return {"steps": steps, "status": "needs-captcha", "captcha": rec["captcha"]}
        plan, phone = _plan_fields(rec.get("fields", []), email, password, username)
        if phone:
            return {"steps": steps, "status": "needs-sms", "captcha": None}
        new = [(a, s, n, v) for (a, s, n, v) in plan if s not in attempted]
        if not new and step > 0:
            break                                              # no fresh field -> flow complete or stuck
        for action, sel, name, val in new:
            try:
                if action == "fill":
                    page.fill(sel, ov.get(name, ov.get(sel, val)))
                elif action == "check":
                    page.check(sel)
                elif action == "select":
                    page.select_option(sel, index=1 if val and len(val) > 1 else 0)
                attempted.add(sel)
            except Exception:
                pass
        if step == 0:                                          # forced fields the heuristic never planned
            planned = {s for _, s, _, _ in plan} | {n for _, _, n, _ in plan}
            for k, v in ov.items():
                if k not in planned:
                    try:
                        page.fill(k if k[:1] in "#.[" else f'[name="{k}"]', v)
                    except Exception:
                        pass
        _submit(page, submit_sel or rec.get("submit"))
        try:
            page.wait_for_load_state("networkidle", timeout=6000)
        except Exception:
            pass
        page.wait_for_timeout(settle_ms)
        steps = step + 1
    return {"steps": steps, "status": "", "captcha": None}


def browser_register(signup_url, handle=None, tag=None, inbox=None, headless=True, proxy=None,
                     scope_file=None, overrides=None, submit_sel=None, verify="auto",
                     verify_timeout=150, settle_ms=2500, max_steps=3):
    """Point at a signup URL, get a logged-in account. The account-creation workhorse: composes
    clear_wall + selector-aware recon + heuristic auto-fill + inbox verify + storage_state dump.

    overrides = {field_name_or_selector: value} forces a field the heuristic missed.
    Returns {status, email, password, username, state_path, verify_link, verify_status, captcha, fields}.
    status: 'ok' (verify link followed OR verify='none') | 'submitted' (no verify email seen) |
            'needs-captcha' | 'needs-sms' | 'error'. On needs-*, emit ONE `NEEDS:` line - do NOT grind.
    Feed state_path to lib_auth.session_from_state for the authed curl session (-> BOLA chain)."""
    _ensure_bbtools_path()
    from bbtools.lib_browser import browser, clear_wall, dump_state   # lazy: keep the curl path import-light
    password, username = _gen_password(), _gen_username()
    out = {"status": "error", "signup_url": signup_url, "email": None, "password": None,
           "username": None, "state_path": None, "verify_link": None, "verify_code": None,
           "verify_status": None, "captcha": None, "fields": [], "note": None}
    try:
        with browser(headless=headless, proxy=proxy) as ctx:
            pg = ctx.new_page()
            clear_wall(pg, signup_url, scope_file=scope_file)
            pg.wait_for_timeout(settle_ms)                     # let a CSR form paint
            try:
                rec = pg.evaluate(_FORM_JS)
            except Exception:
                pg.wait_for_timeout(1000); rec = pg.evaluate(_FORM_JS)   # a late client redirect killed the ctx
            out["fields"], out["captcha"] = rec.get("fields", []), rec.get("captcha")
            if rec.get("captcha"):
                out["status"] = "needs-captcha"
                out["note"] = f"captcha={rec['captcha']} on signup; solve in-browser if trivial, else NEEDS"
                return out
            _, phone_needed = _plan_fields(rec.get("fields", []), "placeholder", password, username)
            if phone_needed:
                out["status"] = "needs-sms"
                out["note"] = "required phone/OTP field and no free temp-SMS -> NEEDS a number"
                return out
            ib = inbox or TempInbox()                          # mint only once we know we can proceed
            out["email"], out["password"], out["username"] = ib.addr, password, username
            r = _fill_steps(pg, ib.addr, password, username, overrides=overrides,
                            submit_sel=submit_sel, max_steps=max_steps, settle_ms=settle_ms)
            out["steps"] = r["steps"]
            if r["status"] in ("needs-captcha", "needs-sms"):  # a wall surfaced on a later wizard step
                out["status"] = r["status"]
                out["captcha"] = r.get("captcha") or out["captcha"]
                out["note"] = f"mid-signup {r['status']} on step {r['steps'] + 1}"
                return out
            if verify and verify != "none":
                msg = ib.wait_for(lambda m: bool(links(m)) or bool(codes(m)), timeout=verify_timeout)
                if msg:
                    wanted = ("verif", "confirm", "activ", "token", "signup", "register", "welcome")
                    ls = [l for l in links(msg) if any(k in l.lower() for k in wanted)] or links(msg)
                    if ls:
                        link = ls[0] if any(k in ls[0].lower() for k in ("verif", "confirm", "activ")) else unwrap(ls[0])
                        out["verify_link"] = link
                        try:
                            vpg = ctx.new_page(); vpg.goto(link, wait_until="domcontentloaded", timeout=30000)
                            out["verify_status"] = 200
                        except Exception as e:
                            out["verify_status"] = str(e)[:80]
                    cs = codes(msg)
                    if cs:
                        out["verify_code"] = cs[0]
            sp = str(accounts_dir(handle) / f"{tag or 'A'}.state.json") if handle else tempfile.NamedTemporaryFile(delete=False, suffix=".state.json").name
            dump_state(ctx, sp)
            out["state_path"] = sp
            out["status"] = "ok" if (out["verify_status"] == 200 or verify == "none") else "submitted"
            if handle:
                save_account(handle, tag or "A", {"email": ib.addr, "password": password,
                             "username": username, "state_path": sp,
                             "_inbox_token": getattr(ib, "token", None), "verify_status": out["verify_status"]})
    except Exception as e:
        out["note"] = f"error: {str(e)[:120]}"
    return out


def provision_roles(handle, role_signup_urls, **kw):
    """Mint one account per named role and store each.

    role_signup_urls: {role_name: signup_url}  e.g. {"buyer": "https://.../signup",
                                                      "seller": "https://.../seller/signup"}

    Each account is provisioned via browser_register (for CSR/walled signups) and stored
    under tag=role_name so load_account(handle, "seller") retrieves the seller account.

    Returns {role_name: account_dict} where each account_dict carries a state_path.
    """
    out = {}
    for role, url in role_signup_urls.items():
        out[role] = browser_register(url, handle=handle, tag=role, **kw)
    return out


def provision_pair_browser(handle, signup_url, tags=("A", "B"), roles=None, **kw):
    """Mint TWO accounts via browser_register (the IDOR/BOLA default for a CSR/walled signup).
    Returns (A, B) account dicts; each carries a state_path for lib_auth.session_from_state.

    roles: optional tuple/list of two role-specific signup URLs that override signup_url per
    account so A and B land in DIFFERENT roles.  When set, roles[0] is used for tags[0] and
    roles[1] for tags[1]:

      A, B = provision_pair_browser(
          "myshop", "https://app/signup",
          roles=("https://app/signup?type=buyer", "https://app/seller/signup")
      )

    When roles is None (the default), both accounts use signup_url - the original behavior.
    """
    if roles is not None and len(roles) != len(tags):
        raise ValueError(f"roles must have the same length as tags ({len(tags)}); got {len(roles)}")
    out = []
    for i, tag in enumerate(tags):
        url = roles[i] if roles is not None else signup_url
        out.append(browser_register(url, handle=handle, tag=tag, **kw))
    return tuple(out)


def provision_pair(handle, register_fn, tags=("A", "B"), timeout=180, roles=None):
    """Mint TWO accounts (the IDOR/BOLA default) and store both.

    register_fn(inbox) does the target-specific register+verify+login and returns a
    creds/token dict; everything else (inbox, 2-account, storage) is reused here.

    roles: optional tuple/list of two callables that each accept (inbox) and return a
    creds dict, overriding register_fn per account so A and B land in DIFFERENT roles:

      A, B = provision_pair(
          "myshop",
          register_fn=None,              # unused when roles is set
          roles=(
              lambda ib: simple_register("https://app/signup", inbox=ib),           # buyer
              lambda ib: simple_register("https://app/seller/signup", inbox=ib),    # seller
          )
      )

    When roles is None (the default), both accounts use register_fn - the original behavior.
    """
    if roles is not None and len(roles) != len(tags):
        raise ValueError(f"roles must have the same length as tags ({len(tags)}); got {len(roles)}")
    out = []
    for i, tag in enumerate(tags):
        fn = roles[i] if roles is not None else register_fn
        ib = TempInbox()
        data = dict(fn(ib) or {})
        data.setdefault("email", ib.addr)
        data["_inbox_token"] = ib.token
        save_account(handle, tag, data)
        out.append(data)
    return tuple(out)


def _selfcheck():
    # pure extractor logic - no network
    fake = {"text": "your code is 123456 -> https://url1234.ex.com/ls/click?u=x", "html": []}
    assert codes(fake) == ["123456"], codes(fake)
    assert links(fake) == ["https://url1234.ex.com/ls/click?u=x"], links(fake)
    # a null HTML part must not crash extraction
    assert "123456" in msg_body({"text": "code 123456", "html": [None, "<b>x</b>"]})
    tok = "h." + base64.urlsafe_b64encode(b'{"email_verified":true}').decode().rstrip("=") + ".s"
    assert _jwt_claims(tok)["email_verified"] is True

    # simple_register orchestration (offline fakes)
    class _FR:
        status_code = 200
        text = '{"ok":1}'

    class _FakeSess:
        got = None

        def post(self, u, **k):
            return _FR()

        def get(self, u, **k):
            _FakeSess.got = u
            return _FR()

    class _FakeInbox:
        addr = "fake@x.com"
        token = "T"

        def wait_for(self, pred, timeout=0):
            m = {"text": "confirm https://x.com/verify?token=abc123 your code 654321", "html": []}
            return m if pred(m) else None

    r = simple_register("https://x.com/register", session=_FakeSess(), inbox=_FakeInbox())
    assert r["verify_link"] == "https://x.com/verify?token=abc123", r["verify_link"]
    assert r["verify_status"] == 200 and r["verify_code"] == "654321", r
    assert _FakeSess.got == "https://x.com/verify?token=abc123", "verify link not followed"

    # browser_register field-planning heuristic (pure, the load-bearing logic)
    fs = [
        {"sel": '[name="email"]', "name": "email", "type": "email", "required": True},
        {"sel": '[name="password"]', "name": "password", "type": "password", "required": True},
        {"sel": '[name="password2"]', "name": "password2", "type": "password", "required": True,
         "placeholder": "Confirm password"},
        {"sel": '[name="username"]', "name": "username", "type": "text", "required": True},
        {"sel": '[name="first_name"]', "name": "first_name", "type": "text", "required": True},
        {"sel": '[name="csrf"]', "name": "csrf", "type": "hidden", "required": False},
        {"sel": '[name="tos"]', "name": "tos", "type": "checkbox", "required": True},
        {"sel": '[name="news"]', "name": "news", "type": "checkbox", "required": False},
        {"sel": '[name="emailPermission"]', "name": "emailPermission", "type": "checkbox", "required": False},
        {"sel": "#hp", "name": "nickname", "type": "text", "required": False, "hidden": True},
    ]
    plan, phone = _plan_fields(fs, "a@b.co", "PW1", "userX")
    d = {name: (act, val) for act, sel, name, val in plan}
    assert d["email"] == ("fill", "a@b.co"), d
    assert d["password"][1] == "PW1" and d["password2"][1] == "PW1", d   # confirm gets the same pw
    assert d["username"] == ("fill", "userX") and d["first_name"][1] == "Alex", d
    assert d["tos"][0] == "check", d
    assert "news" not in d, "optional checkbox must stay unchecked"
    assert "emailPermission" not in d, "a checkbox named ...email... must NOT map to the email value (reddit dogfood)"
    assert "csrf" not in d and "nickname" not in d, "hidden csrf + honeypot must be skipped"
    assert phone is False
    _, ph2 = _plan_fields([{"sel": '[name="phone"]', "name": "phone", "type": "tel", "required": True}],
                          "a@b.co", "p", "u")
    assert ph2 is True, "required phone must flag needs-sms"
    assert re.match(r"Aa1!\S{8,}", _gen_password()), "gen password policy"

    # live browser fill round-trip (proves the _FORM_JS extraction + plan + Playwright exec wire up)
    _ensure_bbtools_path()
    try:
        from bbtools.lib_browser import browser
    except Exception:
        browser = None
    if browser:
        with browser(headless=True) as ctx:
            pg = ctx.new_page()
            pg.set_content("<form>"
                           "<input name='email' type='email' required>"
                           "<input name='password' type='password' required>"
                           "<input name='username' type='text' required>"
                           "<input name='csrf' type='hidden' value='xyz'>"
                           "<input name='tos' type='checkbox' required>"
                           "<button type='submit'>Create account</button></form>")
            rec = pg.evaluate(_FORM_JS)
            assert rec["captcha"] is None and rec["submit"], rec
            bplan, bph = _plan_fields(rec["fields"], "live@temp.co", "Aa1!secretpw", "davxyz")
            for action, sel, name, val in bplan:
                if action == "fill":
                    pg.fill(sel, val)
                elif action == "check":
                    pg.check(sel)
            assert pg.input_value('[name="email"]') == "live@temp.co", "email not filled"
            assert pg.input_value('[name="username"]') == "davxyz" and pg.is_checked('[name="tos"]'), "fill/check"

            # multi-step wizard: email step -> Continue -> username/password step. _fill_steps must
            # advance and fill BOTH (the reddit-class SPA signup the single-shot path misses).
            wiz = ctx.new_page()
            wiz.set_content(
                "<div id='app'></div><script>"
                "function step2(){document.getElementById('app').innerHTML="
                "\"<form><input name='username' type='text' required>"
                "<input name='password' type='password' required>"
                "<button type='button'>Finish</button></form>\";}"
                "document.getElementById('app').innerHTML="
                "\"<form><input name='email' type='email' required>"
                "<button type='button' onclick='step2()'>Continue</button></form>\";"
                "</script>")
            wr = _fill_steps(wiz, "wiz@temp.co", "Aa1!wizpw", "wizuser", max_steps=3, settle_ms=250)
            assert wr["steps"] == 2, wr
            assert wiz.input_value('[name="username"]') == "wizuser", "step-2 field not filled"
        print("  browser_register: field-plan heuristic + live fill + multi-step wizard ok")

    # provision_pair roles param (pure, no network)
    # Patch via the module's global dict so it works whether run as __main__ or bbtools.lib_provision
    import sys as _sys
    _mod = _sys.modules[__name__]   # the current module object regardless of how it was invoked
    _role_calls = []
    def _buyer_fn(ib):
        _role_calls.append("buyer")
        return {"role": "buyer", "email": ib.addr}
    def _seller_fn(ib):
        _role_calls.append("seller")
        return {"role": "seller", "email": ib.addr}
    _orig_save = _mod.save_account
    _saved = []
    def _fake_save(h, t, d): _saved.append((h, t, d))
    _mod.save_account = _fake_save
    _orig_TI = _mod.TempInbox
    class _FTI:
        addr = "role@x.com"; token = "T3"
        def __init__(self): pass
    _mod.TempInbox = _FTI
    try:
        A2, B2 = provision_pair("_test_handle", None, roles=(_buyer_fn, _seller_fn))
        assert _role_calls == ["buyer", "seller"], _role_calls
        assert A2["role"] == "buyer" and B2["role"] == "seller", (A2, B2)
        assert any(t == "A" for (_, t, _) in _saved), _saved
        assert any(t == "B" for (_, t, _) in _saved), _saved
    finally:
        _mod.save_account = _orig_save
        _mod.TempInbox = _orig_TI

    # provision_pair roles length mismatch raises
    try:
        provision_pair("_h", lambda ib: {}, roles=(lambda ib: {},))   # 1 role, 2 tags
        assert False, "should have raised ValueError"
    except ValueError:
        pass

    # provision_pair_browser roles length mismatch raises
    try:
        provision_pair_browser("_h", "https://x.com/signup", roles=("a",))
        assert False, "should have raised ValueError"
    except ValueError:
        pass

    print("  provision_pair/provision_pair_browser roles param ok (pure)")

    # one live mint (same egress the hunt uses)
    ib = TempInbox()
    assert "@" in ib.addr and ib.token, "inbox mint failed"
    print("SELFCHECK OK  extractors+jwt pass, inbox=", ib.addr)


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return
    cmd = argv[0]
    if cmd == "inbox":
        ib = TempInbox()
        print(json.dumps({"address": ib.addr, "password": ib.password, "token": ib.token}, indent=2))
    elif cmd == "wait":
        ib = TempInbox.attach(argv[1])
        secs = int(argv[2]) if len(argv) > 2 else 150
        for m in ib.poll(timeout=secs):
            print("FROM", m.get("from"), "SUBJ", m.get("subject"))
            for l in links(m):
                print("  LINK", l)
            for c in codes(m):
                print("  CODE", c)
    elif cmd == "firebase":
        print(json.dumps(firebase_emaillink(argv[1], argv[2]), indent=2))
    elif cmd == "register":
        if len(argv) < 2:
            print("usage: register <signup_url> [--handle h --tag A --proxy p --scope f --head --verify none]")
            return
        url, a, i = argv[1], {}, 2
        while i < len(argv):
            if argv[i].startswith("--"):
                k = argv[i][2:]
                if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                    a[k] = argv[i + 1]; i += 2
                else:
                    a[k] = True; i += 1
            else:
                i += 1
        r = browser_register(url, handle=a.get("handle"), tag=a.get("tag"), proxy=a.get("proxy"),
                             scope_file=a.get("scope"), headless=not a.get("head"),
                             verify=a.get("verify", "auto"))
        print(json.dumps({k: v for k, v in r.items() if k != "fields"}, indent=2))
        print(f"# fields seen: {len(r.get('fields', []))}; feed state_path to lib_auth.session_from_state")
    elif cmd == "pair":
        # One-command 2nd-account provisioning (the credential-wall reflex is 45% of quits).
        if len(argv) < 3:
            print("usage: pair <handle> <signup_url> [--proxy p --scope f --head --verify none] "
                  "[--roleA url --roleB url]")
            return
        handle, url, a, i = argv[1], argv[2], {}, 3
        while i < len(argv):
            if argv[i].startswith("--"):
                k = argv[i][2:]
                if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                    a[k] = argv[i + 1]; i += 2
                else:
                    a[k] = True; i += 1
            else:
                i += 1
        roles = (a["roleA"], a["roleB"]) if a.get("roleA") and a.get("roleB") else None
        A, B = provision_pair_browser(handle, url, roles=roles, proxy=a.get("proxy"),
                                      scope_file=a.get("scope"), headless=not a.get("head"),
                                      verify=a.get("verify", "auto"))
        print(json.dumps({"A": {k: v for k, v in A.items() if k != "fields"},
                          "B": {k: v for k, v in B.items() if k != "fields"}}, indent=2))
        print(f"# A+B minted for {handle}; saved to targets/{handle}/accounts/ + ACCOUNTS.md; "
              f"feed each state_path to lib_auth.session_from_state, then run the paired cross-account BOLA")
    elif cmd == "selfcheck":
        _selfcheck()
    else:
        print("unknown cmd:", cmd)
        print(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
