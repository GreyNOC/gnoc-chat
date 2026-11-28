"""gnoc_secrets.py - keep the user's own credentials out of everything the local models see, write or send.

Sources of secret VALUES (loaded lazily, refreshed when a file changes, never printed):
    ~/.config/gnoc/*.env and *.token      (secrets.env: platform API tokens, account passwords ...)
    process environment variables whose NAME looks sensitive (TOKEN, SECRET, PASS, KEY, AUTH, COOKIE, SESSION)
Only values of 8+ characters count, and obvious non-secrets (paths, URLs without credentials, numbers, booleans)
are skipped, so ordinary text is never mangled.

Used by gnoc_agent at every boundary:
    redact(text)       every tool result before the model reads it, and briefs handed to other agents
    find(text)         -> names of secrets present: writes (write_file, edit_file) and outbound requests
                          (http_request, probe_matrix) are REFUSED when the content carries one
    is_secret_path(p)  files whose values never enter the chat (read_file / grep / the shell guard)
Private-key blocks are redacted by pattern even when they are not in any store.
"""
import base64
import contextlib
import glob
import json
import os
import re
import urllib.parse

CONF = os.path.expanduser("~/.config/gnoc")
SENSITIVE_NAME = re.compile(r"(TOKEN|SECRET|PASS|PASSWD|PASSWORD|API_?KEY|(^|_)KEY($|_)|PRIVATE|AUTH|COOKIE|SESSION|"
                            r"CREDENTIAL|BEARER|JWT|SIGNING|SEED|MNEMONIC|(^|_)PAT($|_)|PWD|WEBHOOK|DSN|"
                            r"DATABASE_URL|REDIS_URL|MONGO\w*_URL|AMQP_URL)", re.I)
NOT_SECRET = re.compile(r"^(true$|false$|yes$|no$|none$|null$|\d+$|https?://[^@\s]*$)", re.I)
# a URL under a sensitive name IS the secret when the name says so: a Discord/Slack webhook URL or a database
# DSN carries its credential in the path or the userinfo (QAQC r2: every https:// value counted as public)
_URL_SECRET_NAME = re.compile(r"(WEBHOOK|DSN|DATABASE_URL|REDIS_URL|MONGO\w*_URL|AMQP_URL|TOKEN|SECRET)", re.I)
# Names WE publish in DNS are not secrets, and registering one corrupts every path and hostname the model
# reads. A cookie in a stale Playwright session file carried the exact value "grey-noc" (8 chars, precisely
# the floor in _usable), so every mention of our own site came back as
# "~/Desktop/chat.[REDACTED:...].com" - and the agent fed that redacted string straight back into its
# next read_file, which then failed (measured 2026-10-25, while teaching the bot to run the site). A value
# equal to a name we publish is already public, so excluding it removes no cover: anything that is BOTH a
# real credential and one of these needs rotating, not redacting.
PUBLIC_NAMES = frozenset({"grey-noc", "your-site.example", "your-site.example", "your-site.example"})
_PATHISH = re.compile(r"^(~|\.{0,2})/")
# Matched as a BEGIN marker plus a forward search for END, never as one lazy .*? pair: the pair form is
# quadratic and took 57 s on 20 KB of repeated unterminated BEGIN markers (a model can paste that).
# PGP's "PRIVATE KEY BLOCK" and lower-case markers too (QAQC r2: an armored PGP secret key passed every check)
_PK_BEGIN = re.compile(r"(?i)-----BEGIN [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----")
_PK_END = re.compile(r"(?i)-----END [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----")


def _redact_private_keys(t):
    """Replace every BEGIN..END private-key block; an unterminated BEGIN redacts to the end of the text."""
    out, pos = [], 0
    for m in _PK_BEGIN.finditer(t):
        if m.start() < pos:
            continue
        e = _PK_END.search(t, m.end())
        out.append(t[pos:m.start()])
        out.append("[REDACTED:PRIVATE-KEY]")
        pos = e.end() if e else len(t)
    out.append(t[pos:])
    return "".join(out)
SECRET_FILE = re.compile(r"(^\.env($|\.)|\.env$|\.token$|^id_(rsa|ed25519|ecdsa|dsa)$|\.(pem|key|p12|pfx|keystore|jks|ppk)$|"
                         r"^\.netrc$|^\.pgpass$|^\.?credentials(\.json)?$|^\.git-credentials$|^secrets?\.(env|json|ya?ml)"
                         r"(\.|$)|^identities\.json$|^\.npmrc$|^hosts\.yml$|_history$|^\.pypirc$|^kubeconfig$)")
SECRET_DIRS = tuple(os.path.expanduser(d) for d in (
    "~/.config/gnoc", "~/.ssh", "~/.aws", "~/.gnupg", "~/.config/gh", "~/.docker", "~/.kube",
    "~/.local/share/keyrings", "~/.mozilla", "~/.config/google-chrome", "~/.config/chromium", "~/.password-store",
    "~/.codex", "~/.cloudflared", "~/.pm2", "~/.config/gcloud", "~/.azure", "~/.config/op", "~/.1password"))
# ORACLE: the two settlement keys. The oracle seal HMACs every capture and verdict row; the economy settler signs
# every mint. A model that reads either can forge a PASS or a payout, so both are secret paths (read_file, grep and
# write_file refuse them), shell reads of them are refused (SHELL_SECRET), and their VALUES are redacted from every
# tool result and refused on writes and on the wire (values()).
_WS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_SECRET_FILES = (os.path.join(_WS, ".claude/state/hunt-loop/oracles/.seal"),
                      os.path.join(_WS, ".claude/state/economy/.settler"))
SECRET_DIRS = SECRET_DIRS + STATE_SECRET_FILES
_cache = {"sig": None, "vals": []}
# research-identity values (gnoc_ident): redacted from everything a model reads, but NOT refused on the wire,
# because sending them is the point (a session of an account we own). Never GreyNOC's own credentials.
_EXTRA = {}
_EXTRA_VER = [0]


def register_extra(name, value):
    v = _usable(value)
    if v and _EXTRA.get(v) != name:
        _EXTRA[v] = name
        _EXTRA_VER[0] += 1


# credential files OUTSIDE the store whose values are redacted too (QAQC r2: Claude Code's own login token)
EXTRA_SECRET_FILES = tuple(os.path.expanduser(f) for f in ("~/.claude/.credentials.json",))


# folders in the store that hold a BROWSER, not credentials: a Chrome profile is thousands of cache, locale and
# service-worker files, and reading them as secrets turned ~60 values into 4,782 and made every redact() cost
# 0.4 s (2026-11-19: `gnoc chat` sat on "starting..." for minutes). They stay out of reach through SECRET_DIRS
# (the whole store is a secret path); they are just not string-matched.
_BROWSER_DIR = re.compile(r"(?i)chrom|firefox|mozilla|profile|cache|crashpad|extensions|service worker|"
                          r"webstorage|indexeddb|blob_storage|local storage|session storage")
_BROWSER_MARK = ("Local State", "Preferences", "Cookies", "History")


def _files():
    # every credential file in the store counts, in its subfolders and hidden ones included: *.key, *session*.json,
    # secrets.env.bak*, meta-muse/*.json and dot-files all held live values (QAQC r2: only the top level was read)
    out = set()
    for dp, dns, fns in os.walk(CONF):
        depth = dp[len(CONF):].count(os.sep)
        if dp != CONF and (depth > 2 or any(m in fns for m in _BROWSER_MARK)):
            dns[:] = []
            continue
        dns[:] = [d for d in dns if not os.path.islink(os.path.join(dp, d)) and not _BROWSER_DIR.search(d)]
        for fn in fns:
            f = os.path.join(dp, fn)
            if os.path.isfile(f) and os.path.getsize(f) <= 256_000:
                out.add(f)
    out |= {f for f in EXTRA_SECRET_FILES if os.path.isfile(f)}
    return sorted(out)


def _sig():
    out = []
    for f in _files() + [f for f in STATE_SECRET_FILES if os.path.isfile(f)]:
        try:
            out.append((f, os.path.getmtime(f)))
        except OSError:
            pass
    return tuple(out), tuple(sorted(k for k in os.environ if SENSITIVE_NAME.search(k)))


def _is_path(v):
    """A value that is a filesystem path, not a secret. A leading '/' alone is not enough: an AWS secret access key
    is base64 and starts with '/' one time in 64, and that key was never redacted. A path exists, or its parent
    directory does (a file not created yet); an AWS key's parent never does."""
    if not _PATHISH.match(v):
        return False
    p = os.path.expanduser(v)
    parent = os.path.dirname(p.rstrip("/"))
    return os.path.exists(p) or (parent not in ("", "/", ".", "..") and os.path.isdir(parent))


def _usable(v):
    v = (v if isinstance(v, str) else "").strip().strip("'\"")
    if v.lower() in PUBLIC_NAMES:
        return None
    return v if len(v) >= 8 and not NOT_SECRET.match(v) and not _is_path(v) else None


# NAME=value in a store file. The quoted alternatives deliberately span newlines: a value written as
#   MULTI_KEY="line1
#   line2"
# used to register only "line1, leaving line2 un-redacted on the wire.
_ENV_PAIR = re.compile(r"""(?m)^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*"""
                       r"""(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|([^\n]*?)(?=[ \t]+\#|[ \t]*$))""")
# (the unquoted form ends at a ' #' comment, as in the shell: a '#' INSIDE a token is part of it. It used to cut the
# value at the first '#', so TOKEN=abc#defghijklmn registered nothing and the token went out unredacted.)


def _value_pieces(raw, name=""):
    """Every independently-secret string inside one stored value: the whole value, each line of a multi-line
    value, the password of a user:pass@host URL (a sender can carry just the password), the token of a stored
    'Bearer <token>' header value, and each cookie value of a stored cookie jar (a request can carry one cookie)."""
    out = []
    whole = _usable(raw)
    if whole:
        out.append(whole)
        m = re.match(r"(?i)^(bearer|basic|token|bot)\s+(\S+)$", whole)
        if m and _usable(m.group(2)):
            out.append(_usable(m.group(2)))
        if "COOKIE" in (name or "").upper():
            for part in re.split(r";\s*", whole):
                v = _usable(part.split("=", 1)[1]) if "=" in part else None
                if v:
                    out.append(v)
    if "\n" in (raw or ""):
        for ln in raw.splitlines():
            v = _usable(ln)
            if v:
                out.append(v)
    for src in (whole,) if whole else ():
        with contextlib.suppress(Exception):
            pw = urllib.parse.urlsplit(src).password
            if pw and _usable(pw):
                out.append(_usable(pw))
    return out


def values():
    """[(name, value)] longest first, so a token that contains another is replaced whole."""
    sig = _sig()
    if sig == _cache["sig"]:
        return _cache["vals"]
    vals = {}
    for f in _files():
        base = os.path.basename(f)
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:   # runs on every store change: close the fd
                text = fh.read()
        except OSError:
            continue
        if f.endswith((".token", ".key", ".pem")):
            v = _usable(text)
            if v:
                vals[v] = base
            for ln in text.splitlines():  # a key file is its lines too (a PEM body line is a secret on its own)
                v = _usable(ln)
                if v and len(v) >= 16 and not ln.startswith("-----"):
                    vals[v] = base
            continue
        if f.endswith(".json") or text.lstrip()[:1] in ("{", "["):
            def walk(o, key="", base=base):
                if isinstance(o, dict):
                    for k, x in o.items():
                        walk(x, str(k))
                elif isinstance(o, list):
                    for x in o:
                        walk(x, key)
                # a browser storage state ({"name": "sid", "value": "..."}) keys every cookie as "value": in a
                # session / cookie / credential file that key is the secret, however short
                elif isinstance(o, str) and (SENSITIVE_NAME.search(key) or len(o) >= 24 or
                                             (key == "value" and SENSITIVE_NAME.search(base))) and _usable(o):
                    vals[_usable(o)] = f"{base}:{key or 'value'}"
            try:
                walk(json.loads(text))
            except ValueError:
                pass
            continue
        for m in _ENV_PAIR.finditer(text):
            name = m.group(1)
            # a store also holds non-secret settings (a username, an inbox address): only sensitive names count
            if not SENSITIVE_NAME.search(name):
                continue
            raw = m.group(2) if m.group(2) is not None else \
                (m.group(3) if m.group(3) is not None else (m.group(4) or ""))
            if m.group(2) is not None:   # a double-quoted shell value: the shell unescapes \" \\ \$ \`
                raw = re.sub(r'\\([\\"$`])', r"\1", raw)
            for piece in _value_pieces(raw, name):
                vals[piece] = name
            if _URL_SECRET_NAME.search(name) and re.match(r"(?i)^[a-z][a-z0-9+.-]*://\S{8,}$", raw.strip()):
                vals[raw.strip()] = name
    for f in STATE_SECRET_FILES:  # ORACLE: the seal and the settler key, created by code after import
        with contextlib.suppress(OSError):
            with open(f, encoding="utf-8", errors="replace") as fh:
                v = _usable(fh.read())
            if v:
                vals[v] = os.path.basename(f).lstrip(".") or "state-secret"
    for k, v in os.environ.items():
        if SENSITIVE_NAME.search(k):
            v = _usable(v)
            if v:
                vals.setdefault(v, k)
    _cache["sig"], _cache["vals"] = sig, sorted(((n, v) for v, n in vals.items()), key=lambda x: -len(x[1]))
    return _cache["vals"]


def encodings(v):
    """The forms one secret takes on the wire. A raw-substring check alone missed every one of these: a token
    URL-encoded into a query, base64'd into a body, or wrapped in a Basic credential still leaves the machine."""
    out = {v}
    with contextlib.suppress(Exception):
        out.add(urllib.parse.quote(v, safe=""))
        out.add(urllib.parse.quote_plus(v))
    with contextlib.suppress(Exception):
        b = v.encode()
        out.add(base64.b64encode(b).decode())
        out.add(base64.b64encode(b).decode().rstrip("="))
        out.add(base64.urlsafe_b64encode(b).decode().rstrip("="))
        for user in ("", "x", "api", "token", "user"):  # Basic <base64(user:secret)>
            out.add(base64.b64encode(f"{user}:{v}".encode()).decode())
    with contextlib.suppress(Exception):
        out.add(json.dumps(v)[1:-1])          # JSON string escaping of " and \
        out.add(v.replace(" ", "\\u0020"))    # a value with spaces, \u-escaped into a JSON body
    return {x for x in out if len(x) >= 8}


def _all_pairs(extra=False):
    """Every (name, form) to look for. extra=True adds the registered identity header values, which are
    REDACTED from model output but must never be reported by find(): find() backs the wire leak-check, and
    the agent's own authed request legitimately carries its identity's cookie."""
    vals = values()
    key = (id(vals), _cache["sig"], _EXTRA_VER[0] if extra else 0)
    hit = _pairs_cache.get(bool(extra))
    if hit and hit[0] == key:
        return hit[1]   # every form of every value, built once per change of the store (it ran on EVERY redact)
    pairs = list(vals)
    if extra:
        pairs += sorted(((n, v) for v, n in _EXTRA.items()), key=lambda x: -len(x[1]))
    out = {}
    for n, v in pairs:
        for form in encodings(v):
            out.setdefault(form, n)
    res = sorted(((n, f) for f, n in out.items()), key=lambda x: -len(x[1]))
    _pairs_cache[bool(extra)] = (key, res)
    return res


_pairs_cache = {}


def _text(x):
    """bytes are decoded, not str()'d: str(b'tok') is "b'tok'" and an escaped byte (\\x..) hid the token."""
    if isinstance(x, (bytes, bytearray)):
        return bytes(x).decode("utf-8", "surrogateescape")
    return x if isinstance(x, str) else str(x)


def find(text):
    """Names of the secrets whose values appear in text (never the values)."""
    if not text:
        return []
    t = _text(text)
    names = [n for n, v in _all_pairs() if v in t]
    if _PK_BEGIN.search(t):
        names.append("PRIVATE-KEY")
    return sorted(set(names))


def redact(text):
    """text with every known secret replaced by [REDACTED:<name>]. None / empty come back as given; bytes come
    back as bytes; anything else is str()'d."""
    if not text:
        return text
    if isinstance(text, (bytes, bytearray)):
        return redact(_text(text)).encode("utf-8", "surrogateescape")
    t = _text(text)
    for n, v in _all_pairs(extra=True):
        if v in t:
            t = t.replace(v, f"[REDACTED:{n}]")
    return _redact_private_keys(t)


SYSTEM_SECRET_FILES = ("/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-", "/etc/security/opasswd")


def is_secret_path(p):
    """A file whose contents never go to a model: secret stores, key material, credential files."""
    rp = os.path.realpath(os.path.expanduser(p or ""))
    if any(rp == d or rp.startswith(d + os.sep) for d in SECRET_DIRS):
        return True
    if rp in SYSTEM_SECRET_FILES:   # password hashes: `sudo cat /etc/shadow` would put them in the model's context
        return True
    if SECRET_FILE.search(os.path.basename(rp)):
        return True
    try:
        with open(rp, "rb") as f:
            head = f.read(4096)
        # a key block STARTS a line; a source file that merely mentions the marker (this one) is not a key
        return bool(re.search(rb"(?im)^\s*-----BEGIN [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----|^PuTTY-User-Key-File",
                              head))
    except OSError:
        return False


# shell commands that read a secret store or dump the environment: refused before they run
SHELL_SECRET = re.compile(r"(\.config/bb[^ /]*|bb-hun|secrets?\.env|\.env\b|\.token\b|identities\.json|/\.ssh/|\.aws/|"
                          r"\.netrc|\.git-credentials|\.gnupg|\.claude/\.credentials|\.credentials\.json|\.npmrc|"
                          r"\.docker/|gh/hosts\.yml|\.kube/|\.pgpass|\.bash_history|\.zsh_history|keyrings|\.mozilla/|"
                          # credential stores the guard missed while the read needed no approval (audit A-02,
                          # each confirmed ALLOWED on 2026-10-22): another coding agent's token, the Cloudflare
                          # tunnel cert, and the pm2 dump, which carries every process env var.
                          r"\.codex/|\.cloudflared/|\.pm2/dump|\.pm2/module_conf|\.config/gcloud/|"
                          r"\.azure/|\.terraform\.d/|\.netlify/|\.vercel/|\.config/op/|\.1password/|"
                          r"/proc/[^ ]*/env|\bps\s+(?:[a-zA-Z]*e[a-zA-Z]*)(?=\s|$)|\bps\b[^|;&\n]*\s-[a-zA-Z]*E|"
                          r"\b(?:declare|typeset)\s+-[a-zA-Z]*p|\bcompgen\s+-e|"
                          # an interpreter one-liner that opens a credential place or the environment
                          # (the code is usually quoted and holds ';': the whole line is the code's span)
                          r"\b(?:python3?|perl|ruby|node|php)\b[^|;&\n]*\s-[ceE]\b[^\n]*(?:\.config|\.ssh|"
                          # the WHOLE environment, never one named key (printenv HOME is allowed too)
                          r"credential|environ\b(?!\s*(?:\.get\b|\[))|%ENV\b|process\.env\b(?!\s*[.\[])|"
                          r"(?<!process)\.env\b|bb-h)|"
                          # ORACLE: the oracle seal and the economy settler key, and a glob or whole-dir read of
                          # either state dir (cat .claude/state/hunt-loop/oracles/.s*, grep -r x oracles/)
                          r"(^|[\s/'\"=<(])\.(seal|settler)\b|(hunt-loop/oracles|state/economy)/?(\s|$|[*?\[]|\.[^/\s]*)|"
                          r"^\s*(env|printenv|set|export\s+-p|declare\s+-x)\s*($|[|;>])|"
                          r"[|;&]\s*(env|printenv)\s*($|[|;>]))")


_SECRET_BASENAMES = (".git-credentials", ".netrc", ".pgpass", "secrets.env", "secret.env", ".env", "id_rsa",
                     "id_ed25519", "id_ecdsa", "credentials", ".credentials.json", "credentials.json", "identities.json",
                     ".npmrc", ".pypirc", "hosts.yml", ".bash_history", ".zsh_history", ".seal", ".settler")


def _names_only(flat):
    """True for a command that only LISTS names: find / ls / tree with no -exec/-delete/-fprint, piped (if at all)
    only into head/tail/sort/uniq/wc/grep/cut. `find reports/drafts -name "*.md" -o -name "*.json" | head -30` was
    refused as a credential read because "*.json" could match credentials.json (defense drive 2026-11-22); a name
    listing opens no file. Paths inside a credential store are still refused by the path checks."""
    # (?:^|\s)-exec, not \b-exec: a space before "-" is no word boundary, so -exec ... {} + slipped through
    if re.search(r"[;&`<>]|\$\(|(?:^|\s)-(?:exec|execdir|ok|okdir|delete|fprint\w*|fls|printf|files0-from)\b|"
                 r"(?:^|\s)--files0-from\b", flat):
        return False
    segs = [s.strip() for s in flat.split("|")]
    # du too: sizes and names, no file opened ("du -ah ~ | sort -rh | head -5" was refused, batch 5 2026-11-23)
    if not re.match(r"(?:find|ls|tree|du)\b", segs[0]):
        return False
    return all(re.match(r"(?:head|tail|sort|uniq|wc|grep|egrep|cut)\b", s) for s in segs[1:])


def shell_reads_secret(cmd, cwd=None):
    """True when the command reads a credential store or dumps the environment. The TEXT is checked, and so is
    every path the command names after glob/quote/backslash/~ expansion: `cat ~/.config/[b]b-hunt/*.e*`,
    `cat ~/.s*h/id_ed25519` and `xxd ~/.a?s/credentials` named no store literally (QAQC r2)."""
    cmd = str(cmd or "")
    if SHELL_SECRET.search(cmd):
        return True
    flat = re.sub(r"\\(.)", r"\1", cmd).replace('"', "").replace("'", "")
    flat = re.sub(r"\$\{?HOME\}?", os.path.expanduser("~"), flat)
    if flat != cmd and SHELL_SECRET.search(flat):
        return True
    # a names/sizes listing (find/ls/tree/du into head/sort/...) opens no file: walking ~ is not reading ~/.ssh.
    # A credential directory NAMED in it is still refused by the path check below.
    recursive = bool(re.search(r"(^|\s)-[a-zA-Z]*[rR][a-zA-Z]*\b|--recursive|\b(find|tar|rsync|zip|7z|du|tree)\b",
                               flat)) and not _names_only(flat)
    base = cwd or os.getcwd()
    for word in re.findall(r"[^\s|;&<>()`]+", flat):
        word = word.split("=", 1)[-1] if re.match(r"^-{1,2}[\w-]+=", word) else word
        if not ("/" in word or word.startswith(("~", ".")) or any(c in word for c in "*?[")):
            continue
        full = os.path.expanduser(word)
        full = full if os.path.isabs(full) else os.path.join(base, full)   # relative to where the command runs
        cands = [full]
        if any(c in word for c in "*?["):
            import fnmatch
            pat = os.path.basename(word)
            # a pattern that WOULD match a credential file is refused even where none exists yet
            literal = re.sub(r"[*?]|\[[^\]]*\]", "", pat)
            if len(literal) >= 3 and any(fnmatch.fnmatch(n, pat) for n in _SECRET_BASENAMES) \
                    and not _names_only(flat):
                return True
            with contextlib.suppress(Exception):
                cands = glob.glob(full, recursive=False)[:200] or cands
        for c in cands:
            rp = os.path.realpath(c)
            if is_secret_path(rp) or any(rp == d or rp.startswith(d + os.sep)
                                         or (recursive and d.startswith(rp + os.sep))   # grep -r x ~/.config
                                         for d in SECRET_DIRS + EXTRA_SECRET_FILES):
                return True
    return False


# T1.7 (spec SPEC-0security-alignment-20261109): child processes get the environment MINUS every credential-shaped
# name. gnoc_cloud.set_key puts a provider key into os.environ for the live chat (gnoc_cloud.py, `os.environ[env] =
# key`), and every bash call and worker inherited it. Workspace scripts that need a platform token source
# ~/.config/gnoc/secrets.env themselves. idea: 0sec-labs/0 packages/core/src/agent/sanitized-env.ts
# (MIT OR Apache-2.0); reimplemented, no code copied.
CHILD_ENV_DROP = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|CRED|APIKEY|API_KEY|PRIVATE_KEY|_KEY$|COOKIE|"
                            r"SESSION_ID|SESSION_(TOKEN|SECRET|COOKIE)|(^|_)PASS$|(^|_)PAT$|PWD$|^JWT|_JWT$|BEARER|"
                            r"(^|_)AUTH(_TOKEN|_KEY|_HEADER)?$|MNEMONIC|SEED_PHRASE|WEBHOOK|_DSN$|DATABASE_URL|"
                            r"REDIS_URL|MONGO\w*_URL|AMQP_URL|SIGNING_KEY)", re.I)
# (never matched: XAUTHORITY, DBUS_SESSION_BUS_ADDRESS, XDG_SESSION_TYPE, OLDPWD/PWD are needed by GUI programs and
# shells; `PWD$` is guarded below)
CHILD_ENV_SWITCH = "GNOC_CHILD_ENV"   # =passthrough restores the old behaviour (the full environment)
# Names that match the pattern but carry no credential. GNOC_SESSION_KEY is the per-chat SETTINGS identity
# (gnoc_agent.session_file): stripping it would move a child `gnoc ...` command onto another chat's settings file.
CHILD_ENV_KEEP = frozenset({"GNOC_SESSION_KEY"})


def child_env(extra=None, allow=()):
    """os.environ without credential-shaped names (unless named in `allow`), then `extra` applied on top.
    Values are never read or printed here; only names are tested."""
    extra = {k: str(v) for k, v in (extra or {}).items()}
    if str(os.environ.get(CHILD_ENV_SWITCH) or "").strip().lower() == "passthrough":
        return dict(os.environ, **extra)
    keep = set(allow or ()) | CHILD_ENV_KEEP
    env = {k: v for k, v in os.environ.items() if k in keep or k in _SHELL_VARS or not CHILD_ENV_DROP.search(k)}
    env.update(extra)
    return env


_SHELL_VARS = frozenset({"PWD", "OLDPWD"})   # the shell's own working-directory variables, not a password


def private_bin():
    """gnoc's OWN private Python environment's bin folder when gnoc runs inside one (the public install's launcher
    builds ~/.local/share/gnoc-chat/venv and puts it first on PATH), else None (the operator's tree runs on the
    system Python)."""
    import sys
    if sys.prefix != getattr(sys, "base_prefix", sys.prefix):
        return os.path.realpath(os.path.join(sys.prefix, "bin"))
    return None


def user_env(extra=None, allow=()):
    """child_env for a command the agent runs FOR THE USER: their shell, their background processes, their tests,
    linters, type checks and hooks. gnoc's private environment comes off PATH, and VIRTUAL_ENV goes when it is
    gnoc's, so `python3`, `pip` and `pytest` are the user's own. Driving the public build on 2026-11-20,
    `python3 -m pytest -q` in a user's repo found gnoc's venv python, which has no pytest: "No module named
    pytest" on a machine where pytest is installed, and the lead then tried to pip-install it into gnoc."""
    env = child_env(extra, allow)
    pb = private_bin()
    if pb:
        keep = [p for p in str(env.get("PATH") or "").split(os.pathsep) if p and os.path.realpath(p) != pb]
        env["PATH"] = os.pathsep.join(keep) or "/usr/local/bin:/usr/bin:/bin"
        venv = env.get("VIRTUAL_ENV")
        if venv and os.path.realpath(os.path.join(venv, "bin")) == pb:
            env.pop("VIRTUAL_ENV", None)
    # No bytecode cache from the agent's runs. Python trusts a .pyc when the source's mtime (whole seconds) and
    # size match: the agent edits `a - b` to `a + b` (same size) and re-runs the tests inside the same second,
    # and the test run executes the OLD code ("1/1 passed" on code just put back to the buggy line, 2026-11-21).
    # It also stops the agent leaving __pycache__ directories in the user's repo.
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    return env


def child_env_dropped(allow=()):
    """The NAMES child_env would drop right now (for a status line; never the values)."""
    keep = set(allow or ()) | CHILD_ENV_KEEP | _SHELL_VARS
    return sorted(k for k in os.environ if k not in keep and CHILD_ENV_DROP.search(k))


def _register_state_secrets():
    """ORACLE: register the seal and settler VALUES at import (redacted from every tool result)."""
    for f in STATE_SECRET_FILES:
        with contextlib.suppress(OSError):
            with open(f, encoding="utf-8", errors="replace") as fh:
                register_extra(os.path.basename(f).lstrip("."), fh.read())


_register_state_secrets()
