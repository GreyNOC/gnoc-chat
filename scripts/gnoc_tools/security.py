"""Recon, scanning, identities and provisioning tools."""
from gnoc_core.runtime import bind


def t_sast(ctx, path=".", scanners=None):
    (
        OUT_DIR, WS, _inside_ws, _now, _spill, gnoc_sec, json, os, root,
    ) = bind(
        "OUT_DIR", "WS", "_inside_ws", "_now", "_spill", "gnoc_sec", "json", "os", "root",
    )
    p = _inside_ws(str(path or "."))
    if not p or not os.path.exists(p):
        return f"no such path in the active repo: {path} (sast path=. scans the whole working dir)"
    if isinstance(scanners, str):  # 'semgrep' was once iterated as s, e, m, g ...
        scanners = [x.strip() for x in scanners.split(",") if x.strip()]
    which = tuple(scanners) if scanners else ("semgrep", "gitleaks", "npm")
    bad = [s for s in which if s not in ("semgrep", "gitleaks", "npm")]
    if bad:
        return f"bad arguments: unknown scanner(s) {', '.join(bad)}; scanners is a list of semgrep, gitleaks, npm"
    rows, notes = gnoc_sec.sast(p, which)  # each scanner carries its own cap (semgrep 900s, gitleaks 600s, npm 300s)
    out_dir = os.path.join(OUT_DIR, "sast")
    os.makedirs(out_dir, exist_ok=True)
    full = os.path.join(out_dir, f"{_now():%Y%m%d-%H%M%S}.json")
    with open(full, "w") as f:
        json.dump(rows, f, indent=1)
    return _spill(gnoc_sec.sast_text(rows, notes, root()) + f"\nall hits: {os.path.relpath(full, WS)}", "sast")


def t_recon(ctx, domain, crawl=None, program=None):
    (
        _program_gate, gnoc_sec, re, subprocess,
    ) = bind(
        "_program_gate", "gnoc_sec", "re", "subprocess",
    )
    program = program or ctx.program
    if not program:
        return "no active program: call set_program first, or pass program=<handle>"
    # 'https://www.x.com/path' or 'x.com:443' meant the domain x.com / www.x.com
    domain = re.sub(r"^[a-z]+://", "", str(domain or "").strip().lower()).split("/")[0].split(":")[0].rstrip(".")
    if not domain or "." not in domain:
        return "bad arguments: recon needs domain=<an in-scope domain like api.example.com>"
    if crawl and "://" not in str(crawl):
        crawl = "https://" + str(crawl).strip()
    try:  # subfinder / httpx / katana each run under gnoc_sec's 900s cap
        return gnoc_sec.recon(program, lambda u: _program_gate(program, u), domain, crawl)
    except subprocess.TimeoutExpired as e:
        return f"recon TIMED OUT after {e.timeout:.0f}s in {e.cmd[0] if e.cmd else 'a tool'}: re-run on a narrower domain"


def t_js_mine(ctx, url, program=None):
    (
        JS_MINE_DEADLINE_S, WS, _deadline, _first_touch, _learn_paths, _net_fail,
        _note_mined_host, _program_gate, _spill, gnoc_sec, os, target_bytes,
    ) = bind(
        "JS_MINE_DEADLINE_S", "WS", "_deadline", "_first_touch", "_learn_paths",
        "_net_fail", "_note_mined_host", "_program_gate", "_spill", "gnoc_sec", "os",
        "target_bytes",
    )
    program = program or ctx.program
    pol, err = _program_gate(program, url)
    if err:
        return err
    try:  # 15s per bundle inside lib_jsintel; the whole page + bundles walk is capped here
        text = _deadline(lambda: gnoc_sec.js_mine(url, os.path.join(WS, "targets", program, "SCOPE.txt")),
                         JS_MINE_DEADLINE_S, f"js_mine {url[:80]}")
        learned = _learn_paths(program, "", text or "")  # mined routes feed the ghost-path index (2026-10-23)
        _note_mined_host(program, url)   # D89: the directive lists the in-scope hosts not yet mined
        tail = (f"\n[{learned} new route(s) added to targets/{program}/hunts/gnoc/known-paths.txt; http_request "
                "on any of them is a real probe, on an unmined path it is a guess]" if learned else "")
        # the bundle text is the TARGET's own bytes, not a web page: target_bytes fences it AND remembers it for the
        # copy gate (web_bytes only remembered). The tail goes before the spill so a long mine cannot cut it off.
        return _first_touch(ctx, program, url) + _spill(
            target_bytes(url, text or "", ctx) + tail, "jsmine")
    except Exception as e:
        return _net_fail("js_mine", e)


def _note_mined_host(program, url):
    """Append the host to targets/<program>/hunts/gnoc/mined-hosts.txt once (gate-owned, written by code only)."""
    (
        WS, os, re,
    ) = bind(
        "WS", "os", "re",
    )
    host = (re.match(r"^[a-z]+://([^/:?#]+)", str(url or ""), re.I) or [None, ""])[1].lower()
    if not host or not program:
        return
    try:
        fp = os.path.join(WS, "targets", program, "hunts", "gnoc", "mined-hosts.txt")
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        have = set(l.strip().lower() for l in open(fp).read().splitlines()) if os.path.exists(fp) else set()
        if host not in have:
            with open(fp, "a") as f:
                f.write(host + "\n")
    except OSError:
        pass


def t_decode(ctx, text):
    (
        gnoc_sec,
    ) = bind(
        "gnoc_sec",
    )
    if not str(text or "").strip():
        return "bad arguments: decode needs text=<the token or blob to decode>"
    out = gnoc_sec.decode(str(text))
    t = str(text).strip()
    if out.startswith("no known encoding") and t.startswith("eyJ") and t.count(".") < 2:
        # the 9B lead retypes a JWT from a truncated capture line and loses its tail (program-101 2026-10-23)
        out += ("; this looks like a JWT cut short (a JWT has two dots and three parts). Pass the WHOLE token: read "
                "the raw capture file with read_file and copy the complete value, do not retype it from a summary")
    return out


def t_find_symbol(ctx, name, path=None, line=None, action="definition"):
    """name alone: a fast text search for definitions and uses across the repo. name + path + line (where that
    name appears): the language's own resolver (jedi / a language server) answers which definition THAT name
    refers to, or every real reference to it (action=references); a regex cannot tell two `save` methods apart."""
    (
        _inside_ws, _spill, gnoc_code, gnoc_lsp, os, re, root,
    ) = bind(
        "_inside_ws", "_spill", "gnoc_code", "gnoc_lsp", "os", "re", "root",
    )
    name = str(name or "").strip()
    if not re.fullmatch(r"[A-Za-z_$][\w$.]*", name):
        return f"bad arguments: find_symbol needs a bare identifier like launch_dir or Agent.turn, got {name[:60]!r}"
    if path and line:
        p = _inside_ws(str(path))
        if not p or not os.path.isfile(p):
            return f"no such file in the active repo: {path}"
        ok, text = gnoc_lsp.navigate(root(), p, line, name=name, action=action)
        if ok:
            return _spill(text, "symbol")
        return _spill(f"[no precise answer: {text}. Falling back to the text search, which matches the NAME "
                      f"anywhere, not this exact symbol.]\n" + gnoc_code.find_symbol(root(), name), "symbol")
    return _spill(gnoc_code.find_symbol(root(), name), "symbol")  # ripgrep capped at 45s in gnoc_code


def t_repo_map(ctx, sub=""):
    (
        _inside_ws, _rel_home, _spill, gnoc_code, os, root,
    ) = bind(
        "_inside_ws", "_rel_home", "_spill", "gnoc_code", "os", "root",
    )
    sub = str(sub or "").strip().rstrip("/")
    if sub in (".", "./"):
        sub = ""
    if sub and not _inside_ws(sub):
        return f"refused: {sub} is outside the active repo ({_rel_home(root())}); give a subfolder of it"
    if sub and not os.path.isdir(_inside_ws(sub)):
        return f"no such folder {sub} in {_rel_home(root())} (repo_map with no sub shows the whole repo)"
    return _spill(gnoc_code.repo_map(root(), sub), "repomap")


def _scan_gate(ctx, program, url):
    (
        _program_gate, gnoc_scan,
    ) = bind(
        "_program_gate", "gnoc_scan",
    )
    program = program or ctx.program
    pol, err = _program_gate(program, url)
    if err:
        return None, None, err
    bans = gnoc_scan.scanner_ban(program)
    if bans:
        return None, None, (f"refused: {program}'s policy restricts automated scanning, so the scanners are blocked "
                            "here. Lines that triggered it:\n  " + "\n  ".join(bans[:4])
                            + "\nHunt it by hand (probe_matrix / crafted http_request) instead.")
    return program, pol, None


def t_scan(ctx, tool, url, program=None, severity="medium,high,critical", tags=None, wordlist="common",
           extensions="", param=None, data=None, method=None, as_identity=None):
    (
        _first_touch, _scan_gate, _spill, gnoc_ident, gnoc_scan,
    ) = bind(
        "_first_touch", "_scan_gate", "_spill", "gnoc_ident", "gnoc_scan",
    )
    program, pol, err = _scan_gate(ctx, program, url)
    if err:
        return err
    cookie = None
    if as_identity:
        try:
            cookie = gnoc_ident.headers_for(program, [as_identity])[as_identity].get("Cookie")
            if cookie:
                cookie = "Cookie: " + cookie
        except KeyError as e:
            return str(e).strip("'\"") + " (identities action=list shows the saved names)"
    try:  # every scanner runs under gnoc_scan's wall-clock cap and says "stopped at the Ns cap" when it is hit
        if tool == "nuclei":
            out = gnoc_scan.nuclei(program, pol, url, severity, tags)
        elif tool == "ffuf":
            out = gnoc_scan.ffuf(program, pol, url, wordlist, extensions)
        elif tool == "sqlmap":
            out = gnoc_scan.sqlmap(program, pol, url, param, data, method, cookie)
        else:
            return "tool is nuclei, ffuf or sqlmap"
    except Exception as e:
        return f"{tool} failed: {type(e).__name__}: {str(e)[:200]}"
    return _first_touch(ctx, program, url) + _spill(out, f"scan-{tool}")


def t_malware(ctx, path, action="analyze", rules_path=None, rules_string=None, start=None,
              length=64, arch=None, min_len=6, encoding="both"):
    (
        _is_secret, _rel_home, _spill, gnoc_malware, os, root,
    ) = bind(
        "_is_secret", "_rel_home", "_spill", "gnoc_malware", "os", "root",
    )
    p = os.path.expanduser(str(path or ""))
    if not os.path.isabs(p):
        p = os.path.join(root(), p)
    p = os.path.realpath(p)
    # samples may live anywhere on disk, but strings/yara/disassemble print a file's bytes: never a credential.
    # This runs BEFORE the existence check: "not found" for a name under ~/.ssh told the model whether a
    # key file existed there (review 2026-10-22).
    home = os.path.expanduser("~")
    for q in [p] + ([os.path.realpath(os.path.expanduser(str(rules_path)))] if rules_path else []):
        if _is_secret(q) or any(q.startswith(os.path.join(home, s) + os.sep)
                                for s in (".ssh", ".gnupg", ".config/gnoc", ".aws", ".claude")):
            return "refused: that is a credential store or secrets file, not a sample; its bytes never enter the chat"
    if not os.path.exists(p):
        return f"not found: {path} (give the sample's absolute path, or a path relative to {_rel_home(root())})"
    if os.path.isdir(p):
        return f"{path} is a directory: malware analyzes one file (list_dir it and pick the sample)"
    try:
        if action == "analyze":
            return _spill(gnoc_malware.analyze(p), "malware")
        elif action == "hashes":
            return gnoc_malware.hashes(p)
        elif action == "pe":
            return _spill(gnoc_malware.pe_info(p), "pe")
        elif action == "elf":
            return _spill(gnoc_malware.elf_info(p), "elf")
        elif action == "entropy":
            return _spill(gnoc_malware.entropy_map(p), "entropy")
        elif action == "strings":
            return _spill(gnoc_malware.strings_extract(p, min_len=min_len, encoding=encoding), "strings")
        elif action == "yara":
            return _spill(gnoc_malware.yara_scan(p, rules_path, rules_string), "yara")
        elif action == "disassemble":
            return _spill(gnoc_malware.disassemble(p, start, length, arch), "disasm")
        elif action == "sandbox":
            return gnoc_malware.sandbox_indicators(p)
        else:
            return "action is analyze, hashes, pe, elf, entropy, strings, yara, disassemble or sandbox"
    except Exception as e:
        return f"{action} failed: {type(e).__name__}: {str(e)[:200]}"


def t_liveness(ctx, draft_dir):
    """Re-fire the draft's terminal request from its own capture and record whether the sink is still live, as
    evidence/liveness-<date>.json in the draft dir. The agent's own lesson (2026-10-22): a draft is unverified
    until its SINK is re-fired on the day you file - app.example.com hardened a surface between validation and filing.
    scripts/reports.sh ready refuses a draft with no *liveness* file under 24 h old (T-241), and nothing in gnoc
    chat produced one, so every gnoc-built draft died there. The request goes through the same scope, policy,
    rate and secret gates as http_request."""
    (
        WS, _inside_ws, _now, _program_gate, _send, gnoc_hunt, gnoc_report, json, os,
    ) = bind(
        "WS", "_inside_ws", "_now", "_program_gate", "_send", "gnoc_hunt", "gnoc_report",
        "json", "os",
    )
    p = _inside_ws(str(draft_dir or ""))
    if not p or not os.path.isfile(os.path.join(p, "report.md")):
        return f"no report.md under {draft_dir}: pass the draft DIRECTORY (reports/drafts/<program>/<slug>)"
    base = os.path.join(WS, "reports", "drafts")
    if not p.startswith(base + os.sep):
        return f"refused: {draft_dir} is not under reports/drafts/"
    program = os.path.relpath(p, base).split(os.sep)[0]
    complete = [c for _, c in gnoc_hunt.chains(program, 10) if all(e["status"] == "proven" for e in c)]
    if not complete:
        return "refused: no fully proven chain in the ledger to re-fire (the draft's chain is its evidence)"
    chain = complete[0]
    term = chain[-1]
    j, _ = gnoc_report._load_raw(term.get("evidence") or "")
    if not j:
        return f"refused: the terminal edge {term['id']} has no raw capture to replay ({term.get('evidence')})"
    req = j.get("request") or {}
    url, method = req.get("url") or "", (req.get("method") or "GET").upper()
    pol, err = _program_gate(program, url)
    if err:
        return err
    try:
        r, rel = _send(program, pol, url, method, dict(req.get("headers") or {}), req.get("body"))
    except Exception as e:  # noqa: BLE001 - a dead host is itself the answer
        r, rel = {"status": None, "body": "", "error": f"{type(e).__name__}: {e}"}, ""
    need = term.get("must_contain") or ""
    body = r.get("body") or ""
    live = bool(need) and need in (body if isinstance(body, str) else json.dumps(body))
    stamp = f"{_now():%Y%m%d-%H%M%S-%f}"  # two re-fires in one second must not overwrite each other
    evdir = os.path.join(p, "evidence")
    os.makedirs(evdir, exist_ok=True)
    out = os.path.join(evdir, f"liveness-{stamp}.json")
    row = {"ts": _now().isoformat(), "program": program, "edge": term["id"], "url": url, "method": method,
           "status": r.get("status"), "must_contain": need, "live": live, "raw": rel,
           "error": r.get("error"), "body_head": (body if isinstance(body, str) else json.dumps(body))[:600]}
    with open(out, "w") as f:
        json.dump(row, f, indent=1, default=str)
    rel_out = os.path.relpath(out, WS)
    if live:
        return (f"LIVE: {method} {url} -> HTTP {r.get('status')}, the terminal bytes {need[:60]!r} are still in the "
                f"response. Recorded {rel_out}; reports.sh ready accepts it for 24 h.")
    return (f"NOT LIVE: {method} {url} -> HTTP {r.get('status')}{' (' + r['error'] + ')' if r.get('error') else ''}; "
            f"the terminal bytes {need[:60]!r} are gone. Recorded {rel_out}. The sink was hardened or moved: do NOT "
            "say READY; re-prove the chain, or record the draft as remediated (HELD-REASON.md with the receipt).")


def t_pay_check(ctx, program=None, host=None, refresh=False):
    """Can this asset pay, and can we file on this program? Facts from disk (the scope's bounty rows, the cached
    team flags, our own closed record); refresh=True re-reads the platform's team flags (token-free)."""
    (
        gnoc_pay, resolve_program,
    ) = bind(
        "gnoc_pay", "resolve_program",
    )
    program = (resolve_program(program) if program else None) or ctx.program
    if not program:
        return "no active program: set_program first, or pass program=<handle>"
    if isinstance(refresh, str):
        refresh = refresh.strip().lower() in ("true", "1", "yes")
    if refresh:
        gnoc_pay.h1_team(program, refresh=True)
    out = [gnoc_pay.summary(program, offline=not refresh)]
    if host:
        v, why, row = gnoc_pay.payability(program, host)
        out.append(f"{host}: {gnoc_pay.VERDICT_WORD.get(v, v)} - {why}")
        if row and row.get("max"):
            out.append(f"  max severity on that row: {row['max']}")
    sig, n, states = gnoc_pay.own_signal()
    if sig is not None:
        out.append(f"OUR SIGNAL: {sig} over {n} scored ({', '.join(f'{k} {v}' for k, v in sorted(states.items()))}; "
                   f"pull {gnoc_pay.SIGNAL_INFO.get('day')}); {gnoc_pay.recovery(1.0)} resolved closure(s) reach 1.0, "
                   f"{gnoc_pay.recovery(3.0)} reach 3.0")
    return "\n".join(out)


def t_dedup(ctx, terms, program=None):
    (
        gnoc_dedup,
    ) = bind(
        "gnoc_dedup",
    )
    program = program or ctx.program
    if not program:
        return "no active program: dedup checks one program's verdicts - call set_program first, or pass program="
    return gnoc_dedup.check(program, terms)[1]


def _identity_arms(program, identities):
    """probe_matrix identity arms. None -> every saved identity of the program; a list or comma string of names ->
    those; a dict name -> headers (inline) is still accepted. Raises KeyError for an unknown name."""
    (
        gnoc_ident, json,
    ) = bind(
        "gnoc_ident", "json",
    )
    if isinstance(identities, str):
        try:
            identities = json.loads(identities)
        except ValueError:
            identities = [x.strip() for x in identities.split(",") if x.strip()]
    if identities is None:
        return {n: dict(r["headers"]) for n, r in gnoc_ident.load(program).items()}
    if isinstance(identities, list):
        return gnoc_ident.headers_for(program, [str(x) for x in identities])
    return identities if isinstance(identities, dict) else {}


def _site_of(host):
    """The registrable-ish site: the last two labels. app.example.com and app.example.com are different SITES;
    app.example.com and app.example.com are the same one."""
    parts = [p for p in str(host or "").lower().split(":")[0].split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else ".".join(parts)


def _with_identity(program, headers, as_identity, url=None):
    (
        _site_of, gnoc_ident, re,
    ) = bind(
        "_site_of", "gnoc_ident", "re",
    )
    h = dict(headers or {})
    if as_identity:
        rec = (gnoc_ident.load(program) or {}).get(as_identity) or {}
        origin = rec.get("origin") or ""
        if url and origin:
            m = re.search(r"https?://([^/\s]+)", str(url))
            target = m.group(1) if m else ""
            if target and _site_of(target) != _site_of(origin):
                raise PermissionError(
                    f"refused: identity {as_identity} was minted on {origin} and this request goes to "
                    f"{target}, a different site. A session does not carry across brands or TLDs: it can "
                    "only 403, and sending one site's cookies to another is not something to do by "
                    "accident. Probe this host UNAUTHENTICATED, or mint an identity ON it "
                    f"(log in at {_site_of(target)} and identities action=save).")
        h.update(gnoc_ident.headers_for(program, [as_identity])[as_identity])
    return h


def t_identities(ctx, action="list", name=None, headers=None, from_raw=None, token_field=None, note="",
                 program=None):
    (
        _identity_from_storage_state, _inside_ws, _login_shape, _provision_budget,
        _rel, gnoc_ident, json, os,
    ) = bind(
        "_identity_from_storage_state", "_inside_ws", "_login_shape", "_provision_budget",
        "_rel", "gnoc_ident", "json", "os",
    )
    program = program or ctx.program
    if not program:
        return "no active program: call set_program first (identities are kept per program)"
    if action == "list":
        out = gnoc_ident.listing(program)
        if out.startswith("no identities saved"):
            # cycle 5: identities said "MAKE them: provision" while provision was refused by the signup cap, and the
            # lead alternated the two calls. The hint carries the cap state so the loop never forms.
            why = _provision_budget(program, "pair", "A", "A,B", record=False)
            if why:
                out += ("\n  provision is NOT available right now: " + why[:220] + "\n  Hunt the unauth surface "
                        "meanwhile (88% of shipped findings needed no account); say NEEDS: only if the goal cannot "
                        "move without an account.")
        return out
    if action in ("save", "remove", "login") and not str(name or "").strip():
        return f"bad arguments: identities action={action} needs name=<A, B ...> (action=list shows the saved names)"
    if action == "remove":
        return gnoc_ident.remove(program, name)
    if action == "login":   # F7: LOGIN.py logs in IN CODE; only save()'s line (header NAMES) comes back
        return gnoc_ident.login(program, str(name).strip())
    if action == "save":
        if not headers and not from_raw:
            return ("bad arguments: identities action=save needs from_raw=<raw capture of the login response> or "
                    "headers={\"Cookie\": \"...\"}")
        src = ""
        if from_raw:
            fr = str(from_raw).strip()
            if fr.startswith(("{", "[", "eyJ")) or "\n" in fr or len(fr) > 400:
                # the 9B lead pasted a mail.tm inbox JSON and then its JWT here 12 times (program-101 2026-10-23)
                return ("bad arguments: from_raw must be the PATH of a raw capture written by http_request "
                        "(targets/<program>/hunts/.../raw/<id>.json), not the token or JSON itself. A token copied "
                        "out of an inbox file (mail.tm, roles ROLE_USER) is the MAILBOX session, not a target "
                        "session: a target identity exists only after a LOGIN response from an in-scope host, or "
                        "after provision action=pair/register minted the account.")
            p = _inside_ws(fr)
            if not p or not os.path.isfile(p):
                return (f"no raw capture at {fr} (from_raw is a file path under targets/<program>/hunts/.../raw/; "
                        "list_dir the raw folder to find the login response capture)")
            state_reply = _identity_from_storage_state(program, name, p, note)
            if state_reply is not None:
                return state_reply
            try:
                headers = dict(headers or {}, **gnoc_ident.from_raw(p, token_field))
            except ValueError as e:
                return f"bad arguments: {e}"
            shape = _login_shape(p)
            if shape:
                return "refused: " + shape
            src = _rel(p)
        if isinstance(headers, str):
            try:
                headers = json.loads(headers)
            except ValueError:
                return "headers must be an object like {\"Cookie\": \"...\"}"
        return gnoc_ident.save(program, name, headers, note, src)
    return "action is list, save, remove or login"


def _provision_budget(program, action, tag, tags, record=True):
    """Why a fresh browser signup must NOT run now, or '' when it may. Two receipts (program-101 2026-10-23): the lead
    re-ran `provision action=pair` twice in 40 minutes while A and B already sat in targets/<p>/accounts/ with
    status submitted and an inbox token (the verify code was the missing step, not another signup); and every
    attempt leaves the shared residential egress, which the first worker measured as rate-gated after ~6 tries."""
    (
        PROVISION_MAX_SIGNUPS, PROVISION_WINDOW_S, WS, json, os, re, time,
    ) = bind(
        "PROVISION_MAX_SIGNUPS", "PROVISION_WINDOW_S", "WS", "json", "os", "re", "time",
    )
    want = [x.strip() for x in str(tags or "A,B").split(",")] if action == "pair" else [tag]
    want = [re.sub(r"[^A-Za-z0-9_-]", "", x)[:24] or "A" for x in want if x]
    acc_dir = os.path.join(WS, "targets", program, "accounts")
    pending = []
    for tg in want:
        try:
            with open(os.path.join(acc_dir, f"{tg}.json")) as f:
                a = json.load(f) or {}
        except (OSError, ValueError):
            continue
        st = a.get("status") or ("submitted" if a.get("email") and not a.get("verify_status") else None)
        if st == "submitted" or (a.get("email") and a.get("_inbox_token") and not a.get("verify_status")):
            pending.append(tg)
    if pending:
        return (f"refused: account(s) {', '.join(pending)} already exist for {program} with the signup SUBMITTED "
                f"and the verify step still owed (targets/{program}/accounts/<tag>.json). Another signup does not "
                "finish the first one: run provision action=wait token=<the _inbox_token in that file> to read the "
                "verify link or code, follow it with http_request, then save the LOGIN response as the identity. "
                "If the inbox stays empty the wall is the risk gate: say NEEDS: once and hunt unauth.")
    ledger = os.path.join(WS, "targets", program, "accounts", "signups.jsonl")
    now = time.time()
    recent = 0
    try:
        with open(ledger) as f:
            for ln in f:
                try:
                    if now - float(json.loads(ln).get("ts", 0)) < PROVISION_WINDOW_S:
                        recent += 1
                except (ValueError, TypeError):
                    pass
    except OSError:
        pass
    n = len(want)
    if recent + n > PROVISION_MAX_SIGNUPS:
        return (f"refused: {recent} browser signup(s) for {program} in the last {PROVISION_WINDOW_S // 3600} h and "
                f"this call adds {n}; the cap is {PROVISION_MAX_SIGNUPS} (a shared residential egress gets flagged "
                "after a handful). Finish the submitted accounts (action=wait), or hunt unauth and say NEEDS: for a "
                "hand signup.")
    if not record:   # a peek (identities action=list) must not spend the cap it reports
        return ""
    try:
        os.makedirs(os.path.dirname(ledger), exist_ok=True)
        with open(ledger, "a") as f:
            for tg in want:
                f.write(json.dumps({"ts": now, "action": action, "tag": tg}) + "\n")
    except OSError:
        pass
    return ""


def _cookie_in_scope(domain, program):
    """A cookie belongs to the identity only if its domain is a host the program gate would let us probe."""
    (
        WS,
    ) = bind(
        "WS",
    )
    dom = str(domain or "").lstrip(".").lower()
    if not dom:
        return False
    try:
        from bbtools import lib_scope
        return bool(lib_scope.program_allows(dom, program, WS)[0])
    except Exception:  # noqa: BLE001
        return False


def _identity_from_state(program, tag, state_path, note):
    """Cookie header from a lib_browser storage_state.json, restricted to cookies on in-scope hosts, saved as
    identity <tag>. Off-scope cookies (the CDN, an analytics host) never enter the identity store."""
    (
        WS, _SESSION_COOKIE, _cookie_in_scope, _rel, gnoc_ident, json, os,
    ) = bind(
        "WS", "_SESSION_COOKIE", "_cookie_in_scope", "_rel", "gnoc_ident", "json", "os",
    )
    p = state_path if os.path.isabs(state_path) else os.path.join(WS, state_path)
    try:
        data = json.load(open(p))
    except (OSError, ValueError) as e:
        return f"identity not saved: state file unreadable ({e})"
    pairs, session_like = [], []
    for c in data.get("cookies") or []:
        if _cookie_in_scope(c.get("domain"), program) and c.get("name") and c.get("value") is not None:
            pairs.append(f"{c['name']}={c['value']}")
            if c.get("httpOnly") or _SESSION_COOKIE.search(str(c.get("name"))):
                session_like.append(str(c["name"]))
    if not pairs:
        return ("identity not saved: no in-scope cookies in the state file; log in with http_request and then "
                "identities action=save from_raw=<that raw capture>")
    if not session_like:
        # the chat's provision pair on program-101 returned status=submitted and saved A and B whose jars held only
        # region / language / currency / _nano_fp / timezone / img_sup: a VISITOR, not an account (2026-10-23)
        names = ", ".join(p.split("=", 1)[0] for p in pairs)[:160]
        return (f"identity not saved: the browser jar holds only preference cookies ({names}), no session cookie "
                "(none HttpOnly, none named like a session). The signup did not log in: the verify step is still "
                "owed (check the inbox with provision action=wait token=<inbox token>, or the account needs a "
                "code/captcha the auto-fill could not pass). An identity without a session is a fake authed arm.")
    return gnoc_ident.save(program, tag, {"Cookie": "; ".join(pairs)}, note or "provisioned", _rel(p))


def _provision_receipt(program, action, signup_url, accounts, tag="A"):
    """Append one row per account attempt to targets/<program>/accounts/provision-log.jsonl. D104: the wall a
    signup hit (captcha, sms, a verify mail that never came, an error) must be a file, not a collapsed chat line.
    Never the address, never the password: the mailbox DOMAIN and the statuses."""
    (
        WS, _now, json, os,
    ) = bind(
        "WS", "_now", "json", "os",
    )
    if not program:
        return
    rows = []
    for a in accounts or []:
        if not isinstance(a, dict):
            continue
        email = str(a.get("email") or "")
        rows.append({"ts": _now().isoformat(timespec="seconds"), "action": action, "tag": a.get("tag") or tag,
                     "status": a.get("status"), "verify_status": a.get("verify_status"), "captcha": a.get("captcha"),
                     "note": str(a.get("note") or "")[:300], "signup_url": str(signup_url or "")[:200],
                     "mail_domain": email.split("@", 1)[1] if "@" in email else "",
                     "state_saved": bool(a.get("state_path"))})
    if not rows:
        return
    try:
        fp = os.path.join(WS, "targets", program, "accounts", "provision-log.jsonl")
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        with open(fp, "a") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
    except OSError:
        pass


def t_provision(ctx, action="register", program=None, signup_url=None, tag="A", tags=None, overrides=None,
                verify="auto", headless=True, role_urls=None, token=None, seconds=150, extra=None, as_form=False,
                email_field="email", password_field="password", note="", proxy=None):
    (
        ORCH, WS, _PROVISION_RUNNER, _PROVISION_TIMEOUT, _activity,
        _identity_from_state, _program_gate, _provision_budget, _provision_receipt,
        _read, _rel, contextlib, gnoc_ident, gnoc_secrets, json, os, re, socket,
        subprocess, sys,
    ) = bind(
        "ORCH", "WS", "_PROVISION_RUNNER", "_PROVISION_TIMEOUT", "_activity",
        "_identity_from_state", "_program_gate", "_provision_budget", "_provision_receipt",
        "_read", "_rel", "contextlib", "gnoc_ident", "gnoc_secrets", "json", "os", "re",
        "socket", "subprocess", "sys",
    )
    program = program or ctx.program
    if not program:
        return "no active program: call set_program first (accounts are kept per program)"
    action = str(action or "register").strip().lower()
    tag = re.sub(r"[^A-Za-z0-9_-]", "", str(tag or "A"))[:24] or "A"
    # Egress matters more than the captcha on a reputation-scored signup (T-26c): program-101 answered 429 "System busy" to
    # a CORRECT code from every datacenter client and lets the same flow through from a residential IP. Default to
    # the phone egress (scripts/PHONE-EGRESS.md, socks5h://127.0.0.1:1081) when it is up, unless told otherwise.
    if proxy is None:
        proxy = os.environ.get("GNOC_PROVISION_PROXY") or os.environ.get("PHONE_SOCKS") or ""
        if not proxy and not os.path.exists(os.path.join(ORCH, "phone-egress.off")):
            try:
                with socket.create_connection(("127.0.0.1", 1081), timeout=0.5):
                    proxy = "socks5h://127.0.0.1:1081"
            except OSError:
                proxy = ""
    proxy = str(proxy or "").strip() or None
    if proxy and proxy.lower() in ("none", "direct", "off"):
        proxy = None
    if action == "list":
        md = os.path.join(WS, "targets", program, "ACCOUNTS.md")
        body = (_read(md) or "").strip()
        acc_dir = os.path.join(WS, "targets", program, "accounts")
        files = sorted(os.listdir(acc_dir)) if os.path.isdir(acc_dir) else []
        return ((body[:3000] if body else f"no targets/{program}/ACCOUNTS.md yet")
                + (f"\naccount files: {', '.join(files)}" if files else "")
                + "\n" + gnoc_ident.listing(program))
    if isinstance(headless, str):
        headless = headless.lower() not in ("0", "false", "no")
    req = {"action": action, "program": program, "tag": tag, "verify": verify or "auto", "headless": bool(headless),
           "scope_file": os.path.join(WS, "targets", program, "SCOPE.txt"), "note": note, "proxy": proxy}
    if action in ("register", "pair"):
        url = str(signup_url or "").strip()
        if not url:
            return f"bad arguments: provision action={action} needs signup_url=<the signup page on an in-scope host>"
        urls = [url] + [str(u).strip() for u in (role_urls or []) if str(u).strip()]
        for u in urls:
            _pol, err = _program_gate(program, u)
            if err:
                return err
        req["signup_url"] = url
        if isinstance(overrides, str):
            try:
                overrides = json.loads(overrides)
            except ValueError:
                return "overrides must be an object like {\"field name or selector\": \"value\"}"
        req["overrides"] = overrides or None
        if action == "pair":
            t = tags if isinstance(tags, list) else [x.strip() for x in str(tags or "A,B").split(",") if x.strip()]
            if len(t) != 2:
                return "bad arguments: pair needs tags=A,B (exactly two names)"
            req["tags"] = [re.sub(r"[^A-Za-z0-9_-]", "", x)[:24] or "A" for x in t]
            req["role_urls"] = urls[1:3] if len(urls) >= 3 else None
        # spent LAST: a call refused for scope or bad tags used to burn signups (QAQC 2026-11-19)
        budget = _provision_budget(program, action, tag, ",".join(req["tags"]) if action == "pair" else tags)
        if budget:
            return budget
    elif action == "simple":
        url = str(signup_url or "").strip()
        if not url:
            return "bad arguments: provision action=simple needs signup_url=<the POST register endpoint>"
        _pol, err = _program_gate(program, url)
        if err:
            return err
        if isinstance(extra, str):
            try:
                extra = json.loads(extra)
            except ValueError:
                return "extra must be an object of the extra form fields the register endpoint requires"
        req.update({"register_url": url, "extra": extra or None, "as_form": bool(as_form),
                    "email_field": email_field or "email", "password_field": password_field or "password"})
    elif action == "wait":
        token = str(token or "").strip()
        if not token.startswith("eyJ"):
            # launch #19 called wait with token='inbox_token' (the placeholder from the hint) and burned 150 s on a
            # token mail.tm could never honour; the real one is in the saved account file, so resolve it from there
            tagf = re.sub(r"[^A-Za-z0-9_-]", "", token or tag)[:24] or tag
            accf = os.path.join(WS, "targets", program, "accounts", f"{tagf}.json")
            saved = {}
            if os.path.isfile(accf):
                try:
                    with open(accf) as fh:
                        saved = json.load(fh)
                except (OSError, ValueError):
                    saved = {}
            if not saved.get("_inbox_token"):
                return (f"bad arguments: provision action=wait needs token=<the mail.tm token, starts with eyJ>; "
                        f"{token!r} is not one and targets/{program}/accounts/{tagf}.json carries no _inbox_token. "
                        "Pass tag=<A|B> for a saved account, or the token from action=inbox.")
            token, tag = str(saved["_inbox_token"]), tagf
        req.update({"token": token, "seconds": max(5, min(int(seconds or 150), 360))})
    elif action != "inbox":
        return "action is inbox, wait, register, pair, simple or list"
    env = gnoc_secrets.child_env({"HUNT_TARGET": program})   # T1.7
    try:
        r = subprocess.run([sys.executable, _PROVISION_RUNNER], input=json.dumps(req), capture_output=True,
                           text=True, cwd=WS, env=env, timeout=_PROVISION_TIMEOUT.get(action, 600))
    except subprocess.TimeoutExpired:
        return (f"provision {action} timed out; a bot wall or a verify mail that never came. Check "
                f"targets/{program}/ACCOUNTS.md for a partial account, then say NEEDS: with the exact wall (T-163).")
    out = (r.stdout or "").strip().splitlines()
    res = None
    for ln in reversed(out):
        if ln.startswith("{"):
            with contextlib.suppress(ValueError):
                res = json.loads(ln)
                break
    if not isinstance(res, dict):
        tail = ((r.stderr or "") + "\n" + (r.stdout or "")).strip()[-600:]
        return f"provision {action} produced no result (exit {r.returncode}): {tail}"
    _activity({"ev": "tool", "phase": "note", "name": "provision", "arg": action, "why": str(res.get("status"))[:60]})
    accounts = res.get("accounts") if action == "pair" else ([res] if action in ("register", "simple") else [])
    _provision_receipt(program, action, signup_url, accounts or [], tag)   # D104
    lines = []
    for a in accounts or []:
        st, t = a.get("status"), a.get("tag") or tag
        line = f"{t}: status={st} email={a.get('email') or '-'} verify={a.get('verify_status') or '-'}"
        if a.get("state_path"):
            line += f" state={_rel(a['state_path'])}"
            if st in ("ok", "submitted"):
                line += "\n   " + _identity_from_state(program, t, a["state_path"], note)
        if a.get("captcha"):
            line += f" captcha={a['captcha']}"
        if a.get("note"):
            line += f"\n   note: {str(a['note'])[:300]}"
        if st in ("needs-captcha", "needs-sms"):
            line += ("\n   a wall, not a dead end (T-163): try the other storefront/locale or role signup, a different "
                     "egress, or the email path; if it is truly phone/KYC-only say ONE NEEDS: line and keep hunting unauth")
        lines.append(line)
    if action == "inbox":
        return (f"inbox {res.get('address')} (token for action=wait: {res.get('token')}); stored as "
                f"targets/{program}/accounts/inbox-{tag}.json. Use it as the signup email, then action=wait token=...")
    if action == "wait":
        msgs = res.get("messages") or []
        if not msgs:
            return f"no mail arrived in {req['seconds']}s (T-23: the signup token may have expired meanwhile; re-send)"
        return "\n".join(f"from {m.get('from')} subject {m.get('subject')}\n  links: {m.get('links')}\n  codes: "
                         f"{m.get('codes')}" for m in msgs[:5])
    # drive cycle 4 (2026-10-26 00:00Z): two "pair" calls each answered "passwords are in <tag>.json" while no account
    # file and no identity existed; the lead then tried as_identity probes and the signup cap was spent. The head
    # line now states the saved count first; the password sentence only when an account file exists.
    tags_wanted = [a.get("tag") or tag for a in (accounts or [])] or [tag]
    try:
        have = gnoc_ident.load(program)
    except Exception:  # noqa: BLE001
        have = {}
    usable = [t for t in tags_wanted if t in have]
    files = [t for t in tags_wanted if os.path.isfile(os.path.join(WS, "targets", program, "accounts", f"{t}.json"))]
    head = f"provision {action} for {program}: {len(usable)} of {len(tags_wanted)} identities SAVED"
    head += (f" (usable as as_identity={', '.join(usable)})" if usable else
             " - NOT usable: no session identity was saved, do not probe as_identity; the per-tag lines say why")
    if files:
        head += f". Passwords are in targets/{program}/accounts/<tag>.json and the ACCOUNTS.md row, never in this chat."
    return head + "\n" + ("\n".join(lines) if lines else json.dumps(res)[:800])


def _login_shape(raw_path):
    """A reason the capture is NOT a login exchange, or '' when it is. An anonymous 403 on /api/admin/config carried
    a Set-Cookie (api_uid=...) and the lead saved it as 'identity A', then probed 'as A' for three hours with a
    visitor cookie it mistook for an account (program-101 2026-10-23). A session comes from a login-shaped request (a
    write to an auth route) or a response that names the account; everything else is a visitor jar."""
    (
        _AUTH_PATH, _ID_MARKER, json, re,
    ) = bind(
        "_AUTH_PATH", "_ID_MARKER", "json", "re",
    )
    try:
        d = json.load(open(raw_path))
    except (OSError, ValueError):
        return ""  # from_raw already validated the shape; nothing more to say
    req, resp = d.get("request") or {}, d.get("response") or {}
    if not req:
        return ""  # a capture with no request block (older format) cannot be judged; from_raw validated the rest
    method = str(req.get("method") or "GET").upper()
    url = str(req.get("url") or "")
    path = re.sub(r"^https?://[^/]+", "", url)
    status = resp.get("status")
    body = str(resp.get("body") or "")[:200_000]
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = 0
    if status >= 400:
        return (f"that capture is a {status} response ({method} {path[:60]}); a refused request cannot establish a "
                "session. Its Set-Cookie is a visitor cookie, not an account. Log in first (POST the login route, "
                "or provision action=pair) and save THAT response.")
    if method in ("POST", "PUT", "PATCH") and _AUTH_PATH.search(path):
        return ""
    if _ID_MARKER.search(body):
        return ""
    return (f"that capture is an anonymous {method} {path[:60]} (no auth route written, no account field in the "
            "body); its Set-Cookie is a visitor cookie, not a login. A real identity needs the LOGIN response "
            "(POST /login, /auth, /session ...) or a response whose body names the account (user_id, email, "
            "nickname). Use provision action=pair to mint one, or headers={...} only for a session you verified.")


def _identity_from_storage_state(program, name, path, note):
    """A Playwright storage_state.json (top-level "cookies" list) is a browser jar, not a capture. It becomes an
    identity ONLY when provisioning verified the account behind it (targets/<p>/accounts/<tag>.json with status
    ok or submitted); the program-101 lead tried to save hunts/provision-20261023/A.state.json, the jar of a signup that
    never completed (2026-10-23). Returns None when the file is not a storage state."""
    (
        WS, _identity_from_state, _rel, json, os,
    ) = bind(
        "WS", "_identity_from_state", "_rel", "json", "os",
    )
    try:
        with open(path) as f:
            d = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(d, dict) or not isinstance(d.get("cookies"), list) or "response" in d:
        return None
    acc = os.path.join(WS, "targets", program, "accounts", f"{name}.json")
    status = None
    try:
        with open(acc) as f:
            status = (json.load(f) or {}).get("status")
    except (OSError, ValueError):
        pass
    if status not in ("ok", "submitted"):
        return (f"refused: {_rel(path)} is a browser storage state, and no VERIFIED account {name} exists for "
                f"{program} (targets/{program}/accounts/{name}.json missing or status {status!r}). A jar from a signup "
                "that never completed is an anonymous visitor, not an identity. Finish the signup (provision "
                "action=pair / register) or log in and save the LOGIN response capture.")
    return _identity_from_state(program, name, path, note or f"storage state of verified account {name}")


def _wall_told(ctx, program, url, msg):
    """The wall refusal, or, from the third refusal of the same route in one turn, a one-line closure. D100 (cycle
    28, 11:41Z): six refusals on one walled route in a turn, each a lead-model call, none a probe."""
    (
        WALL_TOLD_PER_TURN, gnoc_hunt,
    ) = bind(
        "WALL_TOLD_PER_TURN", "gnoc_hunt",
    )
    try:
        rk = gnoc_hunt.route_key(url)
    except Exception:  # noqa: BLE001
        rk = str(url)
    st = getattr(ctx, "s", None)
    if not isinstance(st, dict):
        return msg
    key = f"{st.get('_turn_user') or ''}|{program}|{rk}"
    d = st.setdefault("_wall_refusals", {})
    d[key] = int(d.get(key) or 0) + 1
    if d[key] > WALL_TOLD_PER_TURN:
        return (f"route wall: {rk} was refused {d[key]} times this turn and is closed for the rest of the turn, any "
                "method or body. Fire a route that answered (KNOWN ROUTES, ADMISSIBLE ROUTES) or a different host; "
                "if no route is left, park the hypothesis (status=unfired) and say what is walled.")
    return msg


def _identity_premise_refusal(program, hypothesis, headers, named=None):
    """F4: the refusal when the hypothesis premise needs a session and this request carries none, else ""."""
    (
        _IDENTITY_PREMISE, gnoc_hunt,
    ) = bind(
        "_IDENTITY_PREMISE", "gnoc_hunt",
    )
    if not hypothesis or named:
        return ""
    hk = {str(k).lower() for k, v in (headers or {}).items() if str(v).strip()}
    if hk & {"cookie", "authorization"}:
        return ""
    try:
        h = gnoc_hunt._find_hyp(gnoc_hunt.load(program).get("hypotheses", []), hypothesis) or {}
    except Exception:  # noqa: BLE001 - no ledger, no premise to check
        return ""
    req = h.get("requires")
    premise = " ".join(str(x) for x in (h.get("assumption"), h.get("violation"),
                                        " ".join(req) if isinstance(req, list) else req) if x)
    m = _IDENTITY_PREMISE.search(premise)
    if not m:
        return ""
    return (f"refused (not sent, not counted): {hypothesis}'s premise names {m.group(0)!r} but this request carries no "
            "Cookie, no Authorization and no identity. This hypothesis needs an identity: identities action=list / "
            "login / save, then as_identity='<name>' (probe_matrix: identities='<name>'); as_identity='anon' for a "
            "deliberate unauthenticated arm.")


def _id_seen_on_disk(program, value, timeout=8):
    """True when `value` occurs in any file under targets/<program>/ (notes, captures), False when it does not,
    None when the search could not finish. Cached per (program, value)."""
    (
        WS, _SEEN_ID_CACHE, os, subprocess,
    ) = bind(
        "WS", "_SEEN_ID_CACHE", "os", "subprocess",
    )
    key = (program, value)
    if key in _SEEN_ID_CACHE:
        return _SEEN_ID_CACHE[key]
    base = os.path.join(WS, "targets", str(program or ""))
    if not program or not os.path.isdir(base):
        return None
    try:   # -q exits on the first match, so a hit is cheap; a miss reads the tree once, under the timeout
        p = subprocess.run(["grep", "-rqF", "--binary-files=without-match", "--", value, base],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                           timeout=timeout)
        res = True if p.returncode == 0 else False if p.returncode == 1 else None
    except (OSError, subprocess.TimeoutExpired):
        return None
    if res is not None:
        _SEEN_ID_CACHE[key] = res
    return res


def _invented_id_note(program, url):
    """F4 advisory: an id-shaped value in the URL that no file under targets/<p>/ ever mentions. On 2026-11-09 the
    lead typed client_id=c88fb2a6c1e0e0e0... (made up) while the real vault client id sat in the lane notes."""
    (
        _ID_VALUE, _id_seen_on_disk, urllib,
    ) = bind(
        "_ID_VALUE", "_id_seen_on_disk", "urllib",
    )
    out = []
    for m in _ID_VALUE.finditer(str(url or "")):
        v = urllib.parse.unquote(next(g for g in m.groups() if g))
        if len(v) < 6 or v in out:
            continue
        if _id_seen_on_disk(program, v) is False:
            out.append(v)
    if not out:
        return ""
    return (f"NOTE: identifier {out[0][:48]!r} is not seen anywhere on disk for {program}; verify it is not invented "
            "(a made-up client id or key answers like a real refusal and fakes a DEAD, T-164).\n")


def _lead_probe_note(ctx, program, hypothesis, n=1):
    """F5 2026-11-09: 41 lead-fired http_request calls in one turn burned two 20-probe budgets serially. From the
    6th direct probe on one hypothesis in a turn, say so (advisory, never a block)."""
    (
        LEAD_PROBES_ADVISE,
    ) = bind(
        "LEAD_PROBES_ADVISE",
    )
    st = getattr(ctx, "s", None)
    if not hypothesis or not isinstance(st, dict) or st.get("_worker"):
        return ""
    key = f"{st.get('_turn_user') or ''}|{program}|{hypothesis}"
    d = st.setdefault("_lead_probes", {})
    d[key] = int(d.get(key) or 0) + int(n or 1)
    if d[key] < LEAD_PROBES_ADVISE:
        return ""
    return (f"ADVISORY: {d[key]} direct probes on {hypothesis} this turn. You are probing hands-on; dispatch "
            "probe_briefs()/claude_worker for this hypothesis and keep the lead thin.\n")


def _lead_share_cap():
    """T1.4 switch, read at call time. 0 (the DEFAULT) = advisory only, exactly the F5 behaviour; 0.4 = the lead may
    fire 40% of a hypothesis's probe budget hands-on per turn before it must dispatch. Shipped OFF: it reverses
    F5's written "never block" on a live hunt path, so it waits for the user's go after one session of advisory counts."""
    (
        LEAD_SHARE_ENV, os,
    ) = bind(
        "LEAD_SHARE_ENV", "os",
    )
    try:
        return max(0.0, float(os.environ.get(LEAD_SHARE_ENV) or 0))
    except ValueError:
        return 0.0


def _lead_probe_gate(ctx, program, hypothesis, n=1, thin=False):
    """(note, refusal) BEFORE a lead probe is sent, so a refusal never reaches _send or the economy.
    cap = max(LEAD_PROBES_ADVISE, floor(share * gnoc_economy.budget)); thin=true is the SPINE 7 thin exception, once
    per hypothesis per turn. Workers are never capped. idea: 0sec-labs/0 packages/core/src/agent/coordinator-rails.ts
    MAX_SOLO_BUDGET_SHARE; reimplemented, no code copied."""
    (
        LEAD_PROBES_ADVISE, _lead_share_cap, offline,
    ) = bind(
        "LEAD_PROBES_ADVISE", "_lead_share_cap", "offline",
    )
    st = getattr(ctx, "s", None)
    share = _lead_share_cap()
    if share <= 0 or not hypothesis or not isinstance(st, dict) or st.get("_worker"):
        return "", None
    try:
        import gnoc_economy
        budget = int(gnoc_economy.budget(program, hypothesis))
    except Exception:  # noqa: BLE001 - a broken economy enforces nothing (same posture as budget_refusal)
        return "", None
    cap = max(LEAD_PROBES_ADVISE, int(share * budget))
    key = f"{st.get('_turn_user') or ''}|{program}|{hypothesis}"
    have = int((st.get("_lead_probes") or {}).get(key) or 0)
    if have < cap:
        return "", None
    used = st.setdefault("_lead_thin", [])
    if (thin is True or str(thin).strip().lower() in ("true", "1", "yes")) and key not in used:
        used.append(key)
        return f"NOTE: thin confirmation on {hypothesis}, the one hands-on probe past the lead cap this turn.\n", None
    nxt = "delegate(...)" if offline() else "claude_worker(...)"
    spent = " Its thin confirmation is already spent this turn." if key in used else " One confirmation: thin=true."
    return "", (f"refused: you have fired {have} of {hypothesis}'s {budget}-probe budget hands-on (cap {cap}).\n"
                f"Dispatch it: probe_briefs(hypothesis='{hypothesis}') then {nxt}." + spent)
