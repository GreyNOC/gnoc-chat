"""HTTP/probe/race/browser tools and the scoped sender."""
import os
import re

from gnoc_core.runtime import bind


def valid_handle(program):
    """A program is a bare handle under targets/ - never a path. '/tmp/x' or '../x' holding a home-made SCOPE.txt
    passed the gate once and made any host 'in scope'."""
    (
        _HANDLE,
    ) = bind(
        "_HANDLE",
    )
    return bool(program) and isinstance(program, str) and bool(_HANDLE.match(program)) and ".." not in program


_RESOLVE_CACHE = {}


def _resolves_internal(host, timeout=2.5):
    """The internal address a hostname resolves to, or ''. Bounded (a slow resolver never stalls a probe) and cached
    for a minute; a name that does not resolve is not refused here (the request will fail on its own)."""
    import ipaddress
    import socket
    import threading
    import time as _t
    host = str(host or "").strip("[]").lower()
    if not host:
        return ""
    try:
        ip = ipaddress.ip_address(host)
        return "" if ip.is_global else str(ip)   # literals are lib_scope's business; answer consistently anyway
    except ValueError:
        pass
    hit = _RESOLVE_CACHE.get(host)
    if hit and _t.time() - hit[0] < 60:
        return hit[1]
    box = []

    def look():
        try:
            box.append({a[4][0] for a in socket.getaddrinfo(host, None)})
        except (OSError, UnicodeError):
            box.append(set())
    th = threading.Thread(target=look, daemon=True)
    th.start()
    th.join(timeout)
    bad = ""
    for a in sorted(box[0]) if box else ():
        try:
            ip = ipaddress.ip_address(a.split("%")[0])
        except ValueError:
            continue
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_unspecified or \
                ip.is_multicast:
            bad = str(ip)
            break
    _RESOLVE_CACHE[host] = (_t.time(), bad)
    return bad


def _host_header_refusal(program, url, headers):
    """A Host header naming another host than the URL's must be in scope too: on a shared front end (Fastly,
    CloudFront, Akamai) it routes the request to THAT site (QAQC r2: only scope_proxy checked it)."""
    from bbtools import lib_scope
    (WS,) = bind("WS")
    hv = next((str(v) for k, v in (headers or {}).items() if str(k).strip().lower() == "host"), "")
    if not hv:
        return None
    hh = hv.strip().split(":")[0].lower().rstrip(".")
    if hh == lib_scope.extract_host(url):
        return None
    ok, why = lib_scope.program_allows("https://" + hh + "/", program, WS)
    return None if ok else f"OUT_OF_SCOPE Host header {hh!r} for {program}: {why}"


def _program_gate(program, url):
    (
        WS, _LOOPBACK, gnoc_hunt, os, re, valid_handle,
    ) = bind(
        "WS", "_LOOPBACK", "gnoc_hunt", "os", "re", "valid_handle",
    )
    from bbtools import lib_policy, lib_scope
    # The machine's OWN dev server is not a bug-bounty target, and a coding turn cannot be made to verify a
    # page it is forbidden to load. Measured 2026-10-26: with a hunt program pinned, a web edit sent the lead
    # round 19 calls trying to open its own file, every one refused OUT_OF_SCOPE. Loopback is allowed here and
    # nowhere else; a real target is never 127.0.0.1 (lib_scope refuses internal IPs for exactly that reason).
    if _LOOPBACK.match(str(url or "")):
        return {"network_ok": True, "status": "loopback", "rate": 0}, None
    if not program:
        return None, "refused: no program named and none active: pass program=<handle> or call set_program first"
    if not valid_handle(program) or not os.path.isfile(os.path.join(WS, "targets", program, "SCOPE.txt")):
        return None, f"refused: no targets/{program}/SCOPE.txt (pass a program handle that has been intaken)"
    if not re.match(r"^https?://[^/\s]+", str(url or ""), re.I):
        hosts = ", ".join(gnoc_hunt.scope_hosts(program)[:6]) or "see SCOPE.txt"   # D72: bots sent '/web/v1/'
        return None, (f"bad arguments: url must be a full http(s) URL like https://host/path, got {str(url)[:80]!r}; "
                      f"the in-scope hosts are {hosts}")
    ok, why = lib_scope.program_allows(url, program, WS)
    if not ok:
        return None, f"OUT_OF_SCOPE {url} for {program}: {why}"
    from gnoc_core import provenance as _prov   # an in-scope HOST with another programme's PATH (initech replay)
    moved = _prov.transplant(program, url)
    if moved:
        return None, moved
    internal = _resolves_internal(lib_scope.extract_host(url))
    if internal:
        # an in-scope NAME pointing at this machine or the LAN (localhost.acme.com, a rebinding record) would reach
        # Burp, the scope proxy or a router; lib_scope only refused internal IP literals (QAQC r2)
        return None, (f"OUT_OF_SCOPE {url} for {program}: the host resolves to an internal address ({internal}); a "
                      "program's asset is never this machine or the LAN")
    pol = lib_policy.policy(program, WS)
    if not pol.get("network_ok"):
        return None, f"refused: {program} policy {pol.get('status')}: {pol.get('evidence', '')[:200]}"
    return pol, None


def _destructive_gate(program, method, url):
    """RULE 4 in code: an irreversibly destructive method is never a probe. touch() is the tool for a state change
    (BEFORE, WRITE, AFTER, REVERT, four captures). Measured 2026-11-04: 8 DELETE captures already on disk (program-64
    /v1/admin/users/unimpersonate, program-100 /public/pos/split-payment/estimate), each fired through the ordinary probe
    path with no revert and no before/after pair, i.e. the gate that was supposed to stop it did not exist."""
    (
        DESTRUCTIVE_METHODS,
    ) = bind(
        "DESTRUCTIVE_METHODS",
    )
    m = str(method or "GET").upper()
    if m not in DESTRUCTIVE_METHODS:
        return
    raise PermissionError(
        f"refused: {m} is an irreversibly destructive method and is not a probe (RULE 4). A state change runs "
        "through touch() with read_url, write_url, body and revert_body, so BEFORE/WRITE/AFTER/REVERT are all "
        "captured; a DELETE you cannot undo is never sent at a live target, not even on an object you own. If the "
        f"surface needs {m} to be proven, say so and stop there.")


_IDENT_HDR = __import__("re").compile(
    r"(?i)^x-(?:hackerone|h1|bugcrowd|intigriti|yeswehack|ywh|bug-?bounty|researcher|security-research)\b")


def _apply_carrier(hdrs, pol, handle=None):
    """Put the programme's REQUIRED identification on the request, and nothing it did not ask for."""
    (
        _UA_BASE,
    ) = bind(
        "_UA_BASE",
    )
    if handle is None:
        try:
            from bbtools import lib_policy as _lp   # imported lazily: gnoc_agent has no module-level import
            handle = _lp.handle()
        except Exception:                            # noqa: BLE001 - a missing handle must not block a probe
            handle = ""
    # An identification header the policy did not ask for is dropped, whatever the model typed. On program-19
    # 2026-11-25 the lead sent `X-HackerOne: greynoc` on its own; the policy asks for none, and an unrequested
    # header is the WAF fingerprint that 403ed the whole program-95 estate (T-294, T-302).
    want = pol["header"][0].lower() if pol.get("header") else ""
    for k in [k for k in hdrs if _IDENT_HDR.match(k) and k.lower() != want]:
        del hdrs[k]
    if pol.get("header"):
        hname, hval = pol["header"][0], pol["header"][1]
        # The POLICY value wins over a hand-typed one. setdefault kept whatever the model wrote, and on
        # program-50 2026-11-10 01:40Z three probes went to the wire as `X-HackerOne-Research: gnoc-research`,
        # a handle that is nobody's; the programme asks for the H1 username, and an unattributable probe is
        # the T-302 failure in miniature.
        for k in [k for k in hdrs if k.lower() == hname.lower() and hdrs[k] != hval]:
            del hdrs[k]
        hdrs.setdefault(hname, hval)
    lit = pol.get("ua_literal")
    if lit:
        lit = lit.replace("<your h1 username>", handle or "").replace("yourh1username", handle or "") \
                 .replace("<h1username>", handle or "").strip() or lit
        cur = next((v for k, v in hdrs.items() if k.lower() == "user-agent"), None)
        if not cur:
            hdrs["User-Agent"] = _UA_BASE + " " + lit
        elif lit.lower() not in cur.lower():
            for k in list(hdrs):
                if k.lower() == "user-agent":
                    hdrs[k] = cur.rstrip() + " " + lit
    return hdrs


def _leak_check(url, headers, body):
    (
        gnoc_secrets, json,
    ) = bind(
        "gnoc_secrets", "json",
    )
    leaked = gnoc_secrets.find(" ".join([url, json.dumps(headers or {}, default=str),
                                         body if isinstance(body, str) else json.dumps(body, default=str)]))
    if leaked:
        raise PermissionError(f"refused: the request carries the value of {', '.join(leaked)}; the user's own "
                              "credentials are never sent to a target")


def _capture(program, method, url, hdrs, body, r, tag=None, extra=None):
    """Save one exchange raw under the program's gnoc-agent hunt dir. Returns the path relative to WS."""
    (
        WS, _now, gnoc_oracle, json, os,
    ) = bind(
        "WS", "_now", "gnoc_oracle", "json", "os",
    )
    raw_dir = os.path.join(WS, "targets", program, "hunts", f"gnoc-agent-{_now():%Y%m%d}", "raw")
    os.makedirs(raw_dir, exist_ok=True)
    rp = os.path.join(raw_dir, f"{_now():%H%M%S%f}-{tag or method.lower()}.json")
    row = {"ts": _now().isoformat(), "request": {"method": method.upper(), "url": url, "headers": hdrs, "body": body},
           "response": {"status": r.get("status"), "headers": r.get("headers"), "body": r.get("body"),
                        "via": r.get("via_used")}}
    row.update(extra or {})
    with open(rp, "w") as f:
        json.dump(row, f, indent=1, default=str)
    gnoc_oracle.seal(rp)  # ORACLE: HMAC seal; oracle verify refuses an unsealed (hand-written) capture
    rel = os.path.relpath(rp, WS)
    # RECEIPTS (2026-11-25): the end-of-turn block lists what really went out, lead and bots alike
    from gnoc_core import receipts
    body_out = r.get("body")
    receipts.record(method, url, r.get("status"),
                    r.get("len") if r.get("len") is not None else (len(body_out) if body_out is not None else None),
                    rel, error=receipts.body_error(body_out))
    return rel


def _econ_budget(program, hypothesis):  # ECON: refuse a probe once the hypothesis's budget is spent
    """Raise gnoc_economy.BudgetExhausted (no request fired, no probe counted) when the budget is exhausted."""
    (
        _budget_alternatives, gnoc_hunt,
    ) = bind(
        "_budget_alternatives", "gnoc_hunt",
    )
    if not hypothesis:
        return
    try:
        import gnoc_economy
    except Exception:  # noqa: BLE001 - no economy, no budget
        return
    msg = gnoc_economy.budget_refusal(program, hypothesis)
    if msg:
        try:
            parked = gnoc_hunt.park_spent(program, gnoc_hunt.canonical_hyp_id(program, hypothesis))   # D63
        except Exception:  # noqa: BLE001
            parked = ""
        raise gnoc_economy.BudgetExhausted(msg + "." + parked + _budget_alternatives(program, hypothesis))


def _budget_alternatives(program, hypothesis):
    """D60 (drive cycle 21, 2026-10-26): the refusal said 'pivot to the next open hypothesis' and the lead tried
    H3, H6, H7, H16 and H19 in turn, each refused the same way (H3 seven times, H16 six). Name the ids with budget
    left, or say that a new hypothesis is the only move."""
    (
        gnoc_hunt,
    ) = bind(
        "gnoc_hunt",
    )
    try:
        import gnoc_economy
        rows = gnoc_hunt.open_with_budget(program, gnoc_economy.budget, skip=hypothesis)
    except Exception:  # noqa: BLE001
        return ""
    if rows:
        return (". Open with budget left: " + ", ".join(f"{i} ({n}/{b})" for i, n, b in rows[:6])
                + ". Probe one of those; every other id is spent.")
    return (". No open hypothesis has budget left: add a new one (hunt_hypothesis action=add) aimed at a route that "
            "has answered (known-paths, js_mine), not at a wall.")


def _url_host(url):
    (
        re,
    ) = bind(
        "re",
    )
    m = re.match(r"^[a-z]+://([^/:?#]+)", str(url or ""), re.I)
    return m.group(1).lower() if m else ""


def _egress_print():
    """Which tunnels this machine has up (wg*, tun*, mullvad*, proton*, ppp*): the route a request leaves by. A
    host-down mark made on one route says nothing about another. program-78 2026-11-26: a worker connected Mullvad,
    two QA hosts timed out for gnoc chat, and the mark kept refusing them after the tunnel dropped."""
    try:
        names = os.listdir("/sys/class/net")
    except OSError:
        return ""
    return ",".join(sorted(n for n in names if re.match(r"(?:wg|tun|tap|mullvad|proton|ppp|nordlynx)", n)))


def _mark_host_down(url, e):
    """Count a connect timeout against the host. Two in 15 minutes wall it (fast-fail instead of 30 s each)."""
    (
        HOST_DOWN_FOR_S, _HOST_DOWN, _url_host, time,
    ) = bind(
        "HOST_DOWN_FOR_S", "_HOST_DOWN", "_url_host", "time",
    )
    if not ("timed out" in str(e).lower() or "timeout" in type(e).__name__.lower()):
        return
    h = _url_host(url)
    if not h:
        return
    row = _HOST_DOWN.get(h)
    via = _egress_print()
    if row and time.time() - row[1] < HOST_DOWN_FOR_S and (row[2] if len(row) > 2 else via) == via:
        row[0] += 1
        row[1] = time.time()
    else:
        _HOST_DOWN[h] = [1, time.time(), via]


def _host_down_note(url):
    """The refusal for a walled host, or None. program-50 2026-11-10 03:00Z: the admin SPA's API origin
    (scrm-sreadmin-api) black-holed every connection and the lead paid 30 s per probe, three times in six minutes,
    with four hypotheses parked on that one host. An origin that never completes a handshake is not a 'retry once'
    case after the second time: it is UNFIRED ground until the wall expires."""
    (
        HOST_DOWN_AFTER, HOST_DOWN_FOR_S, _HOST_DOWN, _url_host, time,
    ) = bind(
        "HOST_DOWN_AFTER", "HOST_DOWN_FOR_S", "_HOST_DOWN", "_url_host", "time",
    )
    h = _url_host(url)
    row = _HOST_DOWN.get(h) if h else None
    if not row or row[0] < HOST_DOWN_AFTER:
        return None
    if len(row) > 2 and row[2] != _egress_print():   # the route changed since the mark: try the host again
        _HOST_DOWN.pop(h, None)
        return None
    age = time.time() - row[1]
    if age >= HOST_DOWN_FOR_S:
        _HOST_DOWN.pop(h, None)
        return None
    left = int((HOST_DOWN_FOR_S - age) // 60) + 1
    return (f"HOST UNREACHABLE: {h} black-holed {row[0]} connection(s) (connect timeout, no handshake) in the last "
            f"{HOST_DOWN_FOR_S // 60} minutes; not sent. Mark every hypothesis that lives only on this host UNFIRED "
            f"with reason 'origin not reachable from here' and move to a host that answers. The wall lifts in about "
            f"{left} minute(s); a browser arm (browser tool) is the one thing worth trying meanwhile if the host is "
            "meant to be public.")


def _send(program, pol, url, method="GET", headers=None, body=None, hypothesis=None):
    """One gated, rate-limited request with its raw capture saved. Returns (response dict, raw path rel to WS)."""
    (
        HTTP_DEADLINE_S, HostUnreachable, WS, _apply_carrier, _capture, _deadline,
        _destructive_gate, _econ_budget, _graph_db, _host_down_note, _last_http,
        _leak_check, contextlib, gnoc_graph, gnoc_hunt, io, os, time,
    ) = bind(
        "HTTP_DEADLINE_S", "HostUnreachable", "WS", "_apply_carrier", "_capture",
        "_deadline", "_destructive_gate", "_econ_budget", "_graph_db", "_host_down_note",
        "_last_http", "_leak_check", "contextlib", "gnoc_graph", "gnoc_hunt", "io", "os",
        "time",
    )
    from bbtools import bh
    hostbad = _host_header_refusal(program, url, headers)
    if hostbad:
        raise PermissionError(hostbad)
    down = _host_down_note(url)
    if down:
        raise HostUnreachable(down)
    walls = gnoc_hunt.program_walls(program)
    rk = gnoc_hunt.route_key(url)
    shells = gnoc_hunt.program_shell_routes(program)
    if rk in shells:
        raise gnoc_hunt.RouteWalled(
            f"route closed: {rk} took {shells[rk]} probes across this program's hypotheses and every granted answer was "
            f"the SPA shell (an HTML document the host serves on every path); no hypothesis gets another probe there, "
            f"any method. Pick a different route from KNOWN ROUTES or a mined bundle, or a different host.")
    if rk in walls and (str(method or "GET").upper() == "GET" and not body or walls[rk][1] >= 2 * gnoc_hunt.WALL_MIN):
        # T-49 / T-266 as a gate: a route that only ever refused, across the WHOLE program, is absent surface; a new
        # hypothesis id on the same GET is the same probe (drive cycle 1, 2026-10-25). POST or a body is a new shape,
        # but only while the route is under 2 x WALL_MIN probes: cycle 4 fed the wall five POSTs with bodies, every one
        # a 404, and each new capture restarted the edge proof budget.
        shape, n = walls[rk]
        try:   # D64: the third wall refusal under a hypothesis that never reached the floor parks it
            parked = gnoc_hunt.note_wall_refusal(program, gnoc_hunt.canonical_hyp_id(program, hypothesis)) \
                if hypothesis else ""
        except Exception:  # noqa: BLE001
            parked = ""
        raise gnoc_hunt.RouteWalled(
            f"route wall: {rk} answered {shape.replace(':', ' len=')} on all {n} probes across this program's "
            f"hypotheses and never a 2xx/3xx; firing it again under another hypothesis id is the same probe "
            f"(T-49, T-266). Not fired, not counted. Pick a route that exists (js_mine, known-paths, hunt_search, "
            f"the vendor docs) or change the method and body." + parked)
    _econ_budget(program, hypothesis)  # ECON: budget exhausted -> refused before the wire, counted as no probe
    _leak_check(url, headers, body)
    _destructive_gate(program, method, url)  # RULE 4: DELETE is never a probe; it is a touch() with a revert
    hdrs = _apply_carrier(dict(headers or {}), pol)
    gap = 1.0 / max(float(pol.get("rps") or 1.0), 0.1)
    wait = _last_http.get(program, 0) + gap - time.time()
    if wait > 0:
        time.sleep(wait)
    _last_http[program] = time.time()
    scope_file = os.path.join(WS, "targets", program, "SCOPE.txt")
    t0 = time.monotonic()  # ORACLE: elapsed is recorded by code, so sqli-time can be judged from captures
    with contextlib.redirect_stderr(io.StringIO()):
        r = _deadline(lambda: bh.req(url, method=method.upper(), body=body, headers=hdrs, scope_file=scope_file),
                      HTTP_DEADLINE_S, f"{method.upper()} {url[:80]}")
    rel = _capture(program, method, url, hdrs, body, r, extra={"elapsed": round(time.monotonic() - t0, 3)})
    try:  # ECON: every gated probe debits 1 RC from the acting bot
        import gnoc_economy
        gnoc_economy.debit_probe(program, gnoc_economy.current_bot("lead"))  # ECON: workers set acting_as; else lead
    except Exception:
        pass
    # DUAL GRAPH: every gated request is a trace, and its host/endpoint become assets. Never let graph
    # state fail a probe that already happened.
    with contextlib.suppress(Exception):
        gnoc_graph.record_probe(program, url, method, r.get("status"), rel, hypothesis or "",
                                db_path=_graph_db())
    return r, rel


def _deadline(fn, secs, what):
    """fn() with a wall-clock cap. Raises TimeoutError naming the cap (the abandoned call finishes in a daemon
    thread), so a hung host or proxy costs the turn one minute, never the whole turn."""
    (
        threading,
    ) = bind(
        "threading",
    )
    box = {}

    def run():
        try:
            box["v"] = fn()
        except BaseException as e:  # handed back to the caller below
            box["e"] = e
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(secs)
    if t.is_alive():
        raise TimeoutError(f"{what} gave no answer within the {secs}s limit")
    if "e" in box:
        raise box["e"]
    return box.get("v")


def _net_fail(what, e):
    """A failed request, said so the model knows what to do next: a timeout is not a block and not a negative."""
    if isinstance(e, TimeoutError) or "timeout" in type(e).__name__.lower() or "timed out" in str(e).lower():
        return (f"{what} TIMED OUT: {e}. A timeout is neither a block nor a negative: retry once; if it repeats, "
                "record the vector UNFIRED with the reason")
    return f"{what} failed: {type(e).__name__}: {str(e)[:300]}"


def _race_ok(ok):
    """ok spec -> predicate on a response dict: 'status:200', 'status:2xx', or a body substring."""
    (
        re,
    ) = bind(
        "re",
    )
    ok = (ok or "status:2xx").strip()
    m = re.fullmatch(r"status:(\d)xx", ok)
    if m:
        return lambda r: str(r.get("status") or "").startswith(m.group(1))
    m = re.fullmatch(r"status:(\d{3})", ok)
    if m:
        return lambda r: str(r.get("status")) == m.group(1)
    return lambda r: ok in str(r.get("body") or "")


def race_verdict(conc_ok, serial_ok, n):
    """The SIG-1 discriminant, in code: more successes concurrently than serially = the one-shot gate is not
    atomic. Equal counts are a negative for this burst; all-pass in both arms means no limit was reached."""
    if conc_ok > serial_ok and serial_ok <= 1:
        return f"RACE SIGNAL: {conc_ok}/{n} concurrent passed vs {serial_ok}/{n} serial (one-shot gate not atomic)"
    if conc_ok > serial_ok:
        return f"DIVERGENT: {conc_ok}/{n} concurrent vs {serial_ok}/{n} serial (check the limit by hand)"
    if conc_ok == n and serial_ok == n:
        return f"NO LIMIT HIT: every request passed in both arms ({n}); this path is not single-use as fired"
    return f"NO RACE: {conc_ok}/{n} concurrent vs {serial_ok}/{n} serial (both arms ran; real concurrency negative)"


def t_race(ctx, url, program=None, method="POST", headers=None, body=None, n=10, ok="status:2xx",
           hypothesis=None, serial=True, as_identity=None):
    """Concurrent burst of n identical requests (released together) plus the same n fired serially as the control.
    Every response is saved raw; the verdict compares how many passed `ok` in each arm."""
    (
        HTTP_DEADLINE_S, RACE_MAX, WS, _apply_carrier, _capture, _deadline,
        _destructive_gate, _econ_budget, _first_touch, _ghost_strict, _last_http, _leak_check, _net_fail,
        _program_gate, _race_n_cap, _race_ok, _with_identity, contextlib, gnoc_hunt,
        io, os, race_verdict, time,
    ) = bind(
        "HTTP_DEADLINE_S", "RACE_MAX", "WS", "_apply_carrier", "_capture", "_deadline",
        "_destructive_gate", "_econ_budget", "_first_touch", "_ghost_strict", "_last_http", "_leak_check",
        "_net_fail", "_program_gate", "_race_n_cap", "_race_ok", "_with_identity",
        "contextlib", "gnoc_hunt", "io", "os", "race_verdict", "time",
    )
    from bbtools import bh
    from bbtools.race_burst import burst
    program = program or ctx.program
    pol, err = _program_gate(program, url)
    if err:
        return err
    strict = _ghost_strict(ctx, program, url)
    if strict:
        return strict
    n = max(2, min(int(n or 10), RACE_MAX))
    try:
        _destructive_gate(program, method, url)   # QAQC 2026-11-19: the burst fired bh.req directly, past RULE 4
        _leak_check(url, headers, body)
        hdrs = _with_identity(program, headers, as_identity, url)
    except PermissionError as e:
        return str(e)
    except KeyError as e:
        return str(e).strip("'\"") + " (identities action=list shows the saved names)"
    hdrs = _apply_carrier(hdrs, pol)
    scope_file = os.path.join(WS, "targets", program, "SCOPE.txt")
    okf = _race_ok(ok)
    try:  # ECON: a burst on a hypothesis whose probe budget is spent is refused before any request
        _econ_budget(program, hypothesis)
        n, capped = _race_n_cap(program, hypothesis, n, arms=2 if serial else 1)   # D55/D69: both arms count
        if capped:
            return capped
    except PermissionError as e:
        return str(e)

    def fire(_i=0):
        with contextlib.redirect_stderr(io.StringIO()):
            return bh.req(url, method=method.upper(), body=body, headers=hdrs, scope_file=scope_file)

    t0 = time.time()
    try:
        conc = _deadline(lambda: burst(fire, n=n), HTTP_DEADLINE_S * 2, f"race burst of {n}")
    except TimeoutError as e:
        return _net_fail("race", e)
    spread = time.time() - t0
    rows, paths = [], []
    for i, r in conc:
        r = r if isinstance(r, dict) else {"status": None, "body": f"{type(r).__name__}: {r}"}
        paths.append(_capture(program, method, url, hdrs, body, r, f"race-c{i:02d}", {"arm": "concurrent"}))
        rows.append(("concurrent", r))
    _last_http[program] = time.time()
    if serial:
        gap = 1.0 / max(float(pol.get("rps") or 1.0), 0.1)
        for i in range(n):
            time.sleep(gap)
            try:
                r = _deadline(fire, HTTP_DEADLINE_S, f"serial {i + 1}")
            except Exception as e:
                r = {"status": None, "body": f"{type(e).__name__}: {e}"}
            paths.append(_capture(program, method, url, hdrs, body, r, f"race-s{i:02d}", {"arm": "serial"}))
            rows.append(("serial", r))
        _last_http[program] = time.time()
    count = {"concurrent": 0, "serial": 0}
    shapes = {}
    for arm, r in rows:
        count[arm] += bool(okf(r))
        k = (arm, r.get("status"), len(str(r.get("body") or "")))
        shapes[k] = shapes.get(k, 0) + 1
    gnoc_hunt.log_probe(program, hypothesis, paths[0] if paths else "")
    gnoc_hunt.mark_burst(program, hypothesis, len(rows))
    gnoc_hunt.note_shapes(program, hypothesis, paths[1:])   # D80: every arm's route shape, so walls form from bursts
    lines = [f"  {arm:<10} {st} len={ln}  x{c}" for (arm, st, ln), c in sorted(shapes.items(), key=str)]
    dead = sum(1 for _, r in rows if r.get("status") is None)
    if dead:  # no response at all is not a refusal: say so before the verdict is read as a negative
        lines.append(f"  {dead} of {len(rows)} request(s) got NO response (timeout/connection error, status None): "
                     "the counts above are not a clean negative; re-run once before trusting them")
    verdict = race_verdict(count["concurrent"], count["serial"] if serial else 0, n) if serial else \
        f"concurrent only: {count['concurrent']}/{n} passed (no serial control fired; not a verdict)"
    return _first_touch(ctx, program, url) + (f"{verdict}\nburst released {n} in {spread:.2f}s; ok = {ok}\n" + "\n".join(lines)
            + f"\nraw: {os.path.dirname(paths[0]) if paths else '-'} (race-c* concurrent, race-s* serial)"
            + (f"\ncounted {len(rows)} probes (burst) against {hypothesis}" if hypothesis else ""))


def _race_n_cap(program, hypothesis, n, arms=2):
    """(n, refusal): the burst size capped to the hypothesis's budget left, or a refusal line when nothing is left.
    Drive cycle 20 (2026-10-26 07:13Z): H28, H30 and H31 ended at 26, 35 and 32 probes against budgets of 20; the
    race tool checked the budget once and then marked the whole burst."""
    (
        _matrix_budget_left,
    ) = bind(
        "_matrix_budget_left",
    )
    try:
        n = max(1, int(n or 10))
    except (TypeError, ValueError):
        n = 10
    left = _matrix_budget_left(program, hypothesis)
    if left is None:
        return n, None
    if left < arms:
        return n, (f"refused: {hypothesis} has no probe budget left for a burst; decide it (hunt_hypothesis "
                   f"action=update status=lead|dead|unfired) or move to the next open hypothesis.")
    return min(n, left // arms), None   # D69: the serial control is a second arm of n (H34: 5 + 10 + 10 = 25 of 20)


def _matrix_budget_left(program, hypothesis):
    """Probes the hypothesis may still spend (budget minus the probes already logged), or None when there is no
    hypothesis or no economy to ask."""
    (
        gnoc_hunt,
    ) = bind(
        "gnoc_hunt",
    )
    if not program or not hypothesis:
        return None
    try:
        import gnoc_economy
        hyp = gnoc_hunt.canonical_hyp_id(program, hypothesis)
        h = gnoc_hunt._find_hyp(gnoc_hunt.load(program).get("hypotheses", []), hyp) or {}
        return max(0, int(gnoc_economy.budget(program, hyp)) - int(h.get("probes") or 0))
    except Exception:  # noqa: BLE001 - no economy, no cap beyond the per-request check
        return None


def _matrix_wall(program, url, hypothesis=None):
    """The one wall refusal for a matrix whose baseline route is a program wall or the SPA shell, else "". D94 (cycle
    25, 10:52Z): probe_matrix on api.program-0.example/api/account (150+ probes, never granted) returned ten RouteWalled
    rows, every variant refused by _send, and the lead read the table as 'the responses differ' and kept going."""
    (
        gnoc_hunt,
    ) = bind(
        "gnoc_hunt",
    )
    try:
        rk = gnoc_hunt.route_key(url)
        shells = gnoc_hunt.program_shell_routes(program)
        if rk in shells:
            return (f"route closed: {rk} took {shells[rk]} probes across this program's hypotheses and every granted "
                    "answer was the SPA shell; a matrix there is ten more of the same. Pick a different route or host.")
        walls = gnoc_hunt.program_walls(program)
        if rk in walls and walls[rk][1] >= 2 * gnoc_hunt.WALL_MIN:
            shape, n = walls[rk]
            parked = ""
            if hypothesis:
                try:
                    parked = gnoc_hunt.note_wall_refusal(program, gnoc_hunt.canonical_hyp_id(program, hypothesis)) or ""
                except Exception:  # noqa: BLE001
                    parked = ""
            return (f"route wall: {rk} answered {shape.replace(':', ' len=')} on all {n} probes across this program's "
                    "hypotheses and never a 2xx/3xx; a matrix there is every variant refused (T-49, T-266). Not fired, "
                    "not counted. Pick a route that exists (js_mine, known-paths, hunt_search) or probe AS a saved "
                    "identity with http_request." + parked)
    except Exception:  # noqa: BLE001
        return ""
    return ""


def t_probe_matrix(ctx, url, program=None, method="GET", headers=None, body=None, identities=None,
                   allow_writes=False, hypothesis=None, thin=False):
    """Fire the variant matrix for one seam and return only what differs (gnoc_probe)."""
    (
        _first_touch, _ghost_strict, _identity_arms, _identity_premise_refusal,
        _lead_probe_gate, _lead_probe_note, _lead_share_cap, _matrix_budget_left,
        _matrix_wall, _program_gate, _send, contextlib, gnoc_hunt, gnoc_probe,
    ) = bind(
        "_first_touch", "_ghost_strict", "_identity_arms", "_identity_premise_refusal",
        "_lead_probe_gate", "_lead_probe_note", "_lead_share_cap", "_matrix_budget_left",
        "_matrix_wall", "_program_gate", "_send", "contextlib", "gnoc_hunt", "gnoc_probe",
    )
    program = program or ctx.program
    pol, err = _program_gate(program, url)
    if err:
        return err
    strict = _ghost_strict(ctx, program, url)
    if strict:
        return strict
    try:
        named = _identity_arms(program, identities)
    except KeyError as e:
        return str(e).strip("'\"") + " (identities action=list shows the saved names)"
    needs_id = _identity_premise_refusal(program, gnoc_hunt.canonical_hyp_id(program, hypothesis) if hypothesis
                                         else None, headers if isinstance(headers, dict) else {}, named)   # F4
    if needs_id:
        return needs_id
    ids = {"none": {}, "junk-bearer": {"Authorization": "Bearer gnoc.invalid.token"}}
    ids.update(named)
    rows = []
    # a string 'false' is truthy: a write-enabling flag is True only when it says so
    writes = allow_writes is True or str(allow_writes).strip().lower() in ("true", "1", "yes")
    # D47 (drive cycle 18, 2026-10-26 05:23Z): H24 went from 12 to 32 probes in ONE matrix against a budget of 20;
    # the per-request budget check read the count as it stood when the loop started. The matrix counts its own sends
    # against the budget that remained at entry and stops there.
    closed = gnoc_hunt.closed_hypothesis(program, gnoc_hunt.canonical_hyp_id(program, hypothesis)) if hypothesis else None
    if closed:
        return closed   # D56
    walled = _matrix_wall(program, url, hypothesis)   # D94
    if walled:
        return walled
    hyp_c = gnoc_hunt.canonical_hyp_id(program, hypothesis) if hypothesis else None
    thin_note, lead_cap = _lead_probe_gate(ctx, program, hyp_c, 1, thin)   # T1.4, before any send
    if lead_cap:
        return lead_cap
    remaining = _matrix_budget_left(program, hypothesis)
    fired = 0
    for label, m, u, extra in gnoc_probe.variants(url, method, ids, writes):
        if remaining is not None and fired:   # D55: a bot and the lead may work one hypothesis at once; re-read
            remaining = _matrix_budget_left(program, hypothesis)
            fired = 0
        if remaining is not None and fired >= remaining:
            rows.append((label, m, u, f"not sent: {hypothesis} budget reached ({fired} sent this matrix)", None))
            continue
        _, err = _program_gate(program, u)
        if err:
            rows.append((label, m, u, err[:80], None))
            continue
        h = dict(headers or {}) if not label.startswith("as:") else {}
        h.update(extra)
        try:
            r, rp = _send(program, pol, u, m, h, body if m not in ("GET", "HEAD", "OPTIONS") else None,
                          hypothesis=hypothesis)  # ECON: probe budget
        except Exception as e:
            rows.append((label, m, u, f"{type(e).__name__}: {e}", None))
            continue
        fired += 1
        gnoc_hunt.log_probe(program, hypothesis, rp)
        rows.append((label, m, u, gnoc_probe.fingerprint(r), rp))
    table, n = gnoc_probe.summarize(rows)
    raws = {r[0]: r[4] for r in rows if r[4]}
    if hyp_c and raws and _lead_share_cap() > 0:   # T1.4: with the cap on, a matrix's sends count toward the lead share
        with contextlib.suppress(Exception):
            thin_note += _lead_probe_note(ctx, program, hyp_c, len(raws))
    return thin_note + _first_touch(ctx, program, url) + (table + f"\nbaseline raw={raws.get('baseline')}  control raw={raws.get('control:nonsense')}"
            + (f"\ncounted {len(raws)} probes against {hypothesis}" if hypothesis else ""))


def t_sweep(ctx, url, program=None, method="GET", slots=None, payload_set="encodings", headers=None, body=None,
            cap=40, hypothesis=None):  # ORACLE: {{X}} markers filled by code, every variant via the gated sender
    (
        _first_touch, _ghost_strict, _program_gate, _send, gnoc_hunt, gnoc_probe,
    ) = bind(
        "_first_touch", "_ghost_strict", "_program_gate", "_send", "gnoc_hunt",
        "gnoc_probe",
    )
    program = program or ctx.program
    # gate the seam URL up front, the way probe_matrix does. Without this an out-of-scope sweep built a
    # full variant table of per-row PermissionErrors under a "0 anomalies" headline, not one refusal.
    _, err = _program_gate(program, url)
    if err:
        return err
    strict = _ghost_strict(ctx, program, url)
    if strict:
        return strict

    def send(label, m, u, h, b):
        pol, err = _program_gate(program, u)
        if err:
            raise PermissionError(err[:100])
        r, rp = _send(program, pol, u, m, h, b, hypothesis=hypothesis)  # ECON: probe budget
        gnoc_hunt.log_probe(program, hypothesis, rp)
        return r, rp
    try:
        return _first_touch(ctx, program, url) + gnoc_probe.sweep(url, method, slots, payload_set, cap, send, headers, body)[0]
    except ValueError as e:
        return f"bad arguments: sweep: {e}"


def t_host_sweep(ctx, hosts, program=None, path="/", headers=None, hypothesis=None, cap=40):
    """ONE liveness pass over MANY in-scope hosts: GET <path> on each, through the gated sender (scope + policy +
    identification header + raw capture), one line per host. Born 2026-11-10 02:50Z on program-50: 187 wildcard
    zones to triage, `bash` refuses a `$h` loop variable at an in-scope host (scope gate, by design), `sweep` takes
    one host and many paths, so the lead fired one http_request per host and spent a turn on liveness alone."""
    (
        _program_gate, _send, gnoc_hunt, re,
    ) = bind(
        "_program_gate", "_send", "gnoc_hunt", "re",
    )
    program = program or ctx.program
    if isinstance(hosts, str):
        hosts = [h for h in re.split(r"[\s,;]+", hosts) if h]
    hosts = [str(h).strip().lower().replace("https://", "").replace("http://", "").rstrip("/") for h in (hosts or [])]
    hosts = [h for h in hosts if h and "/" not in h and "{" not in h and "$" not in h]
    if not hosts:
        return "bad arguments: hosts must be a list (or comma/space separated string) of bare hostnames"
    try:
        cap = max(1, min(int(cap or 40), 60))
    except (TypeError, ValueError):
        cap = 40
    path = "/" + str(path or "/").lstrip("/")
    rows, refused = [], []
    for h in hosts[:cap]:
        u = f"https://{h}{path}"
        pol, err = _program_gate(program, u)
        if err:
            refused.append(f"{h}: {err[:90]}")
            continue
        try:
            r, rp = _send(program, pol, u, "GET", headers, None, hypothesis=hypothesis)
            gnoc_hunt.log_probe(program, hypothesis, rp)
            first = str(r).splitlines()[0] if r else "(no answer)"
            rows.append(f"{h:48} {first[:150]}")
        except Exception as e:  # noqa: BLE001 - one dead host must not end the sweep
            rows.append(f"{h:48} FAILED: {str(e)[:120]}")
    out = [f"HOST SWEEP {program} GET {path}: {len(rows)} host(s) answered the sender, {len(refused)} refused by the gate"
           + (f", {len(hosts) - cap} over the cap of {cap} not sent" if len(hosts) > cap else "")]
    out += rows
    if refused:
        out.append("REFUSED (not in scope for this program): " + " | ".join(refused[:10]))
    out.append("Next: pick the hosts that answered with an app (not a shell, not a 404) and probe them one seam at a "
               "time with http_request / probe_matrix; a liveness line is not a finding.")
    return "\n".join(out)


def t_escalate(ctx, finding, dial=0, oracle_id=None, finder="worker", run=False, program=None):  # ORACLE
    (
        gnoc_oracle, resolve, run_worker,
    ) = bind(
        "gnoc_oracle", "resolve", "run_worker",
    )
    brief, role = gnoc_oracle.escalate_brief(program or ctx.program, finding, dial, oracle_id, finder)
    if not role or str(run).strip().lower() not in ("true", "1", "yes"):
        return brief + (f"\n(run=true dispatches it to the {role} model)" if role else "")
    m, h = resolve(role)
    return run_worker(ctx, brief, m, h, tag="escalate")


def _first_touch(ctx, program, url):
    """The first probe of a host in this conversation runs the verdict-only dedup; prior verdicts are put in front
    of the probe result so the model reads them before it fires the next one."""
    (
        gnoc_dedup, re,
    ) = bind(
        "gnoc_dedup", "re",
    )
    host = (re.match(r"^[a-z]+://([^/:?#]+)", url or "", re.I) or [None, ""])[1].lower()
    seen = ctx.s.setdefault("_dedup_hosts", [])
    if not host or not program or host in seen:
        return ""
    seen.append(host)
    n, text = gnoc_dedup.check(program, host)
    return (text + "\n\n--- probe result ---\n") if n else ""


def t_oast(ctx, action="new", label="", tag=None, program=None):
    (
        gnoc_oast,
    ) = bind(
        "gnoc_oast",
    )
    program = program or ctx.program
    if not program:
        return "no active program: call set_program first (OAST tags are kept per program)"
    if action == "new":
        pr = gnoc_oast.new_probe(program, label or "")
        tag, host, url, note = pr["tag"], pr["dns_host"], pr["http_url"], pr["note"]
        if not tag:
            return f"no OAST listener: {note}"
        parts = []
        if host:
            parts.append(f"DNS/HTTP callback host {host} (for DNS-shaped sinks: nslookup, XXE SYSTEM host, ssrf host)")
        if url:
            parts.append(f"HTTP callback URL {url} (for URL-shaped sinks: url param, webhook, template fetch; "
                         "HTTP only, no DNS)")
        return (f"tag {tag}  ({note})\n" + "\n".join(parts) + f"\nThen oast action=poll tag={tag}. A DNS-only hit "
                "proves resolution from their side, an HTTP hit proves a fetch; neither is impact on its own.")
    if action == "poll":
        return gnoc_oast.poll(program, tag)
    if action == "stop":
        return gnoc_oast.stop(program)
    return f"action is new, poll or stop (got {action!r}): new for a callback host, poll tag=<tag> to read hits"


def _in_active_scope(ctx):
    prog = ctx.program
    if not prog:
        return None
    from bbtools import lib_scope

    def f(host):
        try:
            return bool(lib_scope.program_allows(host, prog)[0])
        except Exception:
            return False
    return f


def _repo_path(text):
    """The repo-relative path a model typed into a web tool, or None. Drive cycle 13 (2026-10-26 02:40Z): a worker
    called web_fetch('targets/program-0/hunts/gnoc/known-paths.txt') three times, then web_search of the same path."""
    (
        WS, os,
    ) = bind(
        "WS", "os",
    )
    t = str(text or "").strip().strip("'\"")
    if not t or " " in t or "://" in t or t.startswith(("http:", "https:")):
        return None
    cand = t if os.path.isabs(t) else os.path.join(WS, t)
    if os.path.isfile(cand) and os.path.realpath(cand).startswith(os.path.realpath(WS) + os.sep):
        return os.path.relpath(os.path.realpath(cand), os.path.realpath(WS))
    return None


def t_web_fetch(ctx, url):
    (
        WS, _deadline, _in_active_scope, _net_fail, _repo_path, _spill, gnoc_comms,
        gnoc_secrets, gnoc_web, os, t_http_request, t_read_file, taint, urllib,
    ) = bind(
        "WS", "_deadline", "_in_active_scope", "_net_fail", "_repo_path", "_spill", "gnoc_comms",
        "gnoc_secrets", "gnoc_web", "os", "t_http_request", "t_read_file", "taint", "urllib",
    )
    url = str(url or "").strip()
    # CONVERT, do not refuse (2026-10-26, drive D35). A refusal that names the right tool is re-sent verbatim by a
    # small worker until the streak breaker switches the tool off, and the lane ends with nothing. The call is run
    # through the tool that fits and the answer says so.
    rp = _repo_path(url)
    if rp:
        return f"converted: {rp} is a file in the repo, not a web page; read_file ran instead:\n" + str(t_read_file(ctx, rp))
    if url and "://" not in url:
        url = "https://" + url  # 'nvd.nist.gov/vuln/...' meant https
    if gnoc_secrets.find(url):
        return "refused: the URL carries a secret value"
    try:
        host = urllib.parse.urlparse(url).hostname or ""
        prog = getattr(ctx, "program", None)
        if host and prog:
            from bbtools import lib_scope
            nos = lib_scope._scope_paths(prog, WS)[1]
            if os.path.isfile(nos) and lib_scope.host_in_scope(host, nos):
                # the program said: do not touch this host. An unidentified page fetch is still touching it
                # (QAQC r2: only http_request honoured NOSCOPE)
                return f"refused: {host} is listed OUT of scope for {prog} (NOSCOPE.txt); it is not fetched at all"
        if host and _in_active_scope(ctx)(host):
            return (f"converted: {host} is in the active program's scope, so http_request (captured, rate-limited, "
                    f"identified) ran instead of web_fetch:\n" + str(t_http_request(ctx, url)))
    except Exception:  # noqa: BLE001 - the scope check must never cost the fetch
        pass
    try:  # gnoc_web caps the request at 25s; this caps DNS + text extraction too
        ok, text = _deadline(lambda: gnoc_web.fetch(url, _in_active_scope(ctx)), 60, f"web_fetch {url[:80]}")
    except Exception as e:
        return _net_fail("web_fetch", e)
    if ok:
        taint(ctx, "web")
        # Remember what was actually READ. generate_image requires its references to be URLs from this
        # list, so "I looked it up" has to be true rather than typed (GreyNOC, 2026-10-24). Bounded: the
        # newest 40, which is far more than one media brief ever cites.
        read = [u for u in (ctx.s.get("fetched_urls") or []) if u != url]
        read.append(url)
        ctx.s["fetched_urls"] = read[-40:]
        return _spill(gnoc_comms.untrusted(f"web page {url[:80]}", text), "web")
    if "timeout" in text.lower() or "timed out" in text.lower():
        text += " (25s request limit hit: retry once, or find the same text via web_search on another site)"
    return text


def t_web_search(ctx, query, n=8):
    (
        _deadline, _net_fail, _repo_path, gnoc_web, re, t_read_file, t_web_fetch,
        web_bytes,
    ) = bind(
        "_deadline", "_net_fail", "_repo_path", "gnoc_web", "re", "t_read_file",
        "t_web_fetch", "web_bytes",
    )
    query = str(query or "").strip()
    if not query:
        return "bad arguments: web_search needs query=<words> (e.g. 'CVE-2024-1234 fix commit')"
    rp = _repo_path(query)
    if rp:
        return f"converted: {rp} is a file in the repo, not a search; read_file ran instead:\n" + str(t_read_file(ctx, rp))
    if " " not in query and re.match(r"https?://\S+$", query):
        return "converted: that is a URL, not a search; web_fetch ran instead:\n" + str(t_web_fetch(ctx, query))
    try:  # one DuckDuckGo page, 25s request cap inside gnoc_web; 45s wall clock here
        rows, note = _deadline(lambda: gnoc_web.search(query, max(1, min(int(n or 8), 20))), 45, "web_search")
    except Exception as e:
        return _net_fail("web_search", e)
    if not rows:
        return note
    # the note (e.g. "no results, DDG rate-limited") is the only thing that explains an empty page; it used to be
    # dropped whenever rows existed, so a partial answer read as a complete one
    return web_bytes("web_search results", "\n".join(
        f"{i}. {t}\n   {u}\n   {sn[:220]}" for i, (t, u, sn) in enumerate(rows, 1)) + (f"\n[{note}]" if note else ""),
        ctx)


def t_burp_check(ctx, paths=None):
    """For each raw capture: was it sent via Burp, and is it in Proxy history (where filing panels come from)?"""
    (
        _deadline, _inside_ws, _read, gnoc_web, json, os,
    ) = bind(
        "_deadline", "_inside_ws", "_read", "gnoc_web", "json", "os",
    )
    paths = [paths] if isinstance(paths, str) else list(paths or [])
    if not paths:
        return "needs paths=[<raw capture files>]: the captures whose Burp panels a filing would use"
    out = []
    for rp in paths[:12]:
        p = _inside_ws(rp)
        if not p or not os.path.isfile(p):
            out.append(f"{rp}: no such capture")
            continue
        try:
            d = json.loads(_read(p))
            rq, via = d["request"], (d.get("response") or {}).get("via")
        except (ValueError, KeyError):
            out.append(f"{rp}: not a gnoc raw capture")
            continue
        try:
            found, detail = _deadline(lambda rq=rq: gnoc_web.burp_history(rq["method"], rq["url"]), 30, "Burp MCP lookup")
        except Exception as e:
            out.append(f"{rp}: could not ask Burp ({type(e).__name__}: {str(e)[:120]}); is Burp running with its MCP "
                       "server on? (scripts/burp-start.sh)")
            continue
        out.append(f"{rp}: sent via {via or '?'}; {detail}"
                   + ("" if found else " -> re-send it through the Burp proxy (curl --path-as-is --proxy) before "
                                      "taking panels"))
    return "\n".join(out) or "give the raw capture paths"


def t_repro_check(ctx, draft_dir):
    (
        _inside_ws, _read, gnoc_gates, os,
    ) = bind(
        "_inside_ws", "_read", "gnoc_gates", "os",
    )
    p = _inside_ws(str(draft_dir or ""))
    if not p or not os.path.isfile(os.path.join(p, "report.md")):
        return (f"no report.md under {draft_dir}: pass the draft DIRECTORY, e.g. reports/drafts/<program>/<slug> "
                "(list_dir reports/drafts/<program> shows them)")
    verdict, nbad = gnoc_gates.write_format_gate(p, ctx.program)
    return f"{verdict} ({nbad} failing)\n" + _read(os.path.join(p, "GATE-local-format.md"))


def t_browser(ctx, url, js=None, wait_ms=3000, as_identity=None, selector=None, program=None):
    (
        BROWSER_DEADLINE_S, _deadline, _first_touch, _leak_check, _net_fail,
        _program_gate, gnoc_ident, target_bytes, _LOOPBACK,
    ) = bind(
        "BROWSER_DEADLINE_S", "_deadline", "_first_touch", "_leak_check", "_net_fail",
        "_program_gate", "gnoc_ident", "target_bytes", "_LOOPBACK",
    )
    import gnoc_browser
    program = program or ctx.program
    if not program and _LOOPBACK.match(str(url or "")):
        # never "call set_program" for a page on this machine: the lead did, and the coding chat became a bounty
        # program's (2026-11-20 SWE drive)
        return ("the browser opens a program's targets only. For your own dev server use http_request "
                f"url={url} (a GET): it returns the status and the page's markup.")
    # No program (or a made-up one) is the end of the browser for this turn: "generate a photo of a triangle" sent
    # it at the gnoc website fifteen times with URL variants the repeat breaker did not count (2026-11-23)
    _off = ("the browser is a bug-bounty tool: it opens an in-scope program's pages and nothing else, and this "
            "request has no program (gnoc's own website is not one). It is OFF for the rest of this turn: answer "
            "without it, and do not reach the same page through another tool.")
    if not program:
        __import__("gnoc_agent")._turn_off_tool(ctx, "browser")
        return "no active program. " + _off
    _, why = _program_gate(program, url)  # same scope AND policy gate as http_request (a banned program passed
    if why:                               # the browser's own host check once)
        if __import__("re").search(r"no targets/|not been intaken|no active program", str(why)):
            __import__("gnoc_agent")._turn_off_tool(ctx, "browser")
            return str(why) + ". " + _off
        return why
    try:
        _leak_check(url, None, js)
        ident = gnoc_ident.headers_for(program, [as_identity])[as_identity] if as_identity else None
    except PermissionError as e:
        return str(e)
    except KeyError as e:
        return str(e).strip("'\"") + " (identities action=list shows the saved names)"
    wait = max(0, min(int(wait_ms or 3000), 20000))
    try:  # goto is capped at 45s inside gnoc_browser; the whole visit (launch, load, wait, js, shot) at this
        res = _deadline(lambda: gnoc_browser.visit(program, url, js=js, wait_ms=wait, identity_headers=ident,
                                                   selector=selector), BROWSER_DEADLINE_S, f"browser {url[:80]}")
    except Exception as e:
        return _net_fail("browser", e)
    return _first_touch(ctx, program, url) + target_bytes(url, gnoc_browser.summary(res), ctx)


def desktop_grants(ctx):
    (
        DESKTOP_MAX_S, time,
    ) = bind(
        "DESKTOP_MAX_S", "time",
    )
    g = ctx.s.setdefault("_desktop", {})
    for t in [t for t, v in g.items() if time.time() - v["ts"] > DESKTOP_MAX_S]:
        del g[t]
    return g


def grant_desktop(ctx, target, reason):
    """Called ONLY from the approval path in run_tools, after the user said yes: the model cannot grant itself."""
    (
        desktop_grants, time,
    ) = bind(
        "desktop_grants", "time",
    )
    desktop_grants(ctx)[target] = {"reason": (reason or "")[:200], "ts": time.time()}


def revoke_desktop(ctx):
    g = ctx.s.pop("_desktop", None) or {}
    return sorted(g)


def t_desktop(ctx, action="look", target="local", reason="", ops=None, text=None, occurrence=1, window=None):
    (
        desktop_grants, gnoc_secrets, json, subprocess,
    ) = bind(
        "desktop_grants", "gnoc_secrets", "json", "subprocess",
    )
    import gnoc_desktop
    target = (target or "local").strip()
    g = desktop_grants(ctx)
    if action == "request":
        return (f"granted: you control {target}'s screen, mouse and keyboard for this task only (it switches off "
                "when you answer). Start with action=look." if target in g else
                f"not granted for {target}")
    if action == "release":
        g.pop(target, None)
        return f"control of {target} released"
    if target not in g:
        return (f"no control of {target}: call desktop action=request target={target} reason=<why you need the "
                "screen/mouse/keyboard>; the user approves it, and it ends with this task")
    try:
        if action == "look":
            png, size = gnoc_desktop.shot(target)
            out = gnoc_desktop.summary(target, png, size, gnoc_desktop.read(png) if gnoc_desktop.ocr_available()
                                       else [], gnoc_desktop.windows(target))
            # SEEING through a local vision model (computer use, 2026-11-23): the lead is text-only and OCR needs
            # tesseract, which most computers do not have. What the screen SAYS is untrusted text.
            try:
                import gnoc_comms
                import gnoc_computer
                if gnoc_computer.vision_model():
                    _m, seen = gnoc_computer.look(png)
                    ctx.s["_screen_sensitive"] = gnoc_computer.sensitive(seen)
                    out += "\n" + gnoc_comms.untrusted(f"what the screen shows ({_m})", seen)
                    if ctx.s["_screen_sensitive"]:
                        out += ("\n!! a password, login, payment or admin prompt is on the screen: do not type or "
                                "click in it; tell the user to handle it themselves, then look again.")
            except Exception as e:  # noqa: BLE001 - the screenshot and OCR still stand
                out += f"\n(vision unavailable: {e})"
            return out
        if action == "click_target":
            # click what is DESCRIBED ("the OK button", "the address bar"): a vision model points at it
            import gnoc_computer
            if ctx.s.get("_screen_sensitive"):
                return ("refused: the last look showed a password, login, payment or admin prompt; the user handles "
                        "that themselves. Look again once it is gone.")
            want = str(text or "").strip()
            if not want:
                return "click_target needs text=<what to click, e.g. 'the OK button'>"
            png, size = gnoc_desktop.shot(target)
            hit = gnoc_computer.locate(png, want)
            if not hit:
                return f"{want!r} is not on {target}'s screen (action=look shows what is)"
            res = gnoc_desktop.act(target, [{"op": "click", "x": hit[0], "y": hit[1]}], size)
            return (f"clicked {want!r} at ({hit[0]},{hit[1]}) (box {hit[2]}): {json.dumps(res)}. Look again to "
                    "check it did what you meant.")
        if action == "do":
            try:
                ops = json.loads(ops) if isinstance(ops, str) else (ops or [])
            except ValueError:
                return 'bad arguments: ops must be a JSON list like [{"op": "click", "x": 100, "y": 200}]'
            if isinstance(ops, dict):
                ops = [ops]
            bad = [o for o in ops if not isinstance(o, dict) or not o.get("op")]
            if not ops or bad:
                return ('bad arguments: ops must be a non-empty list of objects each with "op" (move, click, drag, '
                        'scroll, type, key, sleep), e.g. [{"op": "key", "combo": "ctrl+l"}]; action=look first')
            for o in ops:
                if o.get("op") == "type" and gnoc_secrets.find(str(o.get("text", ""))):
                    return "refused: that text carries one of the user's credentials; it is never typed by the bot"
                if o.get("op") in ("type", "click", "key") and ctx.s.get("_screen_sensitive"):
                    return ("refused: the last look showed a password, login, payment or admin prompt; the user "
                            "handles that themselves. Look again once it is gone.")
            return json.dumps(gnoc_desktop.act(target, ops))
        if action == "click_text":
            if not gnoc_desktop.ocr_available():
                return "click_text needs OCR: sudo apt install tesseract-ocr (or click by coordinates with action=do)"
            png, size = gnoc_desktop.shot(target)
            hit = gnoc_desktop.find_text(gnoc_desktop.read(png), text or "", int(occurrence or 1))
            if not hit:
                return f"'{text}' is not on {target}'s screen (action=look shows what is)"
            res = gnoc_desktop.act(target, [{"op": "click", "x": hit[0], "y": hit[1]}], size)
            return f"clicked '{text}' at ({hit[0]},{hit[1]}) in line {hit[2][:80]!r}: {json.dumps(res)}"
        if action == "focus":
            if target != "local":
                return "focus by window title works on this machine (KDE); on a linked machine click the window"
            import gnoc_kwin
            w = gnoc_kwin.activate(window or "")
            return f"focused {w}" if w else f"no window whose title contains {window!r}"
    except subprocess.TimeoutExpired as e:  # screenshot 40-90s, input 120s: the caps live in gnoc_desktop
        return (f"desktop {action} on {target} TIMED OUT after {e.timeout:.0f}s: the screen or input helper hung; "
                "try action=look once more, or release and tell the user")
    except (KeyError, RuntimeError, OSError, ValueError, subprocess.SubprocessError) as e:
        return f"desktop {action} on {target} failed: {type(e).__name__}: {e}"
    return "action is request, look, do, click_text, click_target, focus or release"


def t_burp_panels(ctx, raw, draft_dir=None, program=None):
    """Re-send one decisive raw capture through Burp's proxy (Proxy history), then, with desktop control of this
    machine granted, drive Burp and save verified request/response panel crops next to the draft."""
    (
        _destructive_gate, _inside_ws, _last_http, _leak_check, _program_gate, desktop_grants, os,
        subprocess, time,
    ) = bind(
        "_destructive_gate", "_inside_ws", "_last_http", "_leak_check", "_program_gate", "desktop_grants", "os",
        "subprocess", "time",
    )
    import gnoc_panels
    program = program or ctx.program
    p = _inside_ws(str(raw or ""))
    if not p or not os.path.isfile(p):
        return (f"no raw capture at {raw}: pass the raw=... path an http_request result printed "
                "(targets/<program>/hunts/gnoc-agent-*/raw/*.json)")
    try:
        req = gnoc_panels.load_raw(p)
    except (ValueError, KeyError):
        return f"{raw} is not a gnoc raw capture (request/response JSON)"
    pol, err = _program_gate(program, req["url"])
    if err:
        return err
    try:
        _destructive_gate(program, req.get("method"), req["url"])   # the re-send is a request like any other
        _leak_check(req["url"], req.get("headers"), req.get("body"))
    except PermissionError as e:
        return str(e)
    try:  # the curl re-send is capped at 60s inside gnoc_panels
        ok, first = gnoc_panels.resend(p)
    except subprocess.TimeoutExpired:
        return "re-send through Burp TIMED OUT after 60s: is Burp's proxy listening? (scripts/burp-start.sh)"
    _last_http[program] = time.time()
    if not ok:
        return f"re-send through Burp failed: {first}"
    head = f"re-sent through Burp proxy ({gnoc_panels.burp_proxy()}): {first}  -> newest row of Proxy history"
    if "local" not in desktop_grants(ctx):
        return head + ("\nPanels need the Burp window: desktop action=request target=local reason='take Burp panels' "
                       "then call burp_panels again (the re-send is harmless to repeat)")
    dest = None
    if draft_dir:
        d = _inside_ws(draft_dir)
        dest = os.path.join(d, "evidence", "panels") if d else None
    dest = dest or os.path.join(os.path.dirname(os.path.dirname(p)), "panels")
    ok, text = gnoc_panels.capture(p, dest)
    return head + "\n" + ("" if ok else "NOT DONE: ") + text
