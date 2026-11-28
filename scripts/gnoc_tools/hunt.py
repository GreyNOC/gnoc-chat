"""Hunt search, ghost paths, program/site, goals, graph, findings and oracle-adjacent tools."""
from gnoc_core.runtime import bind


def _local_page(url, method="GET", headers=None):
    """GET/HEAD of a page on THIS machine (a coding chat's own dev server): no program, no scope, no hunt
    bookkeeping. Without it http_request raised TypeError on a None program, and the browser said "call
    set_program", which a coding turn did (2026-11-20 SWE drive)."""
    import urllib.error
    import urllib.parse
    import urllib.request
    (
        gnoc_modes, os, root,
    ) = bind(
        "gnoc_modes", "os", "root",
    )
    method = str(method or "GET").strip().upper()
    try:
        port = urllib.parse.urlsplit(str(url)).port or 80
    except ValueError:
        return f"bad arguments: {url} is not a URL"
    # only THIS repo's server: another app of his on this machine (the control panel on 8787) is not the coding
    # chat's to call, and a page the lead read could ask it to
    repo = os.path.realpath(root())
    owner = gnoc_modes._listener_cwd(port)
    if owner is not None and port not in gnoc_modes.repo_ports(repo, declared_only=True) and not (
            owner == repo or owner.startswith(repo.rstrip(os.sep) + os.sep)):
        return (f"refused: port {port} is served from {owner}, not from this repo ({repo}); without a program, "
                "http_request only loads this repo's own dev server")
    if method not in ("GET", "HEAD"):
        return (f"refused: only GET or HEAD reach this machine's own server without a program (got {method}); "
                "change the app through its code, then load the page")
    hdrs = {str(k): str(v) for k, v in (headers or {}).items()} if isinstance(headers, dict) else {}
    req = urllib.request.Request(str(url), method=method, headers={"User-Agent": "gnoc-chat-local", **hdrs})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            status, reason, head, raw = r.status, r.reason, r.headers, r.read(200_000)
    except urllib.error.HTTPError as e:
        status, reason, head, raw = e.code, e.reason, e.headers, e.read(200_000)
    except (urllib.error.URLError, OSError, ValueError) as e:
        return f"request failed: {type(e).__name__}: {getattr(e, 'reason', e)} ({url})"
    ctype = (head.get("Content-Type") if head else "") or ""
    body = raw.decode("utf-8", "replace")
    return (f"HTTP {status} {reason}  {url}\ncontent-type: {ctype}  ·  {len(raw)} bytes\n\n"
            + (body[:6000] + (f"\n[... {len(body) - 6000} more characters]" if len(body) > 6000 else "")))


def t_http_request(ctx, url, program=None, method="GET", headers=None, body=None, hypothesis=None,
                   as_identity=None, thin=False):
    (
        _ANON_IDENTITY, _BadArg, _coerce, _count_ghost, _env_tag, _first_touch,
        _ghost_gate, _ghost_path_note, _ghost_strict, _identity_premise_refusal,
        _invented_id_note, _json_content_type, _lead_probe_gate, _lead_probe_note,
        _mark_host_down, _net_fail, _program_gate, _send, _soft200_note, _wall_told,
        _with_identity, contextlib, gnoc_hunt, re, target_bytes, _LOOPBACK,
    ) = bind(
        "_ANON_IDENTITY", "_BadArg", "_coerce", "_count_ghost", "_env_tag", "_first_touch",
        "_ghost_gate", "_ghost_path_note", "_ghost_strict", "_identity_premise_refusal",
        "_invented_id_note", "_json_content_type", "_lead_probe_gate", "_lead_probe_note",
        "_mark_host_down", "_net_fail", "_program_gate", "_send", "_soft200_note",
        "_wall_told", "_with_identity", "contextlib", "gnoc_hunt", "re", "target_bytes", "_LOOPBACK",
    )
    program = program or ctx.program
    if not program and _LOOPBACK.match(str(url or "")):
        return _local_page(url, method, headers)
    pol, err = _program_gate(program, url)
    if err:
        return err
    method = str(method or "GET").strip().upper()
    if not re.fullmatch(r"[A-Z]{3,10}", method):
        return f"bad arguments: method must be an HTTP verb like GET, POST, PUT, PATCH, DELETE; got {method[:20]!r}"
    if isinstance(headers, str):
        try:
            headers = _coerce("headers", headers, {"type": "object"})
        except _BadArg as e:
            return f"bad arguments: http_request: {e}"
    anon = str(as_identity or "").strip().lower() in _ANON_IDENTITY   # F4: a deliberate unauthenticated arm
    try:
        headers = _with_identity(program, headers, None if anon else as_identity, url)
    except KeyError as e:
        return str(e).strip("'\"") + " (identities action=list shows the saved names)"
    except PermissionError as e:
        return str(e)
    headers = _json_content_type(headers, body)
    gq = _graphql_query_of(body)
    if gq is not None:   # GRAPHQL (initech replay 2026-11-25): 12 hand-written queries were malformed on the wire
        from gnoc_core import gqlbuild
        bad = gqlbuild.check_syntax(gq)
        if bad:
            return (f"not sent: the GraphQL query in the body is malformed ({bad}), so the server would answer a "
                    "syntax error and the probe would test nothing. Use the graphql tool (field=, args=, select=, "
                    "wrap=) and the harness writes a valid query, or fix the text.")
    gate = _ghost_gate(ctx, program, url)
    if gate:
        return gate
    hypothesis = gnoc_hunt.canonical_hyp_id(program, hypothesis)  # "H16-mutated" is H16: one budget, one count (D39)
    needs_id = "" if anon else _identity_premise_refusal(program, hypothesis, headers, as_identity)   # F4
    if needs_id:
        return needs_id
    closed = gnoc_hunt.closed_hypothesis(program, hypothesis)  # D56: dead/unfired takes no probe until reopened
    if closed:
        return closed
    owed = gnoc_hunt.verdict_owed(program, hypothesis)  # D43: a verdict turn decides, it does not probe
    if owed:
        return owed
    if hypothesis and _ghost_strict(ctx, program, url):   # D44: an unmined route, after three guesses, is refused
        spent = gnoc_hunt.ghost_guesses_spent(program, hypothesis)
        if spent:
            parked = gnoc_hunt.note_ghost_refusal(program, hypothesis)   # D49: the third refusal parks it
            return spent + ("\n" + parked if parked else "")
    thin_note, lead_cap = _lead_probe_gate(ctx, program, hypothesis, 1, thin)   # T1.4, before any send
    if lead_cap:
        return lead_cap
    invented = thin_note
    with contextlib.suppress(Exception):   # F4 advisory, computed BEFORE this request's own capture lands on disk
        invented += _invented_id_note(program, url)
    try:
        r, rel = _send(program, pol, url, method, headers, body, hypothesis=hypothesis)  # ECON: probe budget
    except PermissionError:   # RULE 4: destructive method, refused before the wire; say why, do not retry it
        raise
    except Exception as e:
        if type(e).__name__ == "RouteWalled":   # refused before the wire, no probe counted
            return _wall_told(ctx, program, url, str(e))   # D100
        if type(e).__name__ == "BudgetExhausted":
            return str(e)
        if type(e).__name__ == "HostUnreachable":   # walled host: refused before the wire, no 30 s spent
            return str(e)
        _mark_host_down(url, e)
        return _net_fail("request", e)
    gnoc_hunt.log_probe(program, hypothesis, rel)
    with contextlib.suppress(Exception):
        invented += _lead_probe_note(ctx, program, hypothesis)   # F5
    hdr_lines = "\n".join(f"{k}: {v}" for k, v in list((r.get("headers") or {}).items())[:30])
    body_txt = r.get("body") or ""
    ghost = _ghost_path_note(program, url, r, body_txt)
    if ghost:
        _count_ghost(ctx, url)
    ghost += _soft200_note(ctx, url, r, body_txt)
    if gq is not None:
        with contextlib.suppress(Exception):
            from gnoc_core import gqlbuild
            taught = gqlbuild.learn(__import__("gnoc_agent").WS, program, body_txt)
            if taught:
                ghost += "GRAPHQL (the server's errors, kept for this programme): " + "; ".join(taught) + "\n"
    return _first_touch(ctx, program, url) + _env_tag(url) + ghost + invented + (
        f"HTTP {r.get('status')}  len={r.get('len')}  via={r.get('via_used')}  raw={rel}\n"
        + target_bytes(url, f"{hdr_lines}\n\n{body_txt[:3000]}"
                       + (f"\n[... {len(body_txt) - 3000} more body chars in raw file]" if len(body_txt) > 3000
                          else ""), ctx))


def _graphql_query_of(body):
    """The GraphQL query text a request body carries ({"query": ...}, or the first of a batch), else None."""
    try:
        d = body if isinstance(body, (dict, list)) else __import__("json").loads(str(body or ""))
    except ValueError:
        return None
    if isinstance(d, list) and d and isinstance(d[0], dict):
        d = d[0]
    if isinstance(d, dict) and isinstance(d.get("query"), str):
        return d["query"]
    return None


def t_graphql(ctx, url, field=None, args=None, select=None, op="query", wrap=None, variables=None, var_types=None,
              operation_name=None, query=None, program=None, headers=None, hypothesis=None, as_identity=None):
    """One GraphQL request whose query the harness writes: the model names the root field, its args, the selection and an
    optional inline-fragment wrapper (wrap=RootQuery is the T-346 shape). Sent through http_request (same gates,
    capture, receipts). A hand-written query= is syntax-checked instead. Initech replay 2026-11-25: 12 malformed
    hand-written queries, none of which tested anything."""
    import json as _json
    from gnoc_core import gqlbuild
    program = program or ctx.program
    for name, val in (("args", args), ("variables", variables), ("var_types", var_types), ("headers", headers)):
        if isinstance(val, str) and val.strip():
            try:
                val = _json.loads(val)
            except ValueError:
                return f"bad arguments: graphql {name} must be a JSON object, got {val[:60]!r}"
            if name == "args":
                args = val
            elif name == "variables":
                variables = val
            elif name == "var_types":
                var_types = val
            else:
                headers = val
    if isinstance(select, str) and select.strip().startswith(("[", "{")):
        try:
            select = _json.loads(select)
        except ValueError:
            return "bad arguments: graphql select must be a list of field paths like [\"id\", \"items.name\"]"
    if query:
        q = str(query)
        bad = gqlbuild.check_syntax(q)
        if bad:
            return (f"not sent: the query= text is malformed ({bad}). Pass field=, args= and select= instead and "
                    "the harness writes a valid query.")
    else:
        if not field:
            return ("bad arguments: graphql needs field=<root field> (and args=, select=, wrap= as needed), or "
                    "query=<a full query text>")
        try:
            q = gqlbuild.build(field, args, select, op=op, wrap=wrap, operation_name=operation_name,
                               var_types=var_types)
        except gqlbuild.BuildError as e:
            return f"bad arguments: graphql: {e}"
        known = gqlbuild.precheck(__import__("gnoc_agent").WS, program, field, args, select) if program else ""
        if known:
            return (f"not sent: {known}. A request the server already refused once tests nothing. Change field, "
                    "args or select; if this endpoint's schema really differs, send query= with the exact text.")
    payload = {"query": q, "variables": variables if isinstance(variables, dict) else {}}
    if operation_name:
        payload["operationName"] = operation_name
    hdrs = dict(headers or {}) if isinstance(headers, dict) else {}
    if not any(k.lower() == "content-type" for k in hdrs):
        hdrs["Content-Type"] = "application/json"
    seen = ctx.s.setdefault("_not_graphql", {}) if isinstance(getattr(ctx, "s", None), dict) else {}
    key = str(url).split("?")[0].rstrip("/").lower()
    if key in seen:
        # program-78 gnoc run 2026-11-26: the lead sent graphql field=root to a docs site three times; each answer was
        # an HTML page. An endpoint that did not answer as GraphQL once will not on the next query either.
        return (f"not sent: {url} already answered a GraphQL request as {seen[key]}, so it is not a GraphQL "
                "endpoint. Find the real one in the app's JS (js_mine) or use http_request for this API.")
    res = t_http_request(ctx, url, program=program, method="POST", headers=hdrs, body=_json.dumps(payload),
                         hypothesis=hypothesis, as_identity=as_identity)
    m = __import__("re").search(r"HTTP (\d{3})\s+len=(\S+)", str(res))
    if m and '"data"' not in str(res) and '"errors"' not in str(res):
        seen[key] = f"HTTP {m.group(1)} len={m.group(2)} with no GraphQL data or errors"
        res = (f"NOT GRAPHQL: {url} answered HTTP {m.group(1)} with no \"data\" or \"errors\" key; it is not a "
               "GraphQL endpoint, and a second graphql call to it is refused.\n") + str(res)
    return f"QUERY (written by gnoc):\n{q}\n\n{res}"


def _soft200_note(ctx, url, r, body_txt):
    """SOFT-200 (T-60, fix 52): launch #21 fired GET app.example.com/api/achilles/account/query_account_info with no
    session and read "HTTP 200 len=702" as the API answering - it was the 702-byte SPA shell the host returns for
    EVERY path. An HTML body on an API-shaped path, or a body the same size as the host's root page, is labelled
    before the model reads the status line. The root length per host is remembered from the first "/" capture."""
    (
        _API_SHAPE,
    ) = bind(
        "_API_SHAPE",
    )
    try:
        from urllib.parse import urlparse
        u = urlparse(str(url or ""))
        host, path = u.netloc.lower(), u.path or "/"
        st = r.get("status")
        hdrs = {str(k).lower(): str(v) for k, v in (r.get("headers") or {}).items()}
        ctype = hdrs.get("content-type", "").lower()
        n = int(r.get("len") or len(body_txt or ""))
        shells = ctx.s.setdefault("_shell_len", {}) if isinstance(getattr(ctx, "s", None), dict) else {}
        html = "text/html" in ctype or (body_txt or "").lstrip()[:15].lower().startswith(("<!doctype", "<html"))
        if path in ("", "/") and st == 200 and html:
            shells[host] = n
            return ""
        if st != 200 or not html:
            return ""
        root = shells.get(host)
        same = root is not None and root > 0 and abs(n - root) <= max(8, root // 50)
        if _API_SHAPE.search(path) or same:
            why = (f"same {n} bytes as the host's root page" if same else "an HTML document on an API-shaped path")
            return (f"SOFT-200 (T-60): {why}; the server routed this to the app shell, not to an API. This is NOT a "
                    "success and NOT a disclosure: it is the same answer a nonsense sibling path gets. A real API "
                    "answer is JSON or a distinct status; fire the nonsense-sibling control and compare bodies.\n")
    except Exception:  # noqa: BLE001 - a note never breaks a probe
        return ""
    return ""


def _ghost_key(url):
    (
        re,
    ) = bind(
        "re",
    )
    host = (re.match(r"https?://([^/?#]+)", url or "") or [None, ""])[1]
    path = re.sub(r"[?#].*$", "", (url or "").split(host, 1)[-1]) if host else ""
    return f"{host}{path}"


def _count_ghost(ctx, url):
    (
        _ghost_key,
    ) = bind(
        "_ghost_key",
    )
    try:
        g = ctx.s.setdefault("_ghost", {})
        g[_ghost_key(url)] = g.get(_ghost_key(url), 0) + 1
    except Exception:  # noqa: BLE001
        pass


def _ghost_strict(ctx, program, url):
    """For burst and matrix tools: a path that is not in the mined routes AND already answered as a ghost once, or
    is simply unknown while routes exist, is refused before any wire. race fired 8+8 at /api/admin/config (program-101)."""
    (
        _GHOST_SKIP_EXT, _ghost_key, _ghost_text, _load_known_paths,
    ) = bind(
        "_GHOST_SKIP_EXT", "_ghost_key", "_ghost_text", "_load_known_paths",
    )
    try:
        known = _load_known_paths(program)
        if not known:
            return None
        key = _ghost_key(url)
        path = key.split("/", 1)[1] if "/" in key else ""
        path = "/" + path if path else "/"
        if path in known or path.rstrip("/") in known or path == "/":
            return None
        segs = [x for x in path.split("/") if x]
        if len(segs) >= 2 and any(k.startswith("/" + "/".join(segs[:2]) + "/") or k == "/" + "/".join(segs[:2])
                                  for k in known):
            return None
        if any(path.lower().endswith(x) for x in _GHOST_SKIP_EXT):
            return None
        n = (ctx.s.get("_ghost") or {}).get(key, 0)
        if n:
            return _ghost_text(program, url, n)
        return (f"refused: {key} is not a mined route for {program} ({len(known)} known routes in targets/{program}/"
                "hunts/gnoc/known-paths.txt) and this tool sends many requests at once. Confirm the route exists "
                "with ONE http_request first (or js_mine the bundle), then burst or matrix it.")
    except Exception:  # noqa: BLE001
        return None


def _ghost_gate(ctx, program, url):
    """The note alone did not stop it: after GHOST-PATH on /api/seller/dashboard the lead sent the same path again
    with a header, then a body, then as a probe_matrix and a sweep (program-101 2026-10-23). The third plain probe of a
    ghost path in one turn is refused with the fix; a mined route is never gated."""
    (
        GHOST_LIMIT, _ghost_key, _ghost_text,
    ) = bind(
        "GHOST_LIMIT", "_ghost_key", "_ghost_text",
    )
    try:
        n = (ctx.s.get("_ghost") or {}).get(_ghost_key(url), 0)
    except Exception:  # noqa: BLE001
        return None
    if n < GHOST_LIMIT:
        return None
    return _ghost_text(program, url, n)


def _ghost_text(program, url, n):
    (
        _ghost_key,
    ) = bind(
        "_ghost_key",
    )
    return (f"refused: {_ghost_key(url)} is a GHOST path (no captured body or mined bundle for {program} mentions "
            f"it) and you already probed it {n} times this turn with 404 / SPA-200 answers. More variants of a path "
            "that does not exist prove nothing. Mine the routes first: js_mine url=<the page's JS bundle URL from "
            "the raw capture>, then probe a route from targets/" + str(program) + "/hunts/gnoc/known-paths.txt.")


def _known_paths_file(program):
    (
        WS, os,
    ) = bind(
        "WS", "os",
    )
    return os.path.join(WS, "targets", program, "hunts", "gnoc", "known-paths.txt")


def _index_routes(program, limit=400):
    """Routes we have ACTUALLY CAPTURED for this programme's in-scope hosts, read from the hunt index.

    The mined-route gate is right to refuse an invented path, but it is only as good as what js_mine
    happened to find. Measured 2026-10-28 on program-72: known-paths.txt held THREE routes, all static JS,
    so the agent dutifully stayed inside them and hypothesised "RCE" and "seam-race pay-then-verify"
    about /static/js/fetchConfig/app - a static config file - because that was all it was allowed to
    touch. Meanwhile the index already held
      app.example.com/default/shop/superbetro/purchase
      app.example.com/default/inventory/superbetro/currency:
      app.example.com/ro/super-spin/eligible
    i.e. the money surfaces the hunt was asked for. Starving the gate turns a good gate into a blindfold.
    These are captured URLs, not guesses, so admitting them does not weaken the ghost-route defence.
    """
    (
        WS, _GHOST_SKIP_EXT, _INDEX_ROUTES_CACHE, os, re,
    ) = bind(
        "WS", "_GHOST_SKIP_EXT", "_INDEX_ROUTES_CACHE", "os", "re",
    )
    if program in _INDEX_ROUTES_CACHE:
        return _INDEX_ROUTES_CACHE[program]
    out = set()
    try:
        import sqlite3
        from urllib.parse import urlsplit
        from bbtools import lib_scope
        db = os.path.join(WS, ".hunt-index", "hunts.db")
        if os.path.isfile(db):
            apexes = set()
            for ln in open(os.path.join(WS, "targets", program, "SCOPE.txt"),
                           encoding="utf-8", errors="replace"):
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                for tok in re.findall(r"[A-Za-z0-9*][A-Za-z0-9.*-]*\.[A-Za-z]{2,}", ln):
                    tok = tok.lstrip("*.").lower().rstrip("/")
                    if "." in tok and " " not in tok:
                        apexes.add(tok)
            if apexes:
                con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
                where = " OR ".join("url LIKE ?" for _ in apexes)
                rows = con.execute("SELECT DISTINCT url FROM urls WHERE url LIKE 'http%' AND (" + where
                                   + ") LIMIT 4000",
                                   tuple("%" + a + "%" for a in sorted(apexes))).fetchall()
                con.close()
                for (u,) in rows:
                    try:
                        ok, _ = lib_scope.program_allows(u, program, WS)
                    except Exception:  # noqa: BLE001
                        continue
                    if not ok:
                        continue
                    p = urlsplit(u).path or "/"
                    if p and p != "/" and not any(p.lower().endswith(x) for x in _GHOST_SKIP_EXT):
                        out.add(p.rstrip("/") or "/")
                    if len(out) >= limit:
                        break
    except Exception:  # noqa: BLE001 - the gate must still work if the index is absent
        out = set()
    _INDEX_ROUTES_CACHE[program] = out
    return out


def _load_known_paths(program):
    (
        _index_routes, _known_paths_file,
    ) = bind(
        "_index_routes", "_known_paths_file",
    )
    f = _known_paths_file(program)
    paths = set()
    try:
        with open(f) as fh:
            paths = set(ln.strip() for ln in fh if ln.strip())
    except OSError:
        pass
    return paths | _index_routes(program)


def _learn_paths(program, host, body):
    """Add every route-looking path in a captured body to the program's known set. Returns how many were new."""
    (
        _GHOST_SKIP_EXT, _PATH_RE, _known_paths_file, _load_known_paths, os,
    ) = bind(
        "_GHOST_SKIP_EXT", "_PATH_RE", "_known_paths_file", "_load_known_paths", "os",
    )
    if not body or not program:
        return 0
    found = set()
    for m in _PATH_RE.finditer(body[:2_000_000]):
        pth = m.group(0)
        if any(pth.lower().endswith(x) for x in _GHOST_SKIP_EXT) or "//" in pth:
            continue
        found.add(pth)
    if not found:
        return 0
    known = _load_known_paths(program)
    new = found - known
    if new:
        f = _known_paths_file(program)
        os.makedirs(os.path.dirname(f), exist_ok=True)
        with open(f, "a") as fh:
            for pth in sorted(new):
                fh.write(pth + "\n")
    return len(new)


def _ghost_path_note(program, url, r, body):
    """Learn routes from this response, then say so when the requested path was never seen anywhere."""
    (
        _GHOST_SKIP_EXT, _learn_paths, _load_known_paths, re,
    ) = bind(
        "_GHOST_SKIP_EXT", "_learn_paths", "_load_known_paths", "re",
    )
    try:
        host = (re.match(r"https?://([^/?#]+)", url or "") or [None, ""])[1]
        path = re.sub(r"[?#].*$", "", (url or "").split(host, 1)[-1]) if host else ""
        _learn_paths(program, host, body) if r.get("status") != 404 else 0
        ctype = ""
        for k, v in (r.get("headers") or {}).items():
            if str(k).lower() == "content-type":
                ctype = str(v).lower()
        if not path or path == "/" or any(path.lower().endswith(x) for x in _GHOST_SKIP_EXT):
            return ""
        known = _load_known_paths(program)
        if not known:
            return ""  # nothing mined yet for this program: no basis to call anything a ghost
        if path in known or path.rstrip("/") in known:
            return ""
        # a crafted variant of a known route (same first two segments) is deliberate, not a ghost
        segs = [x for x in path.split("/") if x]
        if len(segs) >= 2 and any(k.startswith("/" + "/".join(segs[:2]) + "/") or k == "/" + "/".join(segs[:2])
                                  for k in known):
            return ""
        status = r.get("status")
        if status == 404 or (status == 200 and "html" in ctype):
            why = ("404 on it" if status == 404 else "200 + HTML on it is the SPA shell (T-60), not the route")
            return (f"GHOST-PATH: {path} never appeared in any captured body for this program ({len(known)} known "
                    f"routes in targets/{program}/hunts/gnoc/known-paths.txt); a {why}, so this is a guessed path, "
                    "not a tested negative. Mine the real routes first (js_mine url=<the app's JS bundle>, or "
                    "read_file the raw capture of the page) and probe those.\n")
        return ""
    except Exception:  # noqa: BLE001 - a bookkeeping failure never costs the probe
        return ""


def web_bytes(source, text, ctx=None):
    """Text written by someone else on the open web (a search result, a page) as the model must see it: fenced,
    labelled as data, and remembered for the copy gate. web_fetch and mail were fenced from the start; web_search
    was not, so a result title or snippet was the one inbound channel that arrived bare (audit A-08, 2026-10-28)."""
    (
        gnoc_comms, remember_untrusted,
    ) = bind(
        "gnoc_comms", "remember_untrusted",
    )
    remember_untrusted(ctx, text)
    return gnoc_comms.untrusted(source, text)


def target_bytes(url, text, ctx=None):
    """A target's response as the model must see it: fenced and labelled as data. The bench's injection case
    (a planted 'cat secrets.env' in an HTML comment) was followed in 2 of 4 runs by the best model when the body
    arrived bare; web pages, mail and Discord were already fenced, target responses were not. Fencing alone did not
    stop it (2 of 3 still followed), so the text is also remembered for the copy gate in _needs_approval."""
    (
        gnoc_comms, remember_untrusted, urllib,
    ) = bind(
        "gnoc_comms", "remember_untrusted", "urllib",
    )
    remember_untrusted(ctx, text)
    host = urllib.parse.urlsplit(str(url or "")).hostname or "target"
    return gnoc_comms.untrusted(f"response from {host}", text)


def _hit_paths(text):
    """(ours, theirs) - the file paths a search result mentions, split by who wrote them.

    A chat transcript is NOT one of our notes. The agent's own session files, spilled tool output and
    sub-agent logs get indexed like everything else, so a name the model once INVENTED comes back on the
    next search as a hit under our own roof and reads as corroboration. That closes a loop where a
    confabulation becomes its own evidence, so those paths count as neither ours nor theirs.
    """
    (
        _OWN_TRANSCRIPT, _PATH_IN_OUTPUT, _THIRD_PARTY_PATH,
    ) = bind(
        "_OWN_TRANSCRIPT", "_PATH_IN_OUTPUT", "_THIRD_PARTY_PATH",
    )
    ours, theirs = set(), set()
    for m in _PATH_IN_OUTPUT.findall(text or ""):
        if _OWN_TRANSCRIPT.search(m):
            continue
        (theirs if _THIRD_PARTY_PATH.search(m) else ours).add(m)
    return ours, theirs


def _unknown_programs(terms):
    """Terms that look like a program handle but have no targets/<handle> here. Names what we do NOT have."""
    (
        WS, _PROGRAMISH, os,
    ) = bind(
        "WS", "_PROGRAMISH", "os",
    )
    out = []
    for t in terms:
        # _fts_terms wraps a dash-led token in quotes for FTS5 (D90), and 'acme-corp' arrives here as
        # '"acme-corp"': unquoted, nothing matched _PROGRAMISH any more and the withhold guard below went
        # silent, handing back the very rows it exists to withhold. Strip the quoting the query added.
        t = t.strip().strip('"').lower()
        if t in ("or", "and", "not"):
            continue
        if not _PROGRAMISH.match(t) or len(t) < 4 or "." in t:
            continue
        if os.path.isdir(os.path.join(WS, "targets", t)):
            continue
        # only worth saying for a term shaped like a handle someone would name, not every common word
        if "-" in t or "_" in t:
            out.append(t)
    return out


def _fts_terms(terms):
    """Quote any term FTS5 cannot take bare (a path with slashes, a colon, a dash-led token); keep bare words and the
    OR / AND / NOT operators as they are."""
    (
        re,
    ) = bind(
        "re",
    )
    out = []
    for t in terms:
        t = str(t).strip()
        if not t:
            continue
        if t in ("OR", "AND", "NOT") or re.fullmatch(r"[A-Za-z0-9_*]+", t) or (t.startswith('"') and t.endswith('"')):
            out.append(t)
        else:
            out.append('"' + t.replace('"', "") + '"')
    return out


def t_hunt_search(ctx, query):
    (
        WS, _ANSI, _fts_terms, _hit_paths, _run_group, _spill, _unknown_programs, os,
        shlex, subprocess,
    ) = bind(
        "WS", "_ANSI", "_fts_terms", "_hit_paths", "_run_group", "_spill",
        "_unknown_programs", "os", "shlex", "subprocess",
    )
    query = str(query or "").strip()
    if not query:
        return "bad arguments: hunt_search needs query=<host, endpoint or words>"
    try:
        terms = shlex.split(query)
    except ValueError:  # an unbalanced quote ("it's") is not a reason to crash
        terms = query.replace('"', " ").replace("'", " ").split()
    terms = _fts_terms(terms)   # D90: cycle 25 10:46Z, "fts5: syntax error near '/'" on a path term
    # PROVENANCE (initech replay 2026-11-25): an unfiltered search handed bot 6 a stayco hotel capture and it ported
    # the path onto www.initech.com. With a programme active the index returns that programme's rows only, unless
    # the query names another programme we have (then the operator asked about it on purpose).
    from gnoc_core import provenance as _prov
    mine = _prov.active(ctx)
    named = [t for t in terms if os.path.isdir(os.path.join(WS, "targets", t.strip('"').lower()))
             and t.strip('"').lower() != mine]
    env = dict(os.environ)
    if mine and not named:
        env["HQ_TARGET"] = mine
    if not os.path.isfile(os.path.join(WS, "scripts/hq")):
        # the index CLI stays in the operator's workspace: running it anyway raised FileNotFoundError mid-turn
        import gnoc_missing
        return gnoc_missing.note("hunt_search", "the hunt index (scripts/hq)",
                                 "Search this workspace's own notes instead: grep with pattern=<host or word> and "
                                 "path='targets/<program>' (or 'reports'), or find_file for a file by name.")
    try:
        r = _run_group([os.path.join(WS, "scripts/hq"), "search"] + terms,
                           capture_output=True, text=True, timeout=30, cwd=WS, stdin=subprocess.DEVNULL, env=env)
    except subprocess.TimeoutExpired:  # hq search is bounded (<1 s typical, hq_search.py); 30 s means a locked/broken db
        return "hunt_search TIMED OUT after 30s: the hunt index may be locked mid-reindex; retry, or use fewer terms"
    text = _ANSI.sub("", r.stdout or r.stderr or f"(no results for {query!r}: try a host or one word)")
    missing = _unknown_programs(terms)
    ours, theirs = _hit_paths(text)
    if missing and not ours:
        # WITHHOLD, do not annotate. The note version of this said, in the tool output, "there is no
        # targets/acme-corp ... say that plainly rather than answering from it" - and the model answered
        # from it anyway, twice, inventing a bucket name the second time (2026-10-25). Advice appended to
        # a result does not compete with the result. Every row here is third-party material matched only
        # because an upstream repo uses the same example name, so the rows are the defect: they are not
        # evidence about a thing that does not exist, and the model cannot misread what it is not given.
        return ("no results: there is no targets/" + ", no targets/".join(missing) + " in this workspace, "
                + ("these are" if len(missing) > 1 else "so that is") + " not one of our engagements and we "
                "have no notes, hunts or reports for it.\n\n"
                + (f"The index did match {len(theirs)} file(s), but every one is third-party code or "
                   "documentation we cloned to review (" + ", ".join(sorted(theirs)[:3]) + "). "
                   if theirs else
                   "The index matched nothing of ours: the only rows were third-party material or this "
                   "chat's own transcripts. ")
                + "Upstream repos use placeholder org names like acme-corp, example.com and foo-bar "
                "throughout their docs, so those matches are facts about THAT repo and say nothing about "
                "our work. They are withheld here for that reason.\n\n"
                "Tell the user we have nothing on this. Do not answer from that file. If the user wants "
                "that vendor repo searched anyway, run hunt_search again without the handle in the query.")
    notes = []
    if missing:
        notes.append("NOTE: there is no targets/" + ", no targets/".join(missing) + " in this workspace, so "
                     + ("these are" if len(missing) > 1 else "this is") + " not one of our engagements.")
    if theirs:
        notes.append(f"NOTE: {len(theirs)} hit(s) are THIRD-PARTY code or documentation we cloned to review "
                     "(recon/source, vendor, node_modules), not our notes. Upstream docs are full of example "
                     "names and placeholder orgs. Name the file if you cite one.")
    if env.get("HQ_TARGET"):
        notes.append(f"NOTE: rows are limited to {mine} (the active programme) and workspace-wide docs; another "
                     "programme's captures are not routes here. Name that programme in the query to search it.")
    return _spill(text + ("\n\n" + "\n".join(notes) if notes else ""), "hq")


def _rescue_ops_quoting(args):
    """`gnoc video edit <id> --ops '<json>'` whose JSON holds an apostrophe ("nobody's"): shlex takes that
    apostrophe as the closing quote and fails with "No closing quotation". The JSON is the one place a quote
    legitimately appears inside the quotes, so take the span from the first quote after --ops to the LAST
    quote as one token, and accept it only if it parses as JSON. None when the line is not that shape."""
    (
        json, re, shlex,
    ) = bind(
        "json", "re", "shlex",
    )
    m = re.match(r"^(.*?--ops(?:=|\s+))(['\"])(.*)\2(\s.*)?$", str(args or ""), re.S)
    if not m:
        return None
    head, _q, body, tail = m.groups()
    try:
        json.loads(body)
        return shlex.split(head.strip()) + [body] + (shlex.split(tail) if tail and tail.strip() else [])
    except ValueError:
        return None


def _gnoc_class(args):
    """'deny' (interactive / filing), 'read' (no approval), 'control' (fleet or loop control: always asks),
    'write' (asks unless /auto), 'badquote' (the line cannot be split: say so, it is not a policy refusal)."""
    (
        GNOC_CONTROL, GNOC_DENY, GNOC_MUTATING, GNOC_READONLY, GNOC_SUB_READONLY,
        _rescue_ops_quoting, shlex,
    ) = bind(
        "GNOC_CONTROL", "GNOC_DENY", "GNOC_MUTATING", "GNOC_READONLY", "GNOC_SUB_READONLY",
        "_rescue_ops_quoting", "shlex",
    )
    try:
        w = shlex.split(str(args or ""))
    except ValueError:
        # Reported as "interactive or a filing action" until 2026-10-25, which sent the agent into three
        # identical retries of a video edit whose only fault was an apostrophe in a caption.
        w = _rescue_ops_quoting(args)
        if w is None:
            return "badquote", []
    if not w or w[0] in GNOC_DENY:
        return "deny", w
    if tuple(w[:2]) in GNOC_SUB_READONLY and not any(x in GNOC_MUTATING for x in w[2:]):
        return "read", w
    if w[0] in GNOC_READONLY and not any(x in GNOC_MUTATING for x in w[1:]):
        return "read", w
    if w[0] in GNOC_CONTROL:
        return "control", w
    return "write", w


def t_gnoc(ctx, args):
    # D52 (drive cycle 19, 2026-10-26 05:47Z): gnoc(args='hypothesis H18 status=lead evidence=...') four times; the
    # CLI has no such command and the answer ("unknown command") sent the lead back for another try.
    (
        VIDEO_RENDER_LIMIT_S, WS, _ANSI, _gnoc_class, _run_group, _spill,
        _video_render_words, gnoc_secrets, os, re, root, subprocess,
    ) = bind(
        "VIDEO_RENDER_LIMIT_S", "WS", "_ANSI", "_gnoc_class", "_run_group", "_spill",
        "_video_render_words", "gnoc_secrets", "os", "re", "root", "subprocess",
    )
    if re.match(r"\s*hypothes", str(args or ""), re.I):
        return ("refused: the gnoc CLI has no hypothesis command; the ledger is the hunt_hypothesis tool: "
                "hunt_hypothesis(action=update, id=H#, status=lead|dead|unfired, evidence=<raw capture>, notes=...) "
                "or hunt_hypothesis(action=list). Its gates are the same either way.")
    kind, w = _gnoc_class(args)
    if kind == "badquote":
        return ("refused: the shell quoting of `gnoc " + str(args)[:120] + "...` does not close (an apostrophe or quote "
                "inside a quoted argument ends it early). Fix the quoting: write the JSON to a file with write_file "
                "and pass --ops-file <path>, or drop the apostrophe. This is a syntax problem, not a policy refusal.")
    if kind == "deny":
        return f"refused: `gnoc {args}` is interactive or a filing action; the user runs that themselves"
    if w[0] == "leads" and "--once" not in w:
        w.append("--once")
    if w[0] == "video":
        # The agent works in root() (a repo, a target folder, a video project) but this subprocess runs in
        # WS, so a file the agent just wrote and named relatively (`--ops-file gnoc-ops.json`) was "not
        # found" by gnoc video, and the model looped on rewriting it (2026-10-25). Resolve such a token
        # against root() when that is where it exists.
        here = root()
        w = [os.path.join(here, x) if (x and not x.startswith("-") and not os.path.isabs(x)
                                       and os.path.isfile(os.path.join(here, x))
                                       and not os.path.exists(os.path.join(WS, x))) else x for x in w]
    try:
        # A video render (1080p, voice, two formats) is minutes of work by design, and the 300 s cap killed
        # one mid-encode (2026-10-25); every other gnoc command stays on the short leash.
        limit = VIDEO_RENDER_LIMIT_S if _video_render_words(w) else 300
        r = _run_group([os.path.join(WS, "scripts/gnoc")] + w, capture_output=True, text=True, timeout=limit,
                           cwd=WS, env=gnoc_secrets.child_env({"GNOC_PLAIN": "1"}), stdin=subprocess.DEVNULL)  # T1.7
    except subprocess.TimeoutExpired:
        return f"`gnoc {' '.join(w)}` TIMED OUT after {limit}s and was killed; check its state with `gnoc status`"
    out = _ANSI.sub("", (r.stdout or "") + (r.stderr or ""))
    if not r.returncode and w and w[0] in ("stop", "pause"):
        # `gnoc stop` stops the fleet; it must also end this chat's hunt stance, or the next message still runs
        # with the hunt prompt and the hunt toolset. On 2026-11-17 "please stop all hunting" set the STOP flag and
        # left the stance on, so the greeting after it was a hunt turn.
        if isinstance(getattr(ctx, "s", None), dict):
            ctx.s.pop("stance", None)
    if r.returncode:
        # The exit code used to be reported only when there was NO output, so a failed `gnoc video ...` whose
        # child printed its usage text read as a success and the agent moved on to edit a video that was never
        # built (2026-10-25). Say it in words the model acts on.
        out = (out.rstrip() + "\n" if out.strip() else "") + f"[gnoc {w[0]} FAILED: exit {r.returncode}. Read the output above for the reason; do not repeat the same call]"
    return _spill(out, "gnoc")


def resolve_program(name, strict=False):
    """'META', 'meta', 'program-64', or a path under targets/<program>/ -> the program handle, else None.
    Exact first, then case-insensitive, then a UNIQUE prefix / substring match among intaken programs.
    strict: no prefix / substring tier. For scanning the words of free text, where a substring match turns
    English into a target: "make all tests pass" -> program-53 ("all"), "pass ci" -> 1vault (2026-10-24)."""
    (
        WS, os, re,
    ) = bind(
        "WS", "os", "re",
    )
    name = (name or "").strip().rstrip("/")
    if not name:
        return None
    m = re.search(r"(?:^|/)targets/([^/]+)", os.path.realpath(os.path.expanduser(name)) if "/" in name else "")
    if m:
        name = m.group(1)
    try:
        progs = [d for d in os.listdir(os.path.join(WS, "targets"))
                 if os.path.isfile(os.path.join(WS, "targets", d, "SCOPE.txt"))]
    except OSError:
        return None   # a fresh workspace has no targets/ yet: free text is not a program
    low = name.lower()
    tests = [lambda d: d == name, lambda d: d.lower() == low,
             lambda d: re.split(r"[-_]", d.lower())[0] == low]  # META -> program-64 (first word of the handle)
    if not strict:
        tests += [lambda d: d.lower().startswith(low), lambda d: low in d.lower()]
    for test in tests:
        hits = [d for d in progs if test(d)]
        if len(hits) == 1:
            return hits[0]
    return None


def clear_program(ctx):
    """No active program: probes need one named again. A working dir inside that program's folder goes back to
    the workspace root (another repo stays where it is)."""
    (
        WS, _ACTIVE_ROOT, _rel_home, gnoc_goal, os, root,
    ) = bind(
        "WS", "_ACTIVE_ROOT", "_rel_home", "gnoc_goal", "os", "root",
    )
    prog = ctx.s.pop("program", None)
    ctx.s.pop("collab", None)   # a cleared engagement never keeps authorizing hosts in the background
    ctx.s.pop("program_src", None)
    if not prog:
        return "no program was set"
    moved = ""
    pdir = os.path.join(WS, "targets", prog)
    if root() == pdir or root().startswith(pdir + os.sep):
        _ACTIVE_ROOT[0] = WS
        ctx.s["repo"] = None
        gnoc_goal.scope_to(WS)  # back in the hunt workspace: the global hunt goal again
        moved = f"; working directory -> {_rel_home(WS)}"
    return f"program {prog} cleared{moved}"


def _own_site_note(name):
    """The answer for a hunt-ledger call naming the user's OWN site, or None. "can we hunt your-site.example" walked
    set_program -> "intake it first: gnoc pivot" -> HackerOne 401 -> write_file targets/your-site.example/SCOPE.txt
    (2026-11-27). Their site is not a bounty program: it has no SCOPE.txt to intake, and its tools already exist."""
    import re as _re
    if not name:
        return None
    try:
        import gnoc_site
        pub = (gnoc_site._env().get("PUBLIC_URL") or "")
    except Exception:  # noqa: BLE001 - no site configured is "not his site"
        pub = ""
    host = _re.sub(r"^https?://", "", pub).split("/")[0].lower()
    n = _re.sub(r"^https?://", "", str(name).strip().lower()).split("/")[0]
    apex = host.split(".", 1)[-1] if host.count(".") > 1 else host
    if not host or n not in (host, apex):
        return None
    return (f"{n} is the user's OWN site, not a bounty program: there is no SCOPE.txt to intake and nothing to pivot "
            "to (do not create one). Hunt it with site_redteam (the live drill: authz, headers, Host, CORS, cookies, "
            "traversal, errors, store, edge; checks=limits only when the user asks for the loud burst) and site_status "
            "(posture, users, database). Call site_redteam now.")


def t_set_program(ctx, program):
    (
        WS, _graph_import_scope, _read, change_dir, gnoc_collab, gnoc_dedup, gnoc_pay,
        os, resolve_program, root, valid_handle,
    ) = bind(
        "WS", "_graph_import_scope", "_read", "change_dir", "gnoc_collab", "gnoc_dedup",
        "gnoc_pay", "os", "resolve_program", "root", "valid_handle",
    )
    own = _own_site_note(program)
    if own:
        return own
    program = resolve_program(program) or str(program or "")
    if not valid_handle(program) or not os.path.isfile(os.path.join(WS, "targets", program, "SCOPE.txt")):
        return f"no targets/{program}/SCOPE.txt; intake it first: gnoc pivot {program}, or scripts/intake.sh"
    ctx.s["program"] = program
    if gnoc_collab.is_profile(program, WS):
        data = gnoc_collab.profile(program, WS) or {}
        ctx.s["collab"] = {k: data.get(k) for k in
                           ("program", "project", "handoff", "handoff_rel", "sha256", "hosts", "out",
                            "paperwork", "scope_ok", "imported")}
        ctx.s["program_src"] = {"program": program, "how": "set with /program (collaborator engagement)",
                                "sid": ctx.s.get("sid")}
        proj = str(data.get("project") or "")
        moved = ""
        if proj and os.path.isdir(proj) and not (root() == proj or root().startswith(proj + os.sep)):
            # the engagement's work lives in the partner's project, not in targets/<handle>
            moved = "\n" + change_dir(ctx, proj, f"collab {program}")
        _graph_import_scope(program)
        return f"active program -> {program} (collaborator engagement){moved}\n" + gnoc_collab.summary(program, WS)
    ctx.s.pop("collab", None)
    pdir = os.path.join(WS, "targets", program)
    moved = ""
    _graph_import_scope(program)
    if not (root() == pdir or root().startswith(pdir + os.sep)):
        # hunting happens in the program's folder: leave another repo (the website) or another target behind
        moved = "\n" + change_dir(ctx, pdir, f"hunt {program}")
    return (f"active program -> {program}{moved}\n{gnoc_dedup.program_summary(program)}\n"
            + gnoc_pay.summary(program, offline=True) + "\nScope rows:\n"
            + "\n".join(_read(os.path.join(WS, "targets", program, "SCOPE.txt")).splitlines()[:40]))


def _target_handles():
    """Every intaken program: a folder under targets/ that has a SCOPE.txt."""
    (
        WS, os,
    ) = bind(
        "WS", "os",
    )
    tdir = os.path.join(WS, "targets")
    try:  # a '_'-prefixed folder is a fixture (targets/program-08), never a program to hunt
        return sorted(d for d in os.listdir(tdir)
                      if not d.startswith("_") and os.path.isfile(os.path.join(tdir, d, "SCOPE.txt")))
    except OSError:
        return []


def _list_first_tokens(path):
    """First whitespace token of each non-comment line (the program handle in priority / no-yield files),
    in order, mapped to the line's trailing annotation."""
    (
        _read,
    ) = bind(
        "_read",
    )
    out = {}
    for ln in _read(path).splitlines():
        s = ln.strip()
        if s and not s.startswith("#"):
            tok = s.split()[0]
            if tok not in out:
                out[tok] = s[len(tok):].lstrip(" :-#").strip()
    return out


def _scope_row_count(program):
    (
        WS, _read, os,
    ) = bind(
        "WS", "_read", "os",
    )
    return sum(1 for ln in _read(os.path.join(WS, "targets", program, "SCOPE.txt")).splitlines()
               if ln.strip() and not ln.strip().startswith("#"))


def rank_targets(exclude=None):
    """Score every intaken target as a NEXT-to-hunt candidate from on-disk signals only (no network):
    H1/VDP rotation-queue position, scope breadth, freshness (never hunted or cooled off beats just-worked),
    and dead-vector load. Walled / fee / policy-gated targets (no-yield.txt) are dropped outright, so a pick
    is never one an agent must not touch. Returns rows sorted best-first, each with its reasons."""
    (
        WS, _DNR_DIR, _HUNT_STATE, _age_days, _list_first_tokens, _read,
        _scope_row_count, _target_handles, gnoc_collab, gnoc_pay, os,
    ) = bind(
        "WS", "_DNR_DIR", "_HUNT_STATE", "_age_days", "_list_first_tokens", "_read",
        "_scope_row_count", "_target_handles", "gnoc_collab", "gnoc_pay", "os",
    )
    noyield = _list_first_tokens(os.path.join(_HUNT_STATE, "no-yield.txt"))
    pri = list(_list_first_tokens(os.path.join(_HUNT_STATE, "priority.txt")))
    vdp = list(_list_first_tokens(os.path.join(_HUNT_STATE, "priority-vdp.txt")))
    pri_rank = {p: i for i, p in enumerate(pri)}
    vdp_rank = {p: i for i, p in enumerate(vdp)}
    rows = []
    for p in _target_handles():
        if (exclude and p == exclude) or p in noyield:
            continue
        if gnoc_collab.is_profile(p, WS):
            continue   # a collaborator engagement is picked by its project folder, not by bounty EV
        scope_rows = _scope_row_count(p)
        ddir = os.path.join(WS, "reports/drafts", p)
        drafts = sum(1 for d in os.listdir(ddir) if os.path.isdir(os.path.join(ddir, d))) if os.path.isdir(ddir) else 0
        dfile = os.path.join(_DNR_DIR, p + ".txt")
        dead = sum(1 for ln in _read(dfile).splitlines() if ln.strip() and not ln.strip().startswith("#")) \
            if os.path.isfile(dfile) else 0
        last_hunt = _age_days(os.path.join(WS, "targets", p, "hunts"))
        score, reasons = 0.0, []
        if p in pri_rank:
            score += max(0, 40 - pri_rank[p]); reasons.append(f"H1 queue #{pri_rank[p] + 1}")
        elif p in vdp_rank:
            score += max(0, 25 - vdp_rank[p]); reasons.append(f"VDP queue #{vdp_rank[p] + 1}")
        score += min(scope_rows, 30) * 0.4; reasons.append(f"{scope_rows} scope rows")
        if last_hunt is None:
            score += 10; reasons.append("never hunted (fresh ground)")
        elif last_hunt > 14:
            score += 5; reasons.append(f"cooled {int(last_hunt)}d")
        elif last_hunt < 1:
            score -= 5; reasons.append("hunted <1d ago")
        else:
            reasons.append(f"hunted {int(last_hunt)}d ago")
        if dead:
            score -= min(dead, 25) * 0.25; reasons.append(f"{dead} dead vector(s)")
        if drafts:
            reasons.append(f"{drafts} draft(s) on disk")
        # money and filing, from disk only (the cached team flags; never a network call inside a ranking)
        fok, fwhy = gnoc_pay.filing_gate(p, offline=True)
        if not fok:
            score -= 100; reasons.append("BLOCKED: " + fwhy[:80])
        else:
            any_b, b, nb, _ = gnoc_pay.program_pays(p)
            team = gnoc_pay.h1_team(p, offline=True) or {}
            if any_b is False or team.get("offers_bounties") is False:
                score -= 8; reasons.append("VDP: no payout (a resolved filing still earns signal)")
            elif b:
                reasons.append(f"{b} bounty row(s)")
            if team.get("granular_signal"):
                reasons.append(f"signal gate clears (target {team.get('target_signal')})")
        rows.append({"program": p, "score": round(score, 1), "reasons": reasons})
    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows


def t_pick_target(ctx, switch=True, n=10, kind="target"):
    """Analyze every intaken target, rank the best next one, and (by default) switch to the top pick."""
    (
        WS, _read, os, rank_targets, t_set_program,
    ) = bind(
        "WS", "_read", "os", "rank_targets", "t_set_program",
    )
    if kind == "surface":
        if not ctx.program:
            return "no active program: set one first, then pick a surface from its scope"
        rows = [ln for ln in _read(os.path.join(WS, "targets", ctx.program, "SCOPE.txt")).splitlines()
                if ln.strip() and not ln.strip().startswith("#")]
        return (f"{ctx.program} has {len(rows)} in-scope surface(s); pick one to hunt (program unchanged):\n"
                + "\n".join(f"  - {r}" for r in rows[:60]))
    ranked = rank_targets(exclude=ctx.program)
    if not ranked:
        return "no other intaken target has a SCOPE.txt; intake one first (gnoc pivot <program> / scripts/intake.sh)"
    top = ranked[:max(1, min(int(n or 10), 50))]
    if isinstance(switch, str):  # 'false' is truthy: never switch the hunt target on a string that says no
        switch = switch.strip().lower() in ("true", "1", "yes")
    table = (f"Ranked {len(ranked)} candidate target(s)"
             + (f", current {ctx.program} excluded" if ctx.program else "") + ":\n"
             + "\n".join(f"{i + 1}. {r['program']}  [{r['score']}]  {', '.join(r['reasons'])}"
                         for i, r in enumerate(top)))
    if not switch:
        return table + "\n\nTo change to one, call set_program <program> (or pick_target with switch=true for #1)."
    pick = ranked[0]["program"]
    return f"picked {pick} (best of {len(ranked)} by EV)\n\n{table}\n\n{t_set_program(ctx, pick)}"


def _dir_from(path):
    """Resolve a directory the user named: absolute, ~, relative to the current dir, relative to the workspace,
    relative to home (`/dir .gnoc` from anywhere), a sibling of the current dir, or a bare program
    name (META -> targets/program-64)."""
    (
        WS, os, resolve_program, root,
    ) = bind(
        "WS", "os", "resolve_program", "root",
    )
    raw = os.path.expanduser((path or "").strip().strip("'\""))
    cands = [raw] if os.path.isabs(raw) else [os.path.join(root(), raw), os.path.join(WS, raw),
                                              os.path.join(os.path.expanduser("~"), raw),
                                              os.path.join(os.path.dirname(root()), raw)]
    prog = resolve_program(raw) if raw and "/" not in raw else None
    if prog:
        cands.append(os.path.join(WS, "targets", prog))
    for c in cands:
        if os.path.isdir(c):
            return os.path.realpath(c)
    return None


def write_gchat(ctx, d, task=""):
    """Start a fresh gchat.md in the working dir, or a new dated session block in an existing one (never
    overwritten: earlier sessions are the record). Returns a one-line note."""
    (
        GCHAT, _NO_NOTES, _now, _rel_home, gnoc_secrets, os,
    ) = bind(
        "GCHAT", "_NO_NOTES", "_now", "_rel_home", "gnoc_secrets", "os",
    )
    task = gnoc_secrets.redact(task or "")
    f = os.path.join(d, GCHAT)
    if _NO_NOTES.search(d + "/"):
        return f"(no {GCHAT}: {_rel_home(d)} looks like a served/build folder)"
    if os.path.realpath(d) == os.path.realpath(os.path.expanduser("~")):
        return f"(no {GCHAT} in ~: notes go in a project folder)"
    stamp = _now().strftime("%Y-%m-%d %H:%MZ")
    block = (f"## Session {stamp}\n\n**Task:** {task or '(not stated yet)'}\n**Program:** {ctx.program or '-'}\n"
             f"**Directory:** {d}\n\n### State\n- started\n\n### Log\n- {stamp} entered {_rel_home(d)}\n\n"
             "### Next\n- \n")
    try:
        if os.path.isfile(f):
            with open(f, "a") as fh:
                fh.write("\n" + block)
            return f"{GCHAT}: new session block appended"
        with open(f, "w") as fh:
            fh.write(f"# gchat - {os.path.basename(d)}\n\nWorking notes kept by gnoc chat for this directory: what "
                     "it is doing here, what it found, and what comes next. Each session adds a block; keep "
                     "State and Next current, append to Log.\n\n" + block)
        return f"{GCHAT}: written"
    except OSError as e:
        return f"(could not write {GCHAT}: {e})"


def change_dir(ctx, d, task=""):
    """Move the agent's working directory (no history reset: the conversation carries over)."""
    (
        PLAIN, WS, _ACTIVE_ROOT, _graph_import_scope, _system_root, gnoc_collab,
        gnoc_goal, os, repo_is_live, resolve_program, write_gchat,
    ) = bind(
        "PLAIN", "WS", "_ACTIVE_ROOT", "_graph_import_scope", "_system_root",
        "gnoc_collab", "gnoc_goal", "os", "repo_is_live", "resolve_program", "write_gchat",
    )
    home = os.path.expanduser("~")
    rd = os.path.realpath(d)
    if rd == "/tmp" or _system_root(rd) \
            or any(rd == os.path.join(home, s) or rd.startswith(os.path.join(home, s) + os.sep)
                   for s in (".config", ".ssh", ".claude", ".gnupg", ".local", ".cache", ".mozilla")):
        # the working dir is what read/write/bash are contained to: never a system root or a credential store
        # (`/home` and `~/.config` were accepted once, which exposed .credentials.json). ~ itself is allowed
        # since 2026-11-06, the same as a launch from ~; the secret guards keep its credential files out.
        return f"refused: {d} is not a project directory (a system root or a credential store)"
    _ACTIVE_ROOT[0] = d
    ctx.s["repo"] = None if d == WS else d
    gnoc_goal.scope_to(d)  # moving to another repo moves to that repo's own goal (WS -> the global hunt goal)
    prog = resolve_program(d) if "/targets/" in d + "/" else None
    note = ""
    if prog and prog != ctx.program:
        ctx.s["program"] = prog
        note = f"; active program -> {prog}"
        _graph_import_scope(prog)
    if not PLAIN[0]:
        old_collab = ctx.s.get("collab") or {}
        proj = str(old_collab.get("project") or "")
        if old_collab and not (proj and (d == proj or d.startswith(proj + os.sep))):
            ctx.s.pop("collab", None)
            if ctx.program == old_collab.get("program"):
                ctx.s.pop("program", None)
                ctx.s.pop("program_src", None)
                note += "; left the collaborator engagement"
        if not d.startswith(os.path.join(WS, "targets") + os.sep):
            got = gnoc_collab.attach(ctx, d)
            if got and got.get("ok"):
                note += (f"; collaborator engagement -> {got['program']} "
                         f"({len(got.get('hosts') or [])} in scope)")
                _graph_import_scope(got["program"])
            elif got and not got.get("ok"):
                note += f"; collaborator handoff NOT imported: {str(got.get('reason'))[:120]}"
    gnote = write_gchat(ctx, d, task)
    live = "; this checkout is served live by pm2, every change asks first" if repo_is_live(d) else ""
    return f"working directory -> {d}{note}; {gnote}{live}"


def t_change_dir(ctx, path, task=""):
    (
        WS, _dir_from, _rel_home, change_dir, root,
    ) = bind(
        "WS", "_dir_from", "_rel_home", "change_dir", "root",
    )
    d = _dir_from(path)
    if not d:
        return f"no such directory: {path} (tried it as given, under {_rel_home(root())}, under {WS}, and as a program)"
    return change_dir(ctx, d, task)


def t_site_status(ctx, section="overview", refresh=False):
    """The user's OWN website, read live from its own endpoints. Nothing here touches a bounty program."""
    (
        _truthy, gnoc_site,
    ) = bind(
        "_truthy", "gnoc_site",
    )
    try:
        return gnoc_site.summary(section, force=_truthy(refresh))
    except Exception as e:  # noqa: BLE001 - a site that cannot be read is an answer, not a dead turn
        return f"could not read the site: {type(e).__name__}: {e}"


def t_site_redteam(ctx, checks=None, area=None, confirm=False):
    """An authorized drill against the user's OWN site. Read-only; it cannot be pointed anywhere else.

    confirm fires the LOUD check (a burst at the live site). The model asked for it on its own initiative the
    first day this existed - in skip-perms, where no approval prompt stands in the way - so confirm is only
    honoured when the user's OWN words this turn asked for something loud. The model cannot talk its way past
    this: the test is on their text, not on the model's argument."""
    (
        _LOUD_ASK, _truthy, gnoc_redteam, re,
    ) = bind(
        "_LOUD_ASK", "_truthy", "gnoc_redteam", "re",
    )
    if isinstance(checks, str):
        checks = [c.strip() for c in re.split(r"[,\s]+", checks) if c.strip()]
    if checks:
        # checks='all' (defense batch 25) is the default drill, not an unknown check. Drop an alias
        # ANYWHERE in the list: "all,headers" was refused as "unknown check(s) all" (1000-turn drive
        # 2026-11-24), and dropping just the alias leaves the real checks the model named.
        _alias = {"all", "everything", "full", "default", "drill"}
        _kept = [c for c in checks if str(c).lower() not in _alias]
        checks = _kept or None
    bad = [c for c in (checks or []) if c not in gnoc_redteam.CHECKS]
    if bad:
        return f"unknown check(s) {', '.join(bad)}: use any of {', '.join(gnoc_redteam.CHECKS)}"
    loud = _truthy(confirm)
    note = ""
    if loud:
        # HIS words only. _turn_text can carry a trailing [gnoc: ...] hint, and the red-team hint itself
        # says "never the loud 'limits' burst" - matching that text made every "red team the site" turn
        # authorise the burst the hint forbids (1000-turn drive 2026-11-24).
        _his = re.split(r"\n\s*\[gnoc:", str((getattr(ctx, "s", None) or {}).get("_turn_text") or ""))[0]
        asked = _LOUD_ASK.search(_his)
        if not asked:
            # FIRST, not last: as a closing NOTE it sat under 40 lines of results and the lead answered "the loud
            # burst was run this time - rate limits tested" on three "continue" turns in a row (2026-11-27).
            loud, note = False, ("RATE LIMITS WERE NOT TESTED THIS TURN: the loud burst was NOT run. confirm=true "
                                 "was refused because the user did not ask for the burst in their own words. Do not "
                                 "say it ran or that rate limits were tested. Sending confirm=true again (on "
                                 "\"continue\" or any turn the user does not ask) changes nothing: tell them it is "
                                 "available and what it does, and run it when the user says so.\n\n")
    try:
        return note + gnoc_redteam.summary(checks or None, confirm=loud, area=area)
    except Exception as e:  # noqa: BLE001 - a drill that cannot run is an answer, not a dead turn
        return f"the drill could not run: {type(e).__name__}: {e}"


def _turn_program(ctx):
    """The one program handle this turn names, when exactly one is named and it is not the active one.

    Two passes, both narrow on purpose. A bare token counts only when it IS a handle (exact, or case-only),
    which is why "probe bravo now" is caught without a preposition. The first-word tier ("meta" -> program-64)
    is allowed only right after a preposition, because on its own it turns English into a target: "the common
    case" would otherwise resolve to program-32 and refuse an unrelated write."""
    (
        WS, _PROG_IN_TEXT, os, re, resolve_program,
    ) = bind(
        "WS", "_PROG_IN_TEXT", "os", "re", "resolve_program",
    )
    text = str((ctx.s or {}).get("_turn_user") or "")
    if not text:
        return None
    try:
        handles = {d.lower(): d for d in os.listdir(os.path.join(WS, "targets"))
                   if os.path.isfile(os.path.join(WS, "targets", d, "SCOPE.txt"))}
    except OSError:
        return None
    seen = []
    for tok in re.findall(r"[A-Za-z0-9][\w.-]*", text):
        p = handles.get(tok.lower())
        if p and p not in seen:
            seen.append(p)
    for m in _PROG_IN_TEXT.finditer(text):
        # strict: no prefix or substring tier, or English words resolve to programs ("all" -> program-53)
        p = resolve_program(m.group(1), strict=True)
        if p and p not in seen:
            seen.append(p)
    if len(seen) != 1 or seen[0] == ctx.program:
        return None
    return seen[0]


def _program_gate_write(ctx, what):
    """The refusal a ledger WRITE gets when the turn is about another program."""
    (
        _turn_program,
    ) = bind(
        "_turn_program",
    )
    other = _turn_program(ctx)
    if not other:
        return None
    if not ctx.program:
        # NO sticky program means there is no OTHER ledger to mis-file into: _read_program resolves the
        # turn's program and the write lands where it was asked for. Refusing here told the model that
        # adding a program-63 hypothesis "would land on the wrong target's ledger" when the active program
        # was None - a refusal naming no real risk, which is the other half of the _need_program defect
        # above (measured 2026-11-03, same lane).
        return None
    return (f"refused: this turn is about {other}, but the active program is {ctx.program}, so {what} would land on "
            f"the wrong target's ledger. Call set_program(program='{other}') first, then repeat this call. (Measured "
            "2026-10-25: a hypothesis asked for on program-101 was written into program-64.)")


def _read_program(ctx):
    """(program, note) for a ledger READ: the program the turn names wins over the sticky one, and the note says
    so, because an answer from the wrong ledger reads exactly like an answer from the right one."""
    (
        _turn_program,
    ) = bind(
        "_turn_program",
    )
    other = _turn_program(ctx)
    if not other:
        return ctx.program, ""
    return other, (f"[this turn names {other}; the active program is {ctx.program}, so the rows below are "
                   f"{other}'s. set_program(program='{other}') to make it active.]\n")


def _need_program(ctx):
    """The refusal when NO program can be resolved for this call at all.

    It used to test ONLY the sticky ctx.program, while _read_program two lines down in every caller
    already resolves the program the TURN names. So on a conversation with no sticky program every
    ledger call died with "no active program" even when the turn named one by handle. Measured
    2026-11-03: a resumed program-63 conversation carried no sticky program, the two hypotheses the
    turn asked for by name were refused, and the lane fired nothing for two turns while the model
    read the refusal as "the ledger is unavailable"."""
    (
        _turn_program,
    ) = bind(
        "_turn_program",
    )
    if ctx.program or _turn_program(ctx):
        return None
    return "no active program: set_program first"


def t_hunt_brief(ctx, program=None):
    # D48 (drive cycle 18): the lead called hunt_brief 15 times in one cycle, three in a row twice, re-reading the
    # same ~65 lines; like hypothesize, it answers once per turn and then points at the answer it already gave.
    (
        _hunt_brief_body,
    ) = bind(
        "_hunt_brief_body",
    )
    turn = str((getattr(ctx, "s", None) or {}).get("_turn_user") or "")
    key = f"{program or getattr(ctx, 'program', '')}"
    if turn and (ctx.s or {}).get("_briefed_for") == (turn, key):
        return ("refused: hunt_brief for this program already ran this turn and nothing changed since; its answer "
                "is above in this turn. Use hunt_hypothesis(action=list) for the live ledger or read_file on a "
                "specific path. Probe, then ask again next turn.")
    if turn:
        ctx.s["_briefed_for"] = (turn, key)
    return _hunt_brief_body(ctx, program)


def _hunt_brief_body(ctx, program=None):
    (
        gnoc_hunt, gnoc_pay, resolve_program,
    ) = bind(
        "gnoc_hunt", "gnoc_pay", "resolve_program",
    )
    own = _own_site_note(program)
    if own:
        return own
    prog = (resolve_program(program) if program else None) or ctx.program
    if not prog:
        return "no active program: set_program first"
    ctx.s.setdefault("briefed", {})[prog] = True
    pay = gnoc_pay.summary(prog, offline=True)
    return (pay + "\n\n" if pay else "") + gnoc_hunt.brief(prog)


def t_hunt_phase(ctx, program=None):
    """Read-only: the directive the hunt loop would give THIS program right now, and why that phase.

    Measured 2026-10-25: asked which phase program-32 was in, the lead made 18 tool calls on 417k tokens,
    never reached the directive (only /hunt runs it, and that starts hunting) and answered with an invented
    "Phase 3, the preparation phase". The phase is one function call; this is it."""
    (
        _turn_program, gnoc_hunt, re, resolve_program,
    ) = bind(
        "_turn_program", "gnoc_hunt", "re", "resolve_program",
    )
    prog = (resolve_program(program) if program else None) or _turn_program(ctx) or ctx.program
    if not prog:
        return "no active program: set_program first"
    try:
        text = gnoc_hunt.directive(prog, briefed=bool((ctx.s.get("briefed") or {}).get(prog)), peek=True)
    except TypeError:   # an older gnoc_hunt without peek=: fall back, and say the counters moved
        text = gnoc_hunt.directive(prog, briefed=bool((ctx.s.get("briefed") or {}).get(prog)))
    m = re.search(r"PHASE ([A-Z]+(?: [A-Z+]+)*)", text)
    head = f"{prog}: PHASE {m.group(1)}\n" if m else f"{prog}:\n"
    return head + "the directive in force (read-only; /hunt is what executes it):\n" + text


def _add_refusal_example(ctx, prog, action, out):
    """F3 2026-11-09: the lead looped hunt_hypothesis add 11 times in one turn on the same refusal. From the third
    identical refusal in a turn, append ONE violation built from the program's existing routes that the gates
    accept, so there is a passing shape to copy."""
    (
        ADD_REFUSALS_FOR_EXAMPLE, gnoc_hunt,
    ) = bind(
        "ADD_REFUSALS_FOR_EXAMPLE", "gnoc_hunt",
    )
    if str(action or "").lower() != "add" or not str(out or "").lstrip().startswith("refused"):
        return out
    st = getattr(ctx, "s", None)
    if not isinstance(st, dict):
        return out
    key = f"{st.get('_turn_user') or ''}|{prog}|{str(out).strip()[:160]}"
    d = st.setdefault("_add_refusals", {})
    d[key] = int(d.get(key) or 0) + 1
    if d[key] < ADD_REFUSALS_FOR_EXAMPLE:
        return out
    try:
        ex = gnoc_hunt.accepted_example(prog)
    except Exception:  # noqa: BLE001 - an example is a hint, never a failure
        ex = ""
    if not ex:
        return out
    return (out + f"\n  refused {d[key]} times this turn. A shape these gates accept on {prog}: "
            f"violation='{ex}' (swap in your route from the known routes and your mutated field).")


def t_hunt_hypothesis(ctx, action="list", id=None, title=None, crown=None, assumption=None, violation=None,
                      prediction=None, kill_byte=None, status=None, notes=None, evidence=None, burst=None,
                      boundary=None, requires=None):
    (
        PROMO_REFUSALS_PER_TURN, _add_refusal_example, _need_program,
        _program_gate_write, _read_program, gnoc_hunt, re,
    ) = bind(
        "PROMO_REFUSALS_PER_TURN", "_add_refusal_example", "_need_program",
        "_program_gate_write", "_read_program", "gnoc_hunt", "re",
    )
    need = _need_program(ctx)
    if need:
        return need
    if str(action or "").lower() in ("add", "update", "set"):
        refused = _program_gate_write(ctx, "a hypothesis")
        if refused:
            return refused
    prog, note = _read_program(ctx)
    promo = str(action or "").lower() == "update" and str(status or "").lower() in ("lead", "candidate")
    key = None
    if promo:   # D92 (cycle 25, 10:58Z): four refused LEADs on H45 in one turn, nine on H40 earlier; the decision
        #          tools are exempt from the streak breaker, so this is the stop for promotion loops
        key = f"{ctx.s.get('_turn_user') or ''}|{prog}|{gnoc_hunt.canonical_hyp_id(prog, id) if id else id}"
        n = int((ctx.s.setdefault("_promo_refusals", {})).get(key) or 0)
        if n >= PROMO_REFUSALS_PER_TURN:
            return (f"refused: {id} was refused promotion {n} times this turn and nothing has changed. A promotion "
                    "needs a capture whose response shows the mechanism (2xx/3xx carrying the kill byte). Probe it "
                    "for that capture, or park it (hunt_hypothesis action=update status=unfired|dead), or move on.")
    out = gnoc_hunt.hypothesis(prog, action, id, title, crown, assumption, violation,
                               prediction, kill_byte, status, notes, evidence, burst,
                               boundary, requires)
    if key and re.match(r"\s*refused (LEAD|CANDIDATE)", str(out or "")):
        ctx.s["_promo_refusals"][key] = int(ctx.s["_promo_refusals"].get(key) or 0) + 1
    out = _add_refusal_example(ctx, prog, action, out)   # F3: the third identical refusal carries a passing shape
    # EXCLUDED FUNCTIONALITY (2026-10-28). The scope gate checks hosts; nothing checked what the programme
    # put out of scope by FUNCTION. A /hunt program-72 session spent ~40 probes on /ro/user/register while
    # PROGRAM.md line 10 says "All our LOGIN services are out of scope for the moment" - the brief printed
    # that line and nothing acted on it. A warning, never a block: whether "LOGIN services" covers
    # registration is the hunter's judgement, it just has to be made on purpose.
    if str(action or "").lower() in ("add", "update", "set", "list"):
        try:
            from bbtools import lib_policy as _lp
            # On LIST, check the hypotheses ALREADY in the ledger too. They outlive a session, so a
            # hypothesis opened before this gate existed keeps being worked: r4 inherited an H4 aimed at
            # /ro/user/register and went straight back to it one turn after being told LOGIN services are
            # out of scope. Checking only new hypotheses leaves every old one unexamined.
            subject = (" ".join(str(x) for x in (title, crown, assumption, violation, notes) if x)
                       if str(action or "").lower() != "list" else str(out or ""))
            hits = _lp.excluded_match(prog, subject)
            if hits:
                out += ("\n  ! this hypothesis touches what " + prog + " puts OUT OF SCOPE. Decide deliberately "
                        "before spending probes, and say which way you decided:\n"
                        + "\n".join(f"    PROGRAM.md:{ln}  {txt}" for ln, txt, _ in hits))
        except Exception:   # noqa: BLE001 - an advisory must never break the tool
            pass
    return note + out


def t_hunt_edge(ctx, action="add", frm=None, to=None, via=None, status=None, evidence=None, must_contain=None,
                requires=None, id=None, control=None, control_na=None):
    (
        _need_program, _program_gate_write, _read_program, gnoc_hunt,
    ) = bind(
        "_need_program", "_program_gate_write", "_read_program", "gnoc_hunt",
    )
    need = _need_program(ctx)
    if need:
        return need
    if str(action or "").lower() in ("add", "update"):
        refused = _program_gate_write(ctx, "an edge")
        if refused:
            return refused
    prog, note = _read_program(ctx)
    return note + gnoc_hunt.edge(prog, action, frm, to, via, status, evidence, must_contain,
                                 requires, id, control, control_na)


def _copy_tree(src, dst, budget=60_000_000):
    """Copy a repo for sandboxed checks, skipping vendor and VCS dirs. False when it is too big to be worth it."""
    (
        _SKIP_COPY, os, shutil,
    ) = bind(
        "_SKIP_COPY", "os", "shutil",
    )
    total = 0
    for dp, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if not _SKIP_COPY.match(d)]
        rel = os.path.relpath(dp, src)
        os.makedirs(os.path.join(dst, rel), exist_ok=True)
        for f in files:
            sp = os.path.join(dp, f)
            try:
                total += os.path.getsize(sp)
                if total > budget:
                    return False
                shutil.copy2(sp, os.path.join(dst, rel, f))
            except OSError:
                continue
    return True


def _check_runner(r, base=False):
    """Run a reviewer's check command in a THROWAWAY COPY of the repo: a check may import, run and even write,
    because nothing it does reaches the real tree. Commands that reach outside the copy (network, package
    managers, absolute system paths, process control) are refused outright, and each gets 60s.
    base=True: the copy is the committed HEAD (git archive), the code as it was BEFORE the change under review."""
    (
        _CHECK_DENY, _copy_tree, _run_group, gnoc_secrets, os, shutil, subprocess,
        tempfile,
    ) = bind(
        "_CHECK_DENY", "_copy_tree", "_run_group", "gnoc_secrets", "os", "shutil",
        "subprocess", "tempfile",
    )
    box = {"dir": None}

    def run(cmd):
        if _CHECK_DENY.search(cmd or ""):
            raise PermissionError("check command reaches outside the sandbox (network, packages or system paths)")
        if box["dir"] is None:
            d = tempfile.mkdtemp(prefix="gnoc-check-base-" if base else "gnoc-check-")
            if base:
                arch = subprocess.run(["git", "-C", r, "archive", "HEAD"], capture_output=True, timeout=60)
                ok = arch.returncode == 0 and subprocess.run(["tar", "-x", "-C", d], input=arch.stdout,
                                                             capture_output=True, timeout=60).returncode == 0
            else:
                ok = _copy_tree(r, d)
            if not ok:
                shutil.rmtree(d, ignore_errors=True)
                raise RuntimeError("no HEAD to compare against" if base else "repo too large to sandbox")
            box["dir"] = d
        env = gnoc_secrets.child_env(dict(PYTHONDONTWRITEBYTECODE="1", GIT_TERMINAL_PROMPT="0",  # T1.7
                                          PATH=os.environ.get("PATH", ""), HOME=box["dir"], PYTHONPATH=box["dir"]))
        pr = _run_group(["bash", "-c", cmd], cwd=box["dir"], capture_output=True, text=True, timeout=60,
                            stdin=subprocess.DEVNULL, env=env)
        return pr.returncode, (pr.stdout or "") + (pr.stderr or "")

    def cleanup():
        if box["dir"]:
            shutil.rmtree(box["dir"], ignore_errors=True)
    run.cleanup = cleanup
    return run


def _demote_preexisting(r, kept):
    """A CONFIRMED finding whose check fails the SAME way on HEAD is not something the diff did. The reviewer once
    wrote a check asserting main() returns its output (it prints, before and after a rename), it "failed as
    predicted", and the lead obeyed it and broke the CLI (SWE gauntlet 2026-10-24). Demote it to PLAUSIBLE with
    the reason, so the lead weighs it against the request: a pre-existing bug the request asked to fix (a README
    rule) is still fixed, and an invented expectation is not."""
    (
        _check_runner, gnoc_modes, os,
    ) = bind(
        "_check_runner", "gnoc_modes", "os",
    )
    base = _check_runner(r, base=True)
    try:
        for k in kept:
            if k.get("verdict") != "CONFIRMED" or not k.get("check"):
                continue
            path = str(k.get("file") or "")
            mod = os.path.splitext(os.path.basename(path))[0]
            cmd = gnoc_modes.normalize_check(str(k["check"]), (mod,) if path.endswith(".py") else ())
            try:
                code, out = base(cmd)
            except Exception:
                return   # no HEAD (a fresh repo) or no sandbox: nothing to compare, leave the verdicts alone
            if gnoc_modes.check_verdict(code, out)[0] == "confirmed":
                k["verdict"] = "PLAUSIBLE"
                k["note"] = (str(k.get("note") or "") + " | the same check FAILS ON HEAD too, before this diff: the "
                             "behaviour is pre-existing, not introduced by the change. Fix it only if the request "
                             "asks for it.")
    finally:
        base.cleanup()
    kept.sort(key=lambda x: (0 if x["verdict"] == "CONFIRMED" else 1, -(x.get("_agree") or 1),
                             -(x.get("confidence") or 0)))


def _touched_files(diff_text):
    (
        re,
    ) = bind(
        "re",
    )
    return [m.group(1) for m in re.finditer(r"(?m)^\+\+\+ b/(.+)$", diff_text)]


def _test_outcome(call, tool_msg):
    """For a test run (run_tests, or a bash test command): the failure summary ('2/5 passed', 'exit 1'), "" when it
    passed, None when the call was not a test run."""
    (
        TEST_CMD, re,
    ) = bind(
        "TEST_CMD", "re",
    )
    fn = (call or {}).get("function") or {}
    name, args = fn.get("name"), fn.get("arguments") if isinstance(fn.get("arguments"), dict) else {}
    out = str((tool_msg or {}).get("content") or "")
    if name == "run_tests":
        # run_tests now says "1/1 test command passed (this is a count of commands run ...)": the old "1/1 passed"
        # pattern matched nothing, so no run_tests result was ever the latest outcome and an earlier failed
        # `npm test` kept the turn in "its last test run failed; fix it" after two green runs (/goal drive 2026-11-21)
        m = re.match(r"\s*(\d+)/(\d+) (?:test commands? )?passed", out)
        return None if not m else ("" if m.group(1) == m.group(2) else f"{m.group(1)}/{m.group(2)} passed")
    if name == "bash" and TEST_CMD.search(str(args.get("command") or "")):
        m = re.match(r"\s*exit (\d+)", out)
        if not m:
            return None
        if m.group(1) == "0":
            return ""
        tail = re.findall(r"(\d+ failed[^\n]*|FAILED[^\n]{0,80})", out)
        return f"exit {m.group(1)}" + (f": {tail[-1][:100]}" if tail else "")
    return None


def _task_focus(user_text, leftovers=""):
    """The review FOCUS for the turn's own change: judge the diff against the request first. Without it the reviewer
    read the diff alone, flagged "header() crashes if passed a string" on a rename, the lead rewrote header() to
    accept strings, and the rename itself stayed half done (SWE gauntlet 2026-10-24)."""
    (
        re,
    ) = bind(
        "re",
    )
    return ("THE REQUEST this diff is meant to fulfil: " + re.sub(r"\s+", " ", user_text or "")[:600] + "\n"
            "Review against it FIRST: list what the request asks that the diff does not do (a case, a rule from a "
            "spec/README it names, a place it says 'everywhere', a test it asked for). Then real defects the diff "
            "introduces. Do NOT report hypothetical misuse unrelated to the request (an input no caller passes) or "
            "propose behaviour changes the request did not ask for." + (("\n" + leftovers) if leftovers else ""))


def _rename_leftovers(user_text):
    """'rename fmt_name to format_display_name' -> where the OLD name still appears in the repo's code, as one
    line for the review, or "". A rename is complete only when the old identifier is gone; grep knows that exactly."""
    (
        CODE_FILE, _read, os, re, root,
    ) = bind(
        "CODE_FILE", "_read", "os", "re", "root",
    )
    m = re.search(r"\brename\s+`?([A-Za-z_][\w.]*)`?\s+(?:to|->|as)\s+`?([A-Za-z_][\w.]*)`?", user_text or "", re.I)
    if not m:
        return ""
    old = m.group(1).split(".")[-1]
    hits, r = [], root()
    for d, dirs, names in os.walk(r):
        dirs[:] = [x for x in dirs if x not in (".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build")]
        for n in names:
            if not CODE_FILE.search(n):
                continue
            p = os.path.join(d, n)
            for i, ln in enumerate(_read(p).splitlines(), 1):
                if re.search(r"\b" + re.escape(old) + r"\b", ln):
                    hits.append(f"{os.path.relpath(p, r)}:{i}: {ln.strip()[:100]}")
            if len(hits) > 30:
                break
    return (f"CHECK (grep, exact): the old name {old!r} still appears in {len(hits)} place(s) - the rename is not "
            "complete:\n  " + "\n  ".join(hits[:30])) if hits else ""


WORKER_READ_LIMIT = float(__import__("os").environ.get("GNOC_REVIEW_WORKER_LIMIT") or 150)
# A second reader that ran past WORKER_READ_LIMIT is skipped for this long. A CPU-bound 9B worker hit the limit
# on review after review (SWE marathon 2026-11-21), each costing the turn the full 150 s for nothing, and every
# `gnoc chat -p` turn is a new process, so it is remembered on disk (OUT_DIR/review/slow-readers.json).
WORKER_SLOW_FOR = 30 * 60


def _slow_readers(out_dir, now):
    """{"model@host": when it timed out} for the second readers that timed out in the last WORKER_SLOW_FOR s."""
    path = __import__("os").path.join(out_dir, "review", "slow-readers.json")
    try:
        with open(path) as fh:
            rows = __import__("json").load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(rows, dict):
        return {}
    return {k: v for k, v in rows.items() if isinstance(v, (int, float)) and 0 <= now - v < WORKER_SLOW_FOR}


def _mark_slow_reader(out_dir, who, now):
    os_ = __import__("os")
    rows = _slow_readers(out_dir, now)
    rows[who] = now
    path = os_.path.join(out_dir, "review", "slow-readers.json")
    try:
        os_.makedirs(os_.path.dirname(path), exist_ok=True)
        tmp = f"{path}.{os_.getpid()}"
        with open(tmp, "w") as fh:
            __import__("json").dump(rows, fh)
        os_.replace(tmp, path)
    except OSError:
        pass


def t_code_review(ctx, scope="diff", paths=None, focus=""):
    """Code review that reports only what survives verification: the worker reads the diff / files as a hostile
    reviewer and returns suspicions; code checks each one (file, line, snippet present; a read-only check command
    run) before it is a finding. CONFIRMED = a check failed as predicted; PLAUSIBLE = location and promise confirmed
    by reading; the rest is dropped with the reason."""
    (
        CODE_FILE, OUT_DIR, SPIN, TOOL_LLM_TIMEOUT, WS, _check_runner,
        _demote_preexisting, _git, _inside_ws, _json_objects, _now, _parallel, _read,
        _spill, _touched_files, dim, gnoc_modes, gnoc_sec, json, llm_chat, os, re,
        resolve, root, say, yellow,
    ) = bind(
        "CODE_FILE", "OUT_DIR", "SPIN", "TOOL_LLM_TIMEOUT", "WS", "_check_runner",
        "_demote_preexisting", "_git", "_inside_ws", "_json_objects", "_now", "_parallel",
        "_read", "_spill", "_touched_files", "dim", "gnoc_modes", "gnoc_sec", "json",
        "llm_chat", "os", "re", "resolve", "root", "say", "yellow",
    )
    r = root()
    paths = [paths] if isinstance(paths, str) else list(paths or [])
    if scope == "diff" and not paths:
        code, _ = _git(r, "rev-parse", "--is-inside-work-tree")
        if code:
            return "not a git repo: pass paths=[...] to review files"
        text = _git(r, "diff", "--patch")[1] + "\n" + _git(r, "diff", "--cached", "--patch")[1]
        # NEW files are untracked, and `git diff` never shows them: after the lead wrote tests/test_report.py the
        # review said "the diff is empty" and checked nothing (2026-11-20 SWE drive). Each untracked, not-ignored
        # file is added as a new-file diff.
        # Never caches or build output: a repo without a .gitignore had tests/__pycache__/*.pyc untracked, and the
        # review read "Binary files /dev/null and b/...pyc differ" as part of the change (2026-11-20 SWE drive).
        junk = re.compile(r"(?:^|/)(?:__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.tox|\.nox|node_modules|"
                          r"\.venv|venv|env|\.eggs|[^/]*\.egg-info|dist|build|\.coverage[^/]*|htmlcov|\.DS_Store)(?:/|$)"
                          r"|\.(?:pyc|pyo|so|dylib|dll|exe|o|a|class|jar|zip|gz|tar|png|jpe?g|gif|ico|pdf|sqlite3?|db)$")
        for new in [x for x in _git(r, "ls-files", "--others", "--exclude-standard")[1].splitlines()
                    if x and not junk.search(x)][:20]:
            full = os.path.join(r, new)
            if os.path.isfile(full) and os.path.getsize(full) <= 200_000:
                one = _git(r, "diff", "--no-index", "--patch", "--", "/dev/null", new)[1]   # git knows it, on Windows too
                if not re.search(r"^Binary files ", one, re.M):
                    text += "\n" + one
        files = sorted(set(_touched_files(text)))
        desc = f"the working-tree diff ({len(files)} file(s))"
        if not files:
            return "nothing to review: the diff is empty (pass scope=files paths=[...] to review files)"
    else:
        files = []
        for x in paths:
            full = _inside_ws(x)
            if not full:
                return f"refused: {x} is outside the active repo"
            if os.path.isdir(full):
                for dp, _, fs in os.walk(full):
                    files += [os.path.relpath(os.path.join(dp, f), r) for f in fs if CODE_FILE.search(f)]
            else:
                files.append(os.path.relpath(full, r))
        files = sorted(set(files))[:40]
        text = "\n".join(f"===== {f}\n" + "\n".join(f"{i + 1:5d}\t{ln}" for i, ln in enumerate(_read(os.path.join(r, f)).splitlines()))
                         for f in files)
        desc = f"{len(files)} file(s): {', '.join(files[:6])}{' ...' if len(files) > 6 else ''}"
    if not text.strip():
        return "nothing to review"
    sast_rows = []
    for f in files[:6]:
        try:
            got, _ = gnoc_sec.semgrep(os.path.join(r, f), timeout=120)
            sast_rows += got or []
        except Exception:
            pass
    # BOTH GPUs read the code: the lead is idle while this tool runs, and two independent readers catch different
    # things (the quiet kinds are exactly what one reader passes over). Agreement is a confidence signal.
    readers = []
    slow = _slow_readers(OUT_DIR, __import__("time").time())
    for role in ("lead", "worker"):
        m, h = resolve(role)
        if role != "lead" and f"{m}@{h}" in slow:
            say(dim("  ⎿  ") + dim(f"{m}@{h} skipped: it ran past {int(WORKER_READ_LIMIT)}s on a review in the last "
                                   f"{WORKER_SLOW_FOR // 60} min"))
            continue
        if (m, h) not in [(x[1], x[2]) for x in readers]:
            readers.append((role, m, h))
    raw, per_reader = [], []

    def _read_code(role, model, host):
        # the code must fit the reader's window beside the prompt and its answer, or it reads half a file and
        # returns nothing: ~4 chars a token, keep a third of the window for the system prompt and the JSON out
        cap = 26000 if host in ("desktop", "split") else 9000
        body = text[:cap] + (f"\n[... cut at {cap} chars of {len(text)}; review the rest with paths=... in a "
                             "second call]" if len(text) > cap else "")
        msgs = [{"role": "system", "content": gnoc_modes.REVIEW_SYSTEM},
                {"role": "user", "content": f"REVIEW SCOPE: {desc}" + (f"\nFOCUS: {focus}" if focus else "")
                                            + "\nFile paths are relative to the repo root; cite them exactly.\n\n"
                                            + body}]
        mine = []
        # the second reader answers without thinking: with thinking on, a 9B worker spent its whole 2400-token
        # budget reasoning, twice, returned no JSON either time, and held the turn for six minutes (2026-11-20)
        out = llm_chat(model, host, msgs, num_predict=2400, timeout=TOOL_LLM_TIMEOUT,
                       think=(None if role == "lead" else False),
                       on_think=(SPIN.thought if role == "lead" else None)).get("content") or ""
        mine.append(out)
        got = gnoc_modes.review_objects(_json_objects(out))
        if not got:  # a small reader wraps the array in prose or stops mid-answer: ask once more, and this time
            # the answer is held to the schema, so it cannot be prose
            out2 = llm_chat(model, host, msgs + [{"role": "assistant", "content": out[:1500]},
                                                 {"role": "user", "content": "Return ONLY the JSON now, no prose "
                                                  "and no code fence: {\"suspicions\": [ ...suspicion objects... ]}. "
                                                  "If after reading every line you truly found nothing, return "
                                                  "{\"suspicions\": []}."}],
                            num_predict=2400, think=False, timeout=TOOL_LLM_TIMEOUT,
                            fmt=gnoc_modes.REVIEW_SCHEMA).get("content") or ""
            mine.append(out2)
            got = gnoc_modes.review_objects(_json_objects(out2))
        for g in got:
            g["_by"] = f"{model}@{host}"
        return got, mine, f"{model}@{host}"

    SPIN.start("Reviewing", who=" + ".join(f"{m}@{h}" for _, m, h in readers), kind="think")
    proposed = []
    try:
        # the lead's reading is the review; a second reader is a second opinion, and a slow one is not waited for
        # past WORKER_READ_LIMIT seconds (a busy or CPU-bound worker took 346 s for one empty answer)
        limits = [None if role == "lead" else min(TOOL_LLM_TIMEOUT, WORKER_READ_LIMIT) for role, _, _ in readers]
        results = _parallel([(lambda it=it: _read_code(*it)) for it in readers], max_workers=len(readers),
                            timeouts=limits)
        for (role, m, h), res in zip(readers, results):
            if isinstance(res, tuple):
                got, mine, who = res
                per_reader.append((who, len(got)))
                raw += mine
                proposed += got
            elif isinstance(res, TimeoutError):
                _mark_slow_reader(OUT_DIR, f"{m}@{h}", __import__("time").time())
                say(dim("  ⎿  ") + dim(f"{m}@{h} was still reading after {int(limits[readers.index((role, m, h))])}s; "
                                       "not waited for"))
    finally:
        SPIN.stop()
    findings = gnoc_modes.merge_suspicions(proposed)
    if per_reader:
        say(dim("  ⎿  ") + dim("read by " + ", ".join(f"{w} ({n})" for w, n in per_reader)))
    if not findings and raw and not any(re.search(r"^\s*\[\s*\]\s*$", x.strip(), re.M)
                                        or re.fullmatch(r"\{\s*\"suspicions\"\s*:\s*\[\s*\]\s*\}", x.strip()) for x in raw):
        say(dim("  ⎿  ") + yellow("no reader returned parseable suspicions; treat this as NOT REVIEWED"))
    runner = _check_runner(r)
    try:
        kept, dropped = gnoc_modes.verify_findings(r, findings, runner)
    finally:
        runner.cleanup()
    if scope == "diff" and not paths:
        _demote_preexisting(r, kept)
    report = gnoc_modes.review_text(kept, dropped, desc, sast_rows)
    if not findings and not sast_rows:
        report = (f"CODE REVIEW of {desc}: no reader ({', '.join(w for w, _ in per_reader) or 'none ran'}) "
                  "returned a parseable suspicion. "
                  "This is NOT a clean bill of health: read the diff yourself, or re-run with a bigger lead "
                  "(gnoc models use worker <model>) or a narrower scope (paths=[one file]).")
    out_dir = os.path.join(OUT_DIR, "review")
    os.makedirs(out_dir, exist_ok=True)
    fp = os.path.join(out_dir, f"REVIEW-{_now():%Y%m%d-%H%M%S}.md")
    with open(fp, "w") as f:
        f.write(report + "\n\nRAW SUSPICIONS:\n" + json.dumps(findings, indent=1)[:40000]
                + "\n\nRAW MODEL OUTPUT:\n" + "\n---- retry ----\n".join(x[:20000] for x in raw) + "\n")
    ctx.s["_last_review"] = {"confirmed": sum(1 for k in kept if k["verdict"] == "CONFIRMED"), "kept": len(kept)}
    return _spill(report + f"\nfull review: {os.path.relpath(fp, WS)}", "review")


def t_touch(ctx, read_url, write_url, body, revert_body=None, method="PATCH", program=None, as_identity=None,
            headers=None, hypothesis=None):
    """REVERSIBLE REAL TOUCH on an object you own: capture BEFORE (GET read_url), apply the write, capture AFTER,
    then revert (revert_body, or the BEFORE body when the API echoes the object) and capture that too. Four raw
    files; the diff between BEFORE and AFTER is the receipt. Refused on a non-owned object: pass as_identity for the
    research account that owns it."""
    (
        _program_gate, _send, _with_identity, gnoc_hunt,
    ) = bind(
        "_program_gate", "_send", "_with_identity", "gnoc_hunt",
    )
    program = program or ctx.program
    for u in (read_url, write_url):
        pol, err = _program_gate(program, u)
        if err:
            return err
    if not as_identity:
        return "refused: touch needs as_identity=<the research account that OWNS the object> (never a real user's object)"
    try:
        hdrs = _with_identity(program, headers, as_identity, read_url)
        # the same headers go to write_url for the WRITE and the REVERT: a session that belongs to another site
        # must be refused for that host too, not only for the read (QAQC 2026-11-19)
        _with_identity(program, headers, as_identity, write_url)
    except KeyError as e:
        return str(e).strip("'\"") + " (identities action=list shows the saved names)"
    except PermissionError as e:
        return str(e)
    steps, rels = [], []
    try:
        # ECON: budget checked on the BEFORE read only; a refusal mid-sequence would strand an unreverted write
        before, rel = _send(program, pol, read_url, "GET", hdrs, None, hypothesis=hypothesis)
        rels.append(rel)
        steps.append(f"BEFORE  HTTP {before.get('status')} len={before.get('len')} raw={rel}")
        w, rel = _send(program, pol, write_url, method.upper(), hdrs, body)
        rels.append(rel)
        steps.append(f"WRITE   HTTP {w.get('status')} len={w.get('len')} raw={rel}")
        after, rel = _send(program, pol, read_url, "GET", hdrs, None)
        rels.append(rel)
        steps.append(f"AFTER   HTTP {after.get('status')} len={after.get('len')} raw={rel}")
        rb = revert_body if revert_body is not None else (before.get("body") if (before.get("body") or "").strip().startswith("{") else None)
        if rb is not None:
            rv, rel = _send(program, pol, write_url, method.upper(), hdrs, rb)
            rels.append(rel)
            steps.append(f"REVERT  HTTP {rv.get('status')} len={rv.get('len')} raw={rel}")
        else:
            steps.append("REVERT  skipped: give revert_body (the BEFORE body is not a JSON object the API would accept)")
    except Exception as e:
        return "touch failed after " + "; ".join(steps) + f": {type(e).__name__}: {e}"
    for rel in rels:
        gnoc_hunt.log_probe(program, hypothesis, rel)
    changed = (before.get("body") or "") != (after.get("body") or "")
    return ("\n".join(steps) + f"\nBEFORE != AFTER: {changed}"
            + ("  (the write landed: quote the differing bytes from the two raw files)" if changed else
               "  (no visible change: the write did not land, or the read does not show the field)"))


def _env_tag(url):
    (
        gnoc_modes,
    ) = bind(
        "gnoc_modes",
    )
    env, tok = gnoc_modes.env_of(url)
    return f"[NON-PRODUCTION host ({tok}): a finding proven only here closes N/A; capture the production leg too]\n" \
        if env == "nonprod" else ""


def t_goal(ctx, action="show", text="", receipt="", artifact="", status="done", force=False, acceptance="",
           milestones=None):
    """The standing goal: what the user wants achieved, kept across turns and restarts."""
    (
        _goal_program, _seed_goal, gnoc_goal, re, warn_goal_excluded,
    ) = bind(
        "_goal_program", "_seed_goal", "gnoc_goal", "re", "warn_goal_excluded",
    )
    if action == "show":
        return gnoc_goal.status_text()
    if action == "set":
        # A standing WATCH is the defender's watcher, not a goal: "watch for new devices on my wifi and alert me"
        # became the standing goal "Monitor WiFi network for new devices", steering every later turn in that
        # folder (defense drive 2026-11-22). The watcher is GreyNOC's switch.
        _re = __import__("re")
        if _re.search(r"(?i)\b(?:monitor\w*|watch\w*|alert\w*|notify|keep\s+an\s+eye)\b", str(text or "")) and _re.search(
                r"(?i)\b(?:device|wi-?fi|wlan|lan|network|port|ssh|login|intrusion|attack|traffic|connection|process|"
                r"machine|laptop|router|gateway)s?\b", str(text or "")) and not _re.search(
                r"(?i)\b(?:hunt\w*|program|bounty|ato|exploit\w*|report\w*|fix\w*|build\w*|implement\w*|test\w*|"
                r"refactor\w*|write|code|feature|bug)\b", str(text or "")):
            return ("refused: watching this machine or its network is the defender's WATCHER, not a goal. The user "
                    "starts it themselves: /defender watch on [secs] (alert only) or /defender auto on [secs] (alert "
                    "and act); it re-sweeps while this chat is open and new devices, ports and intrusions come up "
                    "as alerts. Tell them that line; set no goal.")
        cur = gnoc_goal.load()
        # HIS words this turn asking for a goal ARE his call. "can we hunt your-site.example and set a goal to get
        # a cvss 10" was refused as "replacing GreyNOC's standing goal is his call", and the lead then told him
        # "Goal set" anyway (2026-11-27). Only his text counts, never the trailing [gnoc: ...] hint or the model.
        _his = _re.split(r"\n\s*\[gnoc:", str((getattr(ctx, "s", None) or {}).get("_turn_text") or ""))[0]
        if _re.search(r"(?i)\b(?:set|make|start|new|change|replace|switch|update)\b[\w\s']{0,24}\bgoals?\b|"
                      r"\bgoal\s+(?:to|of|is|should be)\b", _his):
            force = True
        if cur and cur.get("status") in ("active", "paused") and not force:
            same = cur.get("text") == " ".join(str(text or "").split())
            if same:
                return (f"that goal is already {cur.get('status')} - its progress is kept. "
                        + ("Resume it with action=resume." if cur.get("status") == "paused" else ""))
            return (f"refused: a goal is already {cur.get('status')} - {cur['text']!r}. Replacing the user's "
                    "standing goal is their call: either work toward this one, or say what should replace it and "
                    "call set again with force=true once the user agrees.")
        prog = _goal_program(text, ctx.program)
        acc = acceptance if isinstance(acceptance, list) else \
            [c.strip() for c in re.split(r"[;\n]", str(acceptance or "")) if c.strip()]
        ms = milestones if isinstance(milestones, list) else \
            [c.strip() for c in re.split(r"[;\n]", str(milestones or "")) if c.strip()]
        d, err = gnoc_goal.set_goal(text, prog, milestones=ms, owner=ctx.s.get("sid"), acceptance=acc)
        if err:
            return err
        warn_goal_excluded(prog, d["text"])   # T-303: the agent's own goal gets the check /hunt gets
        seeded = _seed_goal(d)
        return (seeded + "\n" if seeded else "") + gnoc_goal.status_text()
    own = ctx.s.get("sid")   # a write names the conversation doing it: never another chat's goal
    if action == "note":
        return gnoc_goal.note(text, artifact, owner=own)
    if action == "milestone":
        return gnoc_goal.milestone(text, status, receipt or artifact, owner=own)
    if action == "accept":
        # the tool's default status is "done" (milestone-shaped); for a criterion that means MET. Only an
        # explicit status=open adds or re-opens one without a receipt.
        st = "open" if str(status).lower() == "open" else "met"
        return gnoc_goal.accept(text, st, receipt or artifact, owner=own)
    if action == "done":
        return gnoc_goal.done(receipt or artifact, bool(force), owner=own)
    if action == "pause":
        return gnoc_goal.pause(owner=own)
    if action == "resume":
        return gnoc_goal.resume(owner=own)
    if action == "clear":
        return gnoc_goal.clear(owner=own, force=bool(force))
    return "action is show, set, note, milestone, accept, pause, resume, done or clear"


def _goal_program(text, fallback=None):
    """A goal that names a program ('zero click ato on gatewayco') belongs to THAT program, not to whatever happened
    to be active. Only a word that resolves to an intaken program counts."""
    (
        re, resolve_program,
    ) = bind(
        "re", "resolve_program",
    )
    for w in re.findall(r"[A-Za-z0-9][\w.-]{2,}", text or ""):   # digits too: 1vault is a handle
        if w.lower() in ("the", "and", "for", "with", "zero", "click", "ato", "rce", "get", "achieve", "on",
                         "from", "into", "via", "without", "unauth", "production", "live", "prod", "cross",
                         "tenant", "user", "money", "admin", "secret", "pii", "mass", "auth", "bypass", "read",
                         "write", "takeover", "account", "chain", "full"):
            continue
        prog = resolve_program(w, strict=True)
        if prog:
            return prog
    return fallback


def _seed_goal(d):
    """A goal that names a crown gets its milestones from the attack tree: the capabilities it must pass through."""
    (
        _VICTIM_ACTION_LEAVES, gnoc_doctrine, gnoc_goal, gnoc_hunt, re,
    ) = bind(
        "_VICTIM_ACTION_LEAVES", "gnoc_doctrine", "gnoc_goal", "gnoc_hunt", "re",
    )
    if not d or not d.get("crown") or d.get("milestones"):
        return ""
    held = []
    if d.get("program"):
        held = [e["to"] for e in gnoc_hunt.load(d["program"])["edges"] if e["status"] in ("proven", "lead")]
    tree = gnoc_doctrine.attack_tree(d["crown"], held, 2)
    m = re.search(r"LEAVES TO PROVE[^:]*: (.+)", tree)
    leaves = [x.strip() for x in m.group(1).split(",")] if m else []
    # a zero-click goal cannot be reached through a leaf that needs the victim to act ("0 click ato" was seeded
    # "hold open-redirect", GreyNOC's meta goal 2026-10-22)
    skipped = []
    if "zero-click" in (d.get("constraints") or []):
        skipped = [x for x in leaves if x in _VICTIM_ACTION_LEAVES]
        leaves = [x for x in leaves if x not in _VICTIM_ACTION_LEAVES]
    # "hold cache-control" said nothing; name what proving it unlocks, from the tree's own edge
    unlocks = {}
    for frm, to in re.findall(r"(\S+) --\[[^\]]*\]--> (\S+)", tree):
        unlocks.setdefault(frm, to)   # the first edge is the one the tree reached it through
    texts = [f"prove {x}" + (f" (unlocks {unlocks[x]})" if unlocks.get(x) else "") for x in leaves]
    if texts:
        gnoc_goal.seed_milestones(d, texts)
        return (f"seeded {len(texts[:8])} milestone(s) from the attack tree for {d['crown']}"
                + (f"; skipped victim-action leaves for zero-click: {', '.join(skipped)}" if skipped else ""))
    return ""


def _goal_reenter(agent):
    """F9 2026-11-09: when a turn died on a TRANSIENT lead error (after CLOUD_RETRY_BACKOFF) while this conversation
    owns an active /goal, re-enter the goal loop instead of leaving the user at the prompt. Bounded, and it yields to
    Ctrl-C, STOP, and anything typed meanwhile. Returns how many times it re-entered."""
    (
        GOAL_REENTRY_MAX, GOAL_RESUME_PROMPT, TYPED, WS, gnoc_goal, os, root, say, yellow,
    ) = bind(
        "GOAL_REENTRY_MAX", "GOAL_RESUME_PROMPT", "TYPED", "WS", "gnoc_goal", "os", "root", "say",
        "yellow",
    )
    n = 0
    stop_f = os.path.join(WS, ".claude/state/hunt-loop/STOP")
    while agent.s.pop("_lead_transient", False) and n < GOAL_REENTRY_MAX:
        d = gnoc_goal.load()
        if (not gnoc_goal._owned(d, agent.s.get("sid")) or getattr(agent, "interrupted", False)
                or (os.path.exists(stop_f) and (d.get("program") or os.path.realpath(root()) == os.path.realpath(WS)))
                or TYPED.pending()):
            break   # STOP holds hunting (a program goal, or the hunt workspace), never code work in a repo
        n += 1
        say(yellow(f"  lead connection dropped mid-goal; re-entering the goal loop ({n}/{GOAL_REENTRY_MAX})"))
        prog = d.get("program") or agent.ctx.program
        if prog:
            agent.hunt(prog, d["text"])
        else:
            agent.turn(GOAL_RESUME_PROMPT)
    return n


def _goal_fingerprint(d):
    """What 'the goal moved' means: a note, a milestone or criterion closed, or its status changed."""
    d = d or {}
    return (d.get("status"), len(d.get("log") or []),
            sum(1 for m in d.get("milestones") or [] if m.get("status") == "done"),
            sum(1 for a in d.get("acceptance") or [] if a.get("status") == "met"))


def _goal_live(agent):
    """The goal this conversation is driving, or None (no goal, achieved, paused, cleared, another chat's)."""
    (
        gnoc_goal,
    ) = bind(
        "gnoc_goal",
    )
    d = gnoc_goal.load()
    return d if gnoc_goal._owned(d, agent.s.get("sid")) and d.get("status") == "active" else None


def drive_goal(agent, first_prompt=None, why=""):
    """Work the standing goal turn after turn until it is ACHIEVED (closed with its receipt). The user: "when I
    set a goal it should not stop until that goal is complete" (2026-11-18). Measured before this: /goal ran ONE
    turn, then every step needed them to type "continue with the next step of the goal".

    It hands control back only for: the goal being closed, paused or cleared; Ctrl-C (which also HOLDS the goal,
    so it does not restart on their next message until /goal resume or "continue"); the hunt STOP file; a NEEDS:
    line (answer it and the goal resumes by itself); GOAL_STALL_MAX turns with no tool call and no goal movement;
    GOAL_EMPTY_MAX empty answers in a row (the lead is down); or GNOC_GOAL_TURNS when the user set a budget (default:
    none). Typing while it works is an interjection, not a stop: the typed message runs, then the goal resumes.
    A goal with a programme runs the continuous hunt, which has its own loop. Returns the turns it ran."""
    (
        GOAL_CONTINUE, GOAL_EMPTY_MAX, GOAL_SAID_DONE, GOAL_STALL_MAX,
        GOAL_STALL_NUDGE, INTERRUPT, T, TYPED, WS, _SAID_DONE, _goal_fingerprint,
        _goal_live, dim, gnoc_goal, os, re, red, root, say, time, yellow,
    ) = bind(
        "GOAL_CONTINUE", "GOAL_EMPTY_MAX", "GOAL_SAID_DONE", "GOAL_STALL_MAX",
        "GOAL_STALL_NUDGE", "INTERRUPT", "T", "TYPED", "WS", "_SAID_DONE",
        "_goal_fingerprint", "_goal_live", "dim", "gnoc_goal", "os", "re", "red", "root", "say",
        "time", "yellow",
    )
    d = _goal_live(agent)
    if not d or agent.s.get("_goal_hold"):
        return 0
    prog = d.get("program")
    stop_f = os.path.join(WS, ".claude/state/hunt-loop/STOP")
    if prog:
        agent.hunt(prog, d["text"])
        return 1
    try:
        cap = max(0, int(os.environ.get("GNOC_GOAL_TURNS") or 0))
    except ValueError:
        cap = 0
    say(T.bgreen("  ▶ ") + T.byellow("working on the goal until it is done")
        + dim(("  (" + why + ")" if why else "") + "  ·  Ctrl-C stops and holds it · typing interjects · "
              "/goal pause parks it" + (f" · budget {cap} turns" if cap else "")))
    turns = stall = empty = 0
    said_done = False
    try:
        while True:
            d = _goal_live(agent)
            if not d:
                break
            # STOP is the hunt fleet's ("kill all hunting so the chat gets the whole machine"): it holds a goal worked
            # in the hunt workspace, never code work in a repo. "/goal all tests pass" in a scratch repo said "global
            # STOP is set; the goal waits" and did nothing (2026-11-20 SWE drive).
            if os.path.exists(stop_f) and os.path.realpath(root()) == os.path.realpath(WS):
                say(yellow("  global STOP is set; the goal waits") + dim("  (/stop off clears it, then /goal resume)"))
                break
            if cap and turns >= cap:
                say(yellow(f"  goal turn budget reached ({cap}, GNOC_GOAL_TURNS)") + dim("  ·  /goal resume continues"))
                break
            agent.interrupted = False
            INTERRUPT.clear()
            prompt = first_prompt if (turns == 0 and first_prompt) else GOAL_CONTINUE.format(goal=d["text"])
            if said_done:
                prompt = GOAL_SAID_DONE + prompt
            elif stall >= 2:
                prompt = GOAL_STALL_NUDGE.format(n=stall) + prompt
            before = _goal_fingerprint(d)
            ans = agent.turn(prompt)
            turns += 1
            if agent.interrupted:
                agent.s["_goal_hold"] = True
                say(yellow("  goal held (Ctrl-C)") + dim("  ·  /goal resume, or say \"continue\", to go on"))
                break
            if TYPED.pending():
                say(dim("  you typed while it worked: your message runs next, then the goal resumes"))
                break
            if not (ans or "").strip():
                empty += 1
                if empty >= GOAL_EMPTY_MAX:
                    say(red(f"  {empty} turns in a row with no answer (lead model down?); the goal waits")
                        + dim("  ·  /goal resume when it is back"))
                    break
                time.sleep(5 * empty)
                continue
            empty = 0
            after = _goal_live(agent)
            if not after:
                break          # closed (achieved), paused or cleared during the turn
            if re.search(r"(?m)^\s*\**NEEDS:", ans):
                say(yellow("  the goal is waiting on you (NEEDS: above)") + dim("  ·  answer it and the goal resumes"))
                break
            moved = _goal_fingerprint(after) != before
            tools = int(agent.s.get("_turn_tools_last") or 0)
            stall = 0 if (moved or tools) else stall + 1
            said_done = bool(_SAID_DONE.search(ans)) and not moved
            if stall >= GOAL_STALL_MAX:
                say(yellow(f"  {stall} turns with no tool call and no progress on the goal; handing back to you")
                    + dim("  ·  give it a new angle, or /goal resume"))
                break
    except KeyboardInterrupt:
        agent.interrupted = True
        agent.s["_goal_hold"] = True
        say(yellow("\n  goal held (Ctrl-C)") + dim("  ·  /goal resume, or say \"continue\", to go on"))
    d = gnoc_goal.load()
    if d and d.get("status") == "achieved" and gnoc_goal._owned(dict(d, status="active"), agent.s.get("sid")):
        say(T.bgreen("  ✔ goal achieved") + dim(f"  after {turns} turn(s)"))
    return turns


def goal_after_turn(agent, line=""):
    """After one of the user's own messages: a live goal picks itself back up instead of idling at the prompt.
    A Ctrl-C hold is released only by an explicit "continue"/"resume" (or /goal resume)."""
    (
        TYPED, _CONTINUE_WORDS, _goal_live, drive_goal,
    ) = bind(
        "TYPED", "_CONTINUE_WORDS", "_goal_live", "drive_goal",
    )
    if agent.s.get("_goal_hold"):
        if not _CONTINUE_WORDS.match(line or ""):
            return 0
        agent.s.pop("_goal_hold", None)
    if getattr(agent, "interrupted", False) or TYPED.pending() or not _goal_live(agent):
        return 0
    return drive_goal(agent, why="resuming after your message")


def ready_with_draft(ans):
    """True only when the answer says READY: and names a draft dir whose report.md exists on disk."""
    (
        WS, os, re,
    ) = bind(
        "WS", "os", "re",
    )
    m = re.search(r"reports/drafts/[\w.-]+/[\w.-]+", ans or "")
    return bool(re.search(r"(?m)^\s*\**READY:", ans or "") and m
                and os.path.isfile(os.path.join(WS, m.group(0), "report.md")))


def _goal_turn_text(agent, d):
    """Make the goal text THE turn text before the goal's ledger writes.

    A slash command never refreshes `_turn_user`, so at /goal time it still holds the PREVIOUS turn's text. The
    cross-program gate (`_turn_program`) then reads the OLD program out of it and refuses every seeded hypothesis:
    measured 2026-11-10 00:36Z and again 00:46Z on the live chat, "/goal ... on program-58" -> "refused: this turn
    is about program-28, but the active program is program-58", then "/goal ... on program-50" -> "this turn is
    about program-58". Both goals started with ZERO goal-shaped hypotheses, which is exactly the D1 defect of the
    2026-10-25 drive coming back through a different door. The goal text names the program the goal switched to,
    so once it is the turn text the gate sees one program equal to the active one and lets the writes through."""
    (
        re,
    ) = bind(
        "re",
    )
    try:
        agent.s["_turn_user"] = re.sub(r"\s+", " ", str(d.get("text") or "")).strip()[:2000]
    except Exception:  # noqa: BLE001 - a goal without this still starts; the gate just refuses the seeding
        pass


def _goal_hypotheses(agent, d):
    """A goal starts from hypotheses aimed at ITS crown and milestones, not from whatever the ledger held. Drive
    cycle 1 (2026-10-25 23:34Z): "/goal achieve zero click ATO on program-0" spent its first 20 probes on H3, an
    invented admin twin left over from an earlier session, and never proposed one goal-shaped hypothesis. The
    tournament keeps the best n; the PROBE order then puts crown-weighted, unprobed hypotheses first."""
    (
        t_hypothesize,
    ) = bind(
        "t_hypothesize",
    )
    try:
        ms = "; ".join(str(m.get("text", "")) for m in (d.get("milestones") or [])[:6])
        focus = (f"{d.get('crown') or ''} {' '.join(d.get('constraints') or [])}: {d.get('text', '')}. "
                 f"milestones to prove: {ms}")
        out = t_hypothesize(agent.ctx, n=3, focus=focus)
        return "goal hypotheses: " + str(out)[:400].replace("\n", " | ")
    except Exception as e:  # noqa: BLE001 - a goal without fresh hypotheses still starts
        return f"goal hypotheses skipped: {type(e).__name__}: {e}"


def t_hunt_model(ctx, action="show", actors=None, boundaries=None, promises=None, catastrophes=None, stack=None):
    (
        _need_program, _program_gate_write, _read_program, gnoc_hunt,
    ) = bind(
        "_need_program", "_program_gate_write", "_read_program", "gnoc_hunt",
    )
    need = _need_program(ctx)
    if need:
        return need
    if str(action or "").lower() in ("add", "set"):
        refused = _program_gate_write(ctx, "a trust-model item")
        if refused:
            return refused
    prog, note = _read_program(ctx)
    return note + gnoc_hunt.model(prog, action, actors, boundaries, promises, catastrophes, stack)


def t_playbook(ctx, kind="moves", query="", phase=None, k=5):
    """The expert layer on demand: doctrine moves, pattern cards, Manual rules, the chain table, an escalation plan."""
    (
        gnoc_doctrine, gnoc_hunt,
    ) = bind(
        "gnoc_doctrine", "gnoc_hunt",
    )
    k = max(1, min(int(k or 5), 20))
    query = str(query or "")
    if kind in ("card", "next_hops", "kill_check") and not query.strip():
        return {"card": "bad arguments: kind=card needs query=<card id> (kind=cards lists matching ids)",
                "next_hops": "bad arguments: kind=next_hops needs query=<the capability you hold, e.g. ssrf>",
                "kill_check": "bad arguments: kind=kill_check needs query=<the finding in one sentence>"}[kind]
    if kind == "moves":
        rows = gnoc_doctrine.moves(phase, query, k, 520)
        return "\n".join(f"{i}: {t}" for i, t in rows) or "no doctrine rule matches"
    if kind == "opener":
        return gnoc_doctrine.opener()
    if kind == "cards":
        return gnoc_doctrine.cards_text(query, k, min(2, k)) or "no pattern card matches"
    if kind == "card":
        return gnoc_doctrine.card(query.strip())
    if kind == "manual":
        return gnoc_doctrine.manual(query, k)
    if kind == "next_hops":
        return gnoc_doctrine.escalation_plan(query)
    if kind == "attack_tree":
        held = [e["to"] for e in gnoc_hunt.load(ctx.program)["edges"] if e["status"] in ("proven", "lead")] if ctx.program else []
        return gnoc_doctrine.attack_tree(query or "ato", held)
    if kind == "idioms":
        tags = [t.strip() for t in query.split(",") if t.strip()] or gnoc_hunt.stack_tags(ctx.program or "")
        return "\n".join(gnoc_doctrine.idioms_for(tags, 12)) or "no stack tags: run fingerprint first"
    if kind == "kill_check":
        hits = gnoc_doctrine.kill_match(query)
        return ("reads like a pre-rejected shape: " + "; ".join(f"{n} ({snip!r})" for n, snip in hits)
                + ". It is Informative on arrival unless the captured bytes SHOW the capability it lacks."
                if hits else "matches none of the 16 pre-rejected shapes")
    if kind == "pack":
        return gnoc_doctrine.pack(phase or "hypothesize", query, gnoc_hunt.stack_tags(ctx.program or ""))
    return "kind is moves, opener, cards, card, manual, next_hops, idioms, kill_check or pack"


def t_fingerprint(ctx, program=None, extra=""):
    """Stack tags for the program from every raw capture on disk (plus recon httpx output); saved to the model."""
    (
        WS, _read, glob, gnoc_doctrine, gnoc_hunt, json, os,
    ) = bind(
        "WS", "_read", "glob", "gnoc_doctrine", "gnoc_hunt", "json", "os",
    )
    program = program or ctx.program
    if not program:
        return "no active program"
    caps = []
    base = os.path.join(WS, "targets", program)
    files = sorted(glob.glob(os.path.join(base, "hunts", "gnoc-agent-*", "raw", "*.json")))[-60:]
    for f in files:
        try:
            caps.append(json.loads(_read(f)))  # _read: json.load(open(f)) leaked one file handle per capture
        except ValueError:
            continue
    text = str(extra or "")
    for f in sorted(glob.glob(os.path.join(base, "recon", "**", "httpx*.json*"), recursive=True))[-3:]:
        text += "\n" + _read(f)[:20000]
    tags, why = gnoc_doctrine.fingerprint(caps, text)
    if not tags:
        return (f"no stack tags from {len(files)} capture(s): probe one in-scope root with http_request (the response "
                "headers, cookies and error body carry the fingerprint), then run fingerprint again")
    gnoc_hunt.model(program, "add", stack=tags)
    return (f"stack: {', '.join(tags)}  (from {len(files)} captures)\n" + "\n".join("  " + w for w in why[:12])
            + "\nFIRST IDIOMS PER STACK:\n- " + "\n- ".join(gnoc_doctrine.idioms_for(tags, 10)))


def _parse_list(text):
    (
        _json_objects, json, re,
    ) = bind(
        "_json_objects", "json", "re",
    )
    t = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S)
    t = t.rsplit("</think>", 1)[-1]
    objs = []
    for o in _json_objects(t):
        inner = next((v for v in o.values() if isinstance(v, list) and v and isinstance(v[0], dict)), None) \
            if isinstance(o, dict) and "title" not in o else None
        objs += inner if inner else [o]
    out = []
    for h in objs:
        if not isinstance(h, dict):
            continue
        st = str(h.get("start", "")).lower()
        if "|" in st:  # the model copied the template's choice list: decide from the text instead
            h["start"] = "unauth" if re.search(r"unauth|no (session|cookie|token)|without", json.dumps(h), re.I) \
                else "own-account"
        crown = str(h.get("crown", ""))
        if "|" in crown:
            h["crown"] = crown.split("|")[0]
        out.append(h)
    return out


def _propose(model, host, msgs, n=1800):
    """Ask for hypotheses; if nothing parses, ask once more for the bare JSON array."""
    (
        TOOL_LLM_TIMEOUT, _parse_list, llm_chat,
    ) = bind(
        "TOOL_LLM_TIMEOUT", "_parse_list", "llm_chat",
    )
    m = llm_chat(model, host, msgs, num_predict=n, timeout=TOOL_LLM_TIMEOUT)
    got = _parse_list(m.get("content"))
    if not got:
        m2 = llm_chat(model, host, msgs + [{"role": "assistant", "content": (m.get("content") or "")[:2000]},
                                           {"role": "user", "content": "Return ONLY the JSON array of hypothesis "
                                                                       "objects now, no prose, no code fence."}],
                      num_predict=n, timeout=TOOL_LLM_TIMEOUT)
        got = _parse_list(m2.get("content"))
    return got


def t_hypothesize(ctx, n=3, focus=""):
    """Both GPUs propose hypotheses in parallel; code scores, dedups and keeps the best n (tournament)."""
    (
        HYPO_PROMPT, HYPO_PROPOSER_WALL, _parallel, _program_gate_write, _propose,
        gnoc_doctrine, gnoc_hunt, resolve,
    ) = bind(
        "HYPO_PROMPT", "HYPO_PROPOSER_WALL", "_parallel", "_program_gate_write",
        "_propose", "gnoc_doctrine", "gnoc_hunt", "resolve",
    )
    if not ctx.program:
        return "no active program: set_program first"
    refused = _program_gate_write(ctx, "generated hypotheses")
    if refused:
        return refused
    turn = str((ctx.s or {}).get("_turn_user") or "")
    if turn and ctx.s.get("_hypothesized_for") == turn:
        return ("refused: you already ran hypothesize this turn and the ledger kept what scored. Running it again "
                "writes more unprobed hypotheses instead of testing the ones you have: call hunt_hypothesis "
                "action=list, pick the top one and PROBE it (probe_matrix, then crafted http_request variants). "
                "Ask for more only after that one has a verdict.")
    pack = gnoc_hunt.brief(ctx.program, cap=4200)
    expert = gnoc_doctrine.pack("hypothesize", f"{ctx.program} {focus}", gnoc_hunt.stack_tags(ctx.program), cap=4200)
    routes_block = gnoc_hunt.admissible_routes_block(ctx.program)   # D91: the only routes a proposal may name
    msgs = [{"role": "system", "content": HYPO_PROMPT},
            {"role": "user", "content": f"PROGRAM {ctx.program}" + (f"  FOCUS: {focus}" if focus else "")
                                        + (f"\n\n{routes_block}" if routes_block else "")
                                        + f"\n\nWHAT WE KNOW:\n{pack}\n\nEXPERT PACK:\n{expert}"}]
    picks = {"lead": resolve("lead"), "worker": resolve("worker")}
    if picks["lead"] == picks["worker"]:
        picks = {"lead": picks["lead"]}

    def ask(item):
        name, (model, host) = item
        try:
            return name, _propose(model, host, msgs)
        except Exception as e:
            return name, [{"title": f"(proposer {name} failed: {type(e).__name__})"}]
    items = list(picks.items())
    # A PER-SLOT WALL. TOOL_LLM_TIMEOUT is a SILENCE wall per read, and _propose can make TWO calls
    # (a reasoner that answers in prose instead of a JSON array triggers the retry), so one proposer
    # could legitimately hold this thread for ~10 minutes - and this runs straight off /goal, where
    # the only thing between it and the prompt is the operator's patience. A slot past the wall is
    # abandoned (its daemon thread is dropped) and the tournament runs on whoever answered.
    got = _parallel([(lambda it=it: ask(it)) for it in items], max_workers=2,
                    timeouts=[HYPO_PROPOSER_WALL] * len(items))
    got = [g for g in got if isinstance(g, tuple)]  # drop any None (interrupted) / exception slots
    proposals = [(src, h) for src, hs in got for h in hs[:6]]
    if not proposals:
        return "no usable proposals came back (both models returned no JSON); add hypotheses yourself"
    _, table = gnoc_hunt.tournament(ctx.program, proposals, max(1, min(int(n or 3), 10)))
    if str((ctx.s or {}).get("_turn_user") or ""):
        ctx.s["_hypothesized_for"] = ctx.s["_turn_user"]
    return table


def t_build_report(ctx, slug=None, vrt=None):
    (
        _lead_llm, gnoc_report, resolve,
    ) = bind(
        "_lead_llm", "gnoc_report", "resolve",
    )
    if not ctx.program:
        return "no active program: set_program first"
    try:
        finder = resolve("lead")[0]   # T1.5: finding.json records the finder's model family
    except Exception:  # noqa: BLE001
        finder = None
    rel, msg = gnoc_report.build(ctx.program, llm=_lead_llm, slug=slug, vrt=vrt, finder=finder)
    return msg


def t_hunt_chains(ctx, top=5):
    (
        _need_program, gnoc_hunt,
    ) = bind(
        "_need_program", "gnoc_hunt",
    )
    return _need_program(ctx) or gnoc_hunt.chains_text(ctx.program, max(1, min(int(top or 5), 20)))


def _graph_extras(value):
    """A list of ids from a JSON array, a comma/space string, or one int."""
    (
        re,
    ) = bind(
        "re",
    )
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    if isinstance(value, int):
        return [value]
    return [x for x in re.split(r"[\s,]+", str(value).strip()) if x]


def _graph_usage(name, actions):
    return f"bad arguments: {name} action is one of {', '.join(actions)}"


def _graph_db():
    """The graph database for THIS workspace. Tests point G.WS at a temp tree, so this is also
    what keeps test probes out of the real .claude/state/graph/gnoc_graph.db."""
    (
        WS, os,
    ) = bind(
        "WS", "os",
    )
    return os.path.join(WS, ".claude/state/graph/gnoc_graph.db")


def _graph_import_scope(program):
    """Ingest targets/<program>/SCOPE.txt into the asset graph. Idempotent; never fails a caller."""
    (
        WS, _graph_db, contextlib, gnoc_graph, os,
    ) = bind(
        "WS", "_graph_db", "contextlib", "gnoc_graph", "os",
    )
    if not program:
        return
    with contextlib.suppress(Exception):
        gnoc_graph.import_scope(program, os.path.join(WS, "targets", program, "SCOPE.txt"),
                                db_path=_graph_db())


def t_graph_overview(ctx):
    """One compact view of the dual graph: assets, coverage, node counts, open intents/todos, recent work."""
    (
        _graph_db, gnoc_graph,
    ) = bind(
        "_graph_db", "gnoc_graph",
    )
    if not ctx.program:
        return "no active program: set_program first"
    try:
        return gnoc_graph.overview_text(ctx.program, _graph_db())
    except Exception as e:  # noqa: BLE001 - graph state must never kill a turn
        return f"graph overview failed: {type(e).__name__}: {str(e)[:300]}"


def t_asset(ctx, action="search", kind="", identifier="", asset_id=0, query="", limit=100,
            parent="", attrs=None):
    """The asset graph: upsert / search / detail / coverage / untested."""
    (
        _graph_db, _graph_usage, gnoc_graph,
    ) = bind(
        "_graph_db", "_graph_usage", "gnoc_graph",
    )
    actions = ("upsert", "search", "detail", "coverage", "untested")
    action = str(action or "search").strip().lower()
    if action not in actions:
        return _graph_usage("asset", actions)
    dbp = _graph_db()
    try:
        if action == "upsert":
            if not ctx.program:
                return "no active program: set_program first"
            if not kind or not identifier:
                return "bad arguments: asset action=upsert needs kind and identifier"
            row = gnoc_graph.upsert_asset(str(kind), str(identifier), ctx.program,
                                          parent=(parent or None), attrs=attrs or {}, db_path=dbp)
            return f"asset #{row['id']} recorded\n" + gnoc_graph.asset_text(row["id"], dbp)
        if action == "detail":
            if not asset_id:
                return "bad arguments: asset action=detail needs asset_id"
            return gnoc_graph.asset_text(int(asset_id), dbp)
        if action == "coverage":
            if not ctx.program:
                return "no active program: set_program first"
            return gnoc_graph.coverage_text(ctx.program, dbp)
        if action == "untested":
            if not ctx.program:
                return "no active program: set_program first"
            rows = gnoc_graph.untested_assets(ctx.program, int(limit or 100), db_path=dbp)
            if not rows:
                return f"every in-scope asset in {ctx.program} is touched by a probe or a fact"
            return (f"UNTESTED assets in {ctx.program} ({len(rows)}):\n"
                    + "\n".join(f"  #{a['id']} {a['kind']} {a['identifier']}" for a in rows))
        return gnoc_graph.assets_text(ctx.program or None, kind=(kind or None),
                                      query=str(query or ""), limit=int(limit or 100), db_path=dbp)
    except Exception as e:  # noqa: BLE001
        return f"asset {action} failed: {type(e).__name__}: {str(e)[:300]}"


def t_node(ctx, action="search", kind="", title="", body="", node_id=0, src_id=0, dst_id=0,
           state="", priority=0, query="", limit=60, asset_ids=None, parent_ids=None, rel="", attrs=None,
           content="", todo_id=0, depends_on=None, trace_ids=None, tool="", args="", result="",
           evidence_ids=None, trace_id=0, finding_id=0, severity="", confidence="",
           method="", url="", status=None, request="", response="",
           worker="worker", lease_secs=600, error=""):
    """The exploration graph: add / search / detail / update / link, plus the durable todo list, worker
    traces, deduplicated evidence and the findings lifecycle (todo_*, trace_*, evidence_*, finding_*)."""
    (
        _graph_db, _graph_extras, _graph_usage, gnoc_graph, t_approvals, t_evidence,
        t_finding, t_todo, t_trace,
    ) = bind(
        "_graph_db", "_graph_extras", "_graph_usage", "gnoc_graph", "t_approvals",
        "t_evidence", "t_finding", "t_todo", "t_trace",
    )
    actions = ("add", "search", "detail", "update", "link",
               "todo_list", "todo_add", "todo_update", "todo_claim", "todo_heartbeat", "todo_release",
               "trace_search", "trace_get", "trace_add",
               "evidence_add", "evidence_search", "evidence_get",
               "finding_add", "finding_update", "finding_list", "finding_get",
               "approval_list")
    action = str(action or "search").strip().lower()
    if action not in actions:
        return _graph_usage("node", actions)
    if not ctx.program:
        return "no active program: set_program first"
    if action == "approval_list":
        return t_approvals(ctx, state=state, query=query, limit=limit)
    if action.startswith("todo_"):
        return t_todo(ctx, action=action[5:], content=content, todo_id=todo_id, state=state,
                      depends_on=depends_on, worker=worker, lease_secs=lease_secs,
                      error=(body if action == "todo_release" else error))
    if action.startswith("trace_"):
        return t_trace(ctx, action=action[6:], query=query, trace_ids=trace_ids, node_id=node_id,
                       limit=limit, tool=tool, args=args, result=result)
    if action.startswith("evidence_"):
        ev_assets = _graph_extras(asset_ids)
        return t_evidence(ctx, action=action[9:], evidence_ids=evidence_ids, trace_id=trace_id,
                          asset_id=(ev_assets[0] if ev_assets else 0),
                          kind=kind, title=title, body=body, method=method, url=url, status=status,
                          request=request, response=response, query=query, limit=limit)
    if action.startswith("finding_"):
        return t_finding(ctx, action=action[8:], finding_id=finding_id, title=title, body=body,
                         state=state, severity=severity, confidence=confidence, asset_ids=asset_ids,
                         evidence_ids=evidence_ids, query=query, limit=limit)
    dbp = _graph_db()
    try:
        if action == "add":
            if not kind or not title:
                return "bad arguments: node action=add needs kind and title"
            node = gnoc_graph.add_node(ctx.program, str(kind), str(title), body=str(body or ""),
                                       state=(state or None), priority=int(priority or 0),
                                       attrs=attrs or {}, asset_ids=_graph_extras(asset_ids),
                                       parent_ids=_graph_extras(parent_ids), rel=(rel or None),
                                       db_path=dbp)
            return f"node #{node['id']} recorded\n" + gnoc_graph.node_text(ctx.program, node["id"], dbp)
        if action == "detail":
            if not node_id:
                return "bad arguments: node action=detail needs node_id"
            return gnoc_graph.node_text(ctx.program, int(node_id), dbp)
        if action == "update":
            if not node_id:
                return "bad arguments: node action=update needs node_id"
            gnoc_graph.update_node(ctx.program, int(node_id), state=(state or None),
                                   body=(body if body != "" else None), title=(title or None),
                                   priority=(int(priority) if priority not in (None, "") else None),
                                   attrs=attrs or None, db_path=dbp)
            return gnoc_graph.node_text(ctx.program, int(node_id), dbp)
        if action == "link":
            if not src_id or not dst_id:
                return "bad arguments: node action=link needs src_id and dst_id"
            return gnoc_graph.link_nodes(ctx.program, int(src_id), int(dst_id),
                                         rel=str(rel or "derived_from"), db_path=dbp)
        return gnoc_graph.nodes_text(ctx.program, kind=(kind or None), state=(state or None),
                                     query=str(query or ""), limit=int(limit or 60), db_path=dbp)
    except Exception as e:  # noqa: BLE001
        return f"node {action} failed: {type(e).__name__}: {str(e)[:300]}"


def t_todo(ctx, action="list", content="", todo_id=0, state="", depends_on=None,
           worker="worker", lease_secs=600, error=""):
    """The durable planning scratchpad: list / add / update / claim / heartbeat / release.
    claim is the planner/worker handoff: it leases a ready todo to one worker; todo_next skips a live lease."""
    (
        _graph_db, _graph_extras, _graph_usage, gnoc_graph,
    ) = bind(
        "_graph_db", "_graph_extras", "_graph_usage", "gnoc_graph",
    )
    actions = ("list", "add", "update", "claim", "heartbeat", "release")
    action = str(action or "list").strip().lower()
    if action not in actions:
        return _graph_usage("todo", actions)
    if not ctx.program:
        return "no active program: set_program first"
    dbp = _graph_db()
    try:
        if action == "add":
            if not content:
                return "bad arguments: todo action=add needs content"
            row = gnoc_graph.todo_add(ctx.program, str(content),
                                      depends_on=_graph_extras(depends_on), db_path=dbp)
            return f"todo #{row['id']} added\n" + gnoc_graph.todos_text(ctx.program, dbp)
        if action == "update":
            if not todo_id:
                return "bad arguments: todo action=update needs todo_id"
            gnoc_graph.todo_update(ctx.program, int(todo_id), state=(state or None),
                                   content=(content if content else None), db_path=dbp)
            return gnoc_graph.todos_text(ctx.program, dbp)
        if action == "claim":
            row = gnoc_graph.todo_claim(ctx.program, todo_id=(int(todo_id) if todo_id else None),
                                        worker=str(worker or "worker"), lease_secs=lease_secs, db_path=dbp)
            return (f"todo #{row['id']} claimed by {row['claimed_by']} until {row['lease_until']} "
                    f"(attempt {row['attempts']})\n  {row['content']}\n" + gnoc_graph.todos_text(ctx.program, dbp))
        if action == "heartbeat":
            if not todo_id:
                return "bad arguments: todo action=heartbeat needs todo_id"
            row = gnoc_graph.todo_heartbeat(ctx.program, int(todo_id), worker=str(worker or "worker"),
                                            lease_secs=lease_secs, db_path=dbp)
            return f"todo #{row['id']} lease extended to {row['lease_until']}"
        if action == "release":
            if not todo_id:
                return "bad arguments: todo action=release needs todo_id"
            row = gnoc_graph.todo_release(ctx.program, int(todo_id), worker=str(worker or "worker"),
                                          state=(state or "pending"), error=error, db_path=dbp)
            return f"todo #{row['id']} released to {row['state']}\n" + gnoc_graph.todos_text(ctx.program, dbp)
        out = gnoc_graph.todos_text(ctx.program, dbp)
        nxt = gnoc_graph.todo_next(ctx.program, dbp)
        return out + (f"\nNEXT: #{nxt['id']} {nxt['content']}" if nxt else "")
    except Exception as e:  # noqa: BLE001
        return f"todo {action} failed: {type(e).__name__}: {str(e)[:300]}"


def t_trace(ctx, action="search", query="", trace_ids=None, node_id=0, limit=50,
            exclude_node=0, tool="", args="", result=""):
    """Worker traces: search / get / add. Every _send probe is recorded automatically."""
    (
        _graph_db, _graph_extras, _graph_usage, gnoc_graph,
    ) = bind(
        "_graph_db", "_graph_extras", "_graph_usage", "gnoc_graph",
    )
    actions = ("search", "get", "add")
    action = str(action or "search").strip().lower()
    if action not in actions:
        return _graph_usage("trace", actions)
    if not ctx.program:
        return "no active program: set_program first"
    dbp = _graph_db()
    try:
        if action == "get":
            ids = _graph_extras(trace_ids)
            if not ids:
                return "bad arguments: trace action=get needs trace_ids"
            rows = gnoc_graph.trace_get(ctx.program, ids, dbp)
            if not rows:
                return "no matching traces"
            out = []
            for r in rows:
                out.append(f"TRACE #{r['id']} {r['created_at']} {r['worker']}/{r['tool']}\n"
                           f"  args: {r['args']}\n  result: {r['result']}")
            return "\n\n".join(out)
        if action == "add":
            if not tool:
                return "bad arguments: trace action=add needs tool"
            row = gnoc_graph.trace_add(ctx.program, str(tool), str(args or ""), str(result or ""),
                                       node_id=(int(node_id) if node_id else None), db_path=dbp)
            return f"trace #{row['id']} recorded"
        return gnoc_graph.traces_text(ctx.program, query=str(query or ""), limit=int(limit or 50), db_path=dbp)
    except Exception as e:  # noqa: BLE001
        return f"trace {action} failed: {type(e).__name__}: {str(e)[:300]}"


def t_evidence(ctx, action="search", evidence_ids=None, trace_id=0, asset_id=0, kind="", title="",
               body="", method="", url="", status=None, request="", response="", query="", limit=50):
    """Evidence: add / search / get. `add` promotes a trace (trace_id) or a manual observation into
    deduplicated evidence; the same observation increments seen_count instead of duplicating."""
    (
        _graph_db, _graph_extras, _graph_usage, gnoc_graph,
    ) = bind(
        "_graph_db", "_graph_extras", "_graph_usage", "gnoc_graph",
    )
    actions = ("add", "search", "get")
    action = str(action or "search").strip().lower()
    if action not in actions:
        return _graph_usage("evidence", actions)
    if not ctx.program:
        return "no active program: set_program first"
    dbp = _graph_db()
    try:
        if action == "add":
            if not (trace_id or url or request or response or body):
                return ("bad arguments: evidence action=add needs trace_id, or url/request/response/detail")
            tid = int(trace_id) if trace_id and str(trace_id).strip().isdigit() else None
            aid = int(asset_id) if asset_id and str(asset_id).strip().isdigit() else None
            row = gnoc_graph.evidence_add(ctx.program, trace_id=tid, asset_id=aid, kind=(kind or "probe"),
                                          label=title, method=method, url=url, status=status,
                                          request=request, response=response, detail=body, db_path=dbp)
            asset = row.get("asset") or {}
            return (f"evidence #{row['id']} recorded (sha {row['sha256'][:12]}, seen {row['seen_count']})"
                    + (f"\n  asset: #{asset['id']} {asset['identifier']}" if asset else "")
                    + (f"\n  trace: #{row['trace']['id']} {row['trace']['tool']}" if row.get("trace") else ""))
        if action == "get":
            ids = _graph_extras(evidence_ids)
            if not ids:
                return "bad arguments: evidence action=get needs evidence_ids"
            rows = gnoc_graph.evidence_get(ctx.program, ids, dbp)
            if not rows:
                return "no matching evidence"
            out = []
            for r in rows:
                asset = r.get("asset") or {}
                out.append(f"EVIDENCE #{r['id']} {r['kind']} {r['method']} {r['url']}"
                           + (f" -> {r['status']}" if r.get("status") is not None else "")
                           + f"  seen={r['seen_count']}  sha={r['sha256'][:12]}\n"
                           + (f"  label: {r['label']}\n" if r.get("label") else "")
                           + (f"  asset: #{asset['id']} {asset['identifier']}\n" if asset else "")
                           + (f"  raw: {r['raw_path']} sha={r['raw_sha256'][:12]}\n" if r.get("raw_path") else "")
                           + (f"  request: {str(r['request'])[:1200]}\n" if r.get("request") else "")
                           + (f"  response: {str(r['response'])[:1600]}\n" if r.get("response") else "")
                           + (f"  detail: {str(r['detail'])[:1200]}" if r.get("detail") else ""))
            return "\n\n".join(out)
        return gnoc_graph.evidence_text(ctx.program, query=str(query or ""), limit=int(limit or 40), db_path=dbp)
    except Exception as e:  # noqa: BLE001
        return f"evidence {action} failed: {type(e).__name__}: {str(e)[:300]}"


def _finding_view(row):
    lines = [f"FINDING #{row['id']} [{row['state']}] {row['severity'] or '-'}/{row['confidence'] or '-'} "
             f"{row['title']}"]
    if row.get("body"):
        lines.append("  body: " + " ".join(str(row["body"]).split())[:1200])
    if row.get("assets"):
        lines.append("  assets: " + ", ".join(f"#{a['id']} {a['identifier']}" for a in row["assets"][:12]))
    if row.get("evidence"):
        lines.append("  evidence: " + ", ".join(
            f"#{e['id']} {e['method']} {e['url']}" + (f"->{e['status']}" if e.get("status") is not None else "")
            for e in row["evidence"][:12]))
    return "\n".join(lines)


def t_finding(ctx, action="list", finding_id=0, title="", body="", state="", severity="", confidence="",
              asset_ids=None, evidence_ids=None, query="", limit=50):
    """Findings lifecycle: list / add / update / get. candidate -> triaged -> confirmed -> reported.
    confirmed needs severity, confidence, a body (impact+reproduction), one evidence record and one asset."""
    (
        _finding_view, _graph_db, _graph_extras, _graph_usage, gnoc_graph,
    ) = bind(
        "_finding_view", "_graph_db", "_graph_extras", "_graph_usage", "gnoc_graph",
    )
    actions = ("list", "add", "update", "get")
    action = str(action or "list").strip().lower()
    if action not in actions:
        return _graph_usage("finding", actions)
    if not ctx.program:
        return "no active program: set_program first"
    dbp = _graph_db()
    try:
        if action == "add":
            if not title:
                return "bad arguments: finding action=add needs title"
            row = gnoc_graph.finding_add(ctx.program, str(title), body=str(body or ""),
                                         severity=str(severity or ""), confidence=str(confidence or ""),
                                         asset_ids=_graph_extras(asset_ids),
                                         evidence_ids=_graph_extras(evidence_ids),
                                         state=(state or "candidate"), db_path=dbp)
            return "finding recorded\n" + _finding_view(row)
        if action == "update":
            if not finding_id:
                return "bad arguments: finding action=update needs finding_id"
            aids = _graph_extras(asset_ids) if asset_ids not in (None, "", []) else None
            eids = _graph_extras(evidence_ids) if evidence_ids not in (None, "", []) else None
            row = gnoc_graph.finding_update(ctx.program, int(finding_id), state=(state or None),
                                            severity=(severity or None), confidence=(confidence or None),
                                            title=(title or None), body=(body if body != "" else None),
                                            asset_ids=aids, evidence_ids=eids, db_path=dbp)
            return "finding updated\n" + _finding_view(row)
        if action == "get":
            if not finding_id:
                return "bad arguments: finding action=get needs finding_id"
            row = gnoc_graph.finding_get(ctx.program, int(finding_id), dbp)
            return _finding_view(row) if row else f"no finding #{finding_id} in {ctx.program}"
        return gnoc_graph.findings_text(ctx.program, state=(state or ""), query=str(query or ""),
                                        limit=int(limit or 50), db_path=dbp)
    except Exception as e:  # noqa: BLE001
        return f"finding {action} failed: {type(e).__name__}: {str(e)[:300]}"


def t_approvals(ctx, action="list", state="", query="", limit=50):
    """Read the intercept approval queue for the active program. Decisions are operator-only
    (/approve, /deny or `gnoc approvals`), never a model tool."""
    (
        _graph_db, _graph_usage, gnoc_graph,
    ) = bind(
        "_graph_db", "_graph_usage", "gnoc_graph",
    )
    def clip(text, n):
        return " ".join(str(text or "").split())[:n]
    if str(action or "list").strip().lower() != "list":
        return _graph_usage("approval", ("list",))
    if not ctx.program:
        return "no active program: set_program first"
    dbp = _graph_db()
    try:
        rows = gnoc_graph.approval_list(ctx.program, state=(state or "pending"),
                                        limit=int(limit or 50), db_path=dbp)
        if query:
            q = str(query).lower()
            rows = [r for r in rows if q in str(r.get("summary", "")).lower()
                    or q in str(r.get("action", "")).lower() or q in str(r.get("risk", "")).lower()]
        if not rows:
            return f"no approvals in {ctx.program}" + (f" matching {query!r}" if query else "")
        lines = [f"APPROVALS - {ctx.program} ({len(rows)} shown)"]
        for r in rows:
            used = " used" if r.get("used_at") else ""
            lines.append(f"  #{r['id']} [{r['state']}{used}] {r['action']}: {clip(r['summary'], 120)}")
            lines.append(f"       requested by {r['requested_by']}  expires {r['expires_at']}"
                         + (f"  reason={clip(r['reason'], 80)}" if r.get("reason") else ""))
        return "\n".join(lines)
    except Exception as e:  # noqa: BLE001
        return f"approval list failed: {type(e).__name__}: {str(e)[:300]}"
