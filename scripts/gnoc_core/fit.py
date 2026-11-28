"""Fitting the tool schemas to the model's context: the pinned core sets, the per-turn budget and the ranking."""
import re
from .runtime import bind


# Always loaded, whatever the budget: without these a turn cannot read, look, run or answer.
TOOL_CORE = ("read_file", "list_dir", "grep", "bash", "edit_file", "write_file", "gnoc", "hunt_brief",
             "site_status", "tasks", "plan")  # plan is core: planning must never depend on the turn's fit


# How much of the context the tool schemas may take. The rest is the system prompt, the history and the
# reply, and the history is what gets folded away when this is too greedy.
# On a HUNT turn these join the core and are never trimmed. Each is load-bearing for a gate, not a
# convenience: race is the burst control the floor requires, liveness feeds the T-241 re-fire, pay_check
# is the filing gate, oast is the blind-class oracle. Measured 2026-10-25: fitting a hunt to the 16k
# fallback silently dropped race, liveness and pay_check, which a hunt must never be asked to re-request.
HUNT_CORE = ("http_request", "graphql", "probe_matrix", "oast", "race", "dedup", "liveness", "pay_check",
             "hunt_brief", "hunt_model", "hunt_hypothesis", "hunt_phase",
             "graph_overview", "asset", "node")


# The same pinning for a CODING turn, and for the same measured reason. gnoc_modes' swe directive requires
# repo_map / find_symbol at step 1, run_tests at step 4 and code_review at step 5 - but nothing pinned them, so
# on the 16 GB fallback (16k context, 18.3k of schema) a coding turn could lose exactly the tools that make the
# difference between a change and a claim, and the model would then "verify" by reading the file again. A hunt
# that cannot burst and a refactor that cannot run its tests are the same bug (2026-10-26).
SWE_CORE = ("repo_map", "find_symbol", "find_file", "apply_patch", "run_tests", "lint", "typecheck", "code_review",
            "git")


# A WEB APP turn adds the three that see the running thing. A change to a route, a template or a component that
# was verified only by reading the source is unverified: the page is the test.
WEB_CORE = SWE_CORE + ("browser", "http_request", "site_status", "bg")   # bg: the dev server the page is served by


def tool_budget(host, model=None):
    """Tokens the schemas may take on this host: the context MINUS what the prompt, the history and the
    reply need (desktop 32k -> ~18k, the 16k fallback -> a list that leaves room to actually work).

    It was originally sized so the whole registry "just fit" a big host. It no longer does and should not
    be re-tuned to: the registry grows, the context does not, so per-turn selection is load-bearing on
    every host. What must hold is that TOOL_CORE and HUNT_CORE always survive, which fit_tools pins."""
    (
        ctx_for,
    ) = bind(
        "ctx_for",
    )
    ctx = ctx_for(host, model)
    reserve = max(9000, int(ctx * 0.45))
    return max(2500, ctx - reserve)


_TOOL_WORD = re.compile(r"[a-z_]{3,}")


def _tool_text(t):
    f = t.get("function") or {}
    return (f.get("name", "") + " " + (f.get("description") or "")).lower()


# A picture request pins the image tool (and write_file, for an SVG): generate_image's long schema lost to the 16k
# budget on "make an image of a red apple ...", and the lead said "I'll call generate_image" four times with no
# such tool in the request (image drive, 2026-11-23).
_PICTURE = re.compile(r"\b(?:generat\w*|make|create|draw|render|produce|paint|design)\b[^.?!]{0,60}\b(?:image|photo|picture|"
                      r"pic|png|jpe?g|drawing|illustration|logo|icon|wallpaper|artwork|poster|banner|sticker|svg)s?\b|"
                      r"\b(?:image|photo|picture|logo|illustration|wallpaper)\s+of\b|"
                      r"^\s*(?:can\s+you\s+|please\s+)?draw\s+(?:me\s+)?(?:a|an|the|some)\b|"
                      # a bare request: "a watercolour painting of a fishing village at dawn, square, no text"
                      r"^\s*(?:a|an)\s+(?:[\w-]+\s+){0,3}(?:painting|illustration|drawing|photo(?:graph)?|picture|image|"
                      r"render(?:ing)?|poster|portrait|sketch|wallpaper|logo|icon|banner|sticker)s?\s+(?:of|for)\b", re.I)
_PICTURE_CORE = ("generate_image", "write_file")


# HIS OWN SITE, TESTED: "red team my site, just the headers and cookies" never called site_redteam; the 9B tried
# http_request (refused: no program), the browser and `gnoc headers` for 7 minutes (defense batch 25).
_OWN_SITE = re.compile(r"\b(?:my|our|the|his)\s+(?:own\s+)?(?:site|website|web\s*site|web\s*app|server|dashboard)(?:'s)?\b|"
                       r"\bchat\.your-site\.example\b|\bsite_redteam\b", re.I)
_SITE_TEST = re.compile(r"\b(?:red[- ]?team\w*|pen[- ]?test\w*|security\s+test\w*|attack\s+(?:my|our|the)|actually\s+secure|"
                        r"prove\s+it|headers?|cookies?|hsts|csp|cors|content[- ]security[- ]policy|untested|not\s+test\w*|"
                        r"findings?)\b", re.I)


def redteam_checks(text):
    """The site_redteam checks his words name, '' for the whole drill, or None when this is not about testing
    his own site."""
    t = str(text or "")
    if not (_OWN_SITE.search(t) and _SITE_TEST.search(t)) or re.search(r"\b(?:program|bounty|scope|target)\b", t, re.I):
        return None
    if re.match(r"(?i)\W*what(?:'s|\s+is|\s+are|\s+does)\s+(?:a|an|the\s+difference)\b", t) or re.search(
            r"(?i)\b(?:fix|add|implement|refactor|rename|style|build|edit|write|code|change|remove|deploy)\b", t):
        return None   # "what is a red team" is a question, "fix the header on my website" is a code change
    want = []
    for rx, name in ((r"\bheaders?\b|\bcsp\b|content[- ]security", "headers"), (r"\bcookies?\b", "cookies"),
                     (r"\bcors\b", "cors"), (r"\bhsts\b|\bedge\b|cloudflare", "edge"),
                     (r"\buntested\b|\bnot\s+test\w*|\bdid\s*n[o']t\s+(?:test|cover|check)|\bsurface\b", "surface"),
                     (r"\bauth\w*\b|\badmin\b", "authz")):
        if re.search(rx, t, re.I):
            want.append(name)
    return " ".join(dict.fromkeys(want))


def _turn_core(user_text, hunting=False, in_code=False):
    base = _turn_core_base(user_text, hunting, in_code)
    _exact = ""
    with __import__("contextlib").suppress(Exception):
        _exact = (__import__("gnoc_draw").plan(user_text or "")   # a chart or an exact shape ("plot my coffee ...")
                  or __import__("gnoc_draw").edit_plan(user_text or ""))   # or an edit of an existing picture
    if not hunting and (_PICTURE.search(user_text or "") or _exact):
        return tuple(dict.fromkeys(tuple(base or ()) + _PICTURE_CORE))
    if not hunting and redteam_checks(user_text) is not None:
        return tuple(dict.fromkeys(tuple(base or ()) + ("site_redteam",)))
    with __import__("contextlib").suppress(Exception):
        if __import__("gnoc_recall").PAST_CHAT.search(user_text or ""):
            return tuple(dict.fromkeys(tuple(base or ()) + ("recall",)))   # "what did we decide last week"
    return base


def _turn_core_base(user_text, hunting=False, in_code=False):
    """Which tool set this turn may never lose. A hunt keeps HUNT_CORE; a coding or review turn keeps SWE_CORE,
    and a web-app one keeps WEB_CORE on top. Detection is gnoc_modes', so the pinned tools and the directive the
    model is reading always come from the same decision."""
    (
        HUNT_CORE, SWE_CORE, WEB_CORE, _ATTACKY, _SWE_VERB, _WEBAPP, gnoc_modes,
    ) = bind(
        "HUNT_CORE", "SWE_CORE", "WEB_CORE", "_ATTACKY", "_SWE_VERB", "_WEBAPP", "gnoc_modes",
    )
    if hunting:
        return HUNT_CORE
    try:
        mode = gnoc_modes.detect(user_text or "")
    except Exception:   # noqa: BLE001 - tool fitting must never fail a turn
        mode = None
    web = bool(_WEBAPP.search(user_text or ""))
    # "fix the layout on the settings page" is a coding turn that gnoc_modes.detect does not match: its swe
    # vocabulary is backend-shaped (refactor, migrate, traceback). Rather than widen that regex, where a web
    # noun would start stealing hunt turns ("probe the login PAGE for XSS"), treat an unclassified turn as
    # coding when it is in a repo or speaks web. detect() having returned "hunt" or "prod" still wins.
    # a plain build verb outranks the attack guard: "fix the RACE CONDITION in the worker pool" is a refactor,
    # and a turn that detect() already read as "hunt" never reaches here anyway.
    attacky = _ATTACKY.search(user_text or "") and not _SWE_VERB.search(user_text or "")
    # "design" is the coding sibling added for website work: its loop needs the same tools that prove a change,
    # and on a web turn the ones that see the page (2026-10-29: detect() started matching design phrasing, but
    # this branch did not, so a design turn pinned NOTHING and the 16k fallback could drop browser/run_tests).
    if mode in ("swe", "review", "design") or (mode is None and (in_code or web or _SWE_VERB.search(user_text or "")) and not attacky):
        return WEB_CORE if web else SWE_CORE
    return ()


# An unclassified turn that speaks attack is not a coding turn, whatever web nouns it carries: gnoc_modes'
# hunt regex misses "test the checkout endpoint for a RACE", and pinning browser tools there would be wrong.
_SWE_VERB = re.compile(r"\b(fix|add|implement|refactor|rename|migrate|write|debug|port|upgrade|wire|style)\b", re.I)


_ATTACKY = re.compile(r"\b(race|toctou|burst|exploit|payload|vulnerab|unauth|bypass|privesc|escalat|"
                      r"cross-tenant|cross-user|leak|exfil|poison|smuggl|injection|traversal|takeover)\b", re.I)


# Words that mean "the thing under change is served to a browser", so reading the source is not verification.
_WEBAPP = re.compile(r"\b(web ?app|frontend|front-end|browser|page|route|endpoint|url|html|css|dom|react|vue|"
                     r"svelte|next\.?js|nuxt|astro|django|rails|flask|express|fastapi|template|component|"
                     r"localhost:\d+|127\.0\.0\.1:\d+|render|responsive|layout|form|button|click)\b", re.I)


def fit_tools(tools, budget_tokens, user_text="", sticky=(), core=()):
    """The subset of `tools` that fits `budget_tokens`, chosen for THIS turn.

    77 schemas are 18.3k tokens; the laptop model's whole context is 16.4k, so when the desktop drops and
    the chat falls back, every request overflowed before a single history message was added (measured
    2026-10-25: "request (19919 tokens) exceeds the ..."). Trimming descriptions does not fix an order-of-
    magnitude gap - the LIST has to be shorter, per turn.

    Order: the core tools, then the ones already used in this conversation (a task keeps its tools across
    turns), then the ones whose name or description match what he just said, then the rest in registry
    order until the budget is spent. Returns (subset, dropped_names).
    """
    (
        TOOL_CORE, _TOOL_WORD, _name_hits, _tool_text, _tool_tokens,
    ) = bind(
        "TOOL_CORE", "_TOOL_WORD", "_name_hits", "_tool_text", "_tool_tokens",
    )
    tools = list(tools or [])
    if not tools or budget_tokens <= 0 or _tool_tokens(tools) <= budget_tokens:
        return tools, []
    by_name = {(t.get("function") or {}).get("name"): t for t in tools}
    words = set(_TOOL_WORD.findall((user_text or "").lower()))
    keep_core = set(TOOL_CORE) | set(core or ())
    scored = []
    for name, t in by_name.items():
        if name in keep_core:
            rank = 0
        elif name in set(sticky or ()):
            rank = 1
        else:
            text = _tool_text(t)
            hits = sum(1 for w in words if len(w) > 3 and w in text)
            rank = 2 if hits else 3
        scored.append((rank, -_name_hits(name, words), name))
    scored.sort()
    out, used = [], 0
    for rank, _, name in scored:
        t = by_name[name]
        cost = _tool_tokens([t])
        if used + cost > budget_tokens and rank > 1:   # core and sticky are never dropped for budget
            continue
        out.append(t)
        used += cost
    kept = {(t.get("function") or {}).get("name") for t in out}
    return out, sorted(n for n in by_name if n not in kept)


def _name_hits(name, words):
    """A tool whose NAME he said outranks one that merely mentions the word in its description."""
    parts = set(name.lower().split("_"))
    return len(parts & words) * 2 + (1 if name.lower() in words else 0)


def remember_tools(ctx, names):
    """Keep the tools this conversation actually uses, so the next turn still carries them."""
    if not names:
        return
    s = getattr(ctx, "s", None)
    if s is None:
        return
    keep = [n for n in (s.get("_tool_sticky") or []) if n not in names]
    s["_tool_sticky"] = (list(names) + keep)[:24]


def wanted_tools(text, known):
    """Tool names the model NAMED in its answer or reasoning. A turn whose tool was trimmed away says so
    in words ("I would use probe_matrix"); that is the signal to carry it next turn."""
    (
        re,
    ) = bind(
        "re",
    )
    if not text:
        return []
    low = text.lower()
    # word boundaries, not a length cutoff: a >4 filter silently excluded oast, bash, gnoc and race,
    # while a bare substring test matches "race" inside "trace" and "bot" inside "robots".
    return [n for n in known if re.search(r"\b" + re.escape(n.lower()) + r"\b", low)]


def turn_tools(small, direct, hunt=False, code=False, general=False, world=False):
    """The tool list for one turn. A greeting gets none; a world-knowledge question (is_general_question) gets
    only the web; a direct question gets everything except the tools
    that spawn bots, so it can still read a file or check a fact but cannot start a hunt; a hunt directive
    turn gets the hunting subset (HUNT_TOOLS); a turn in a code repo outside the hunt workspace gets CODE_TOOLS;
    a general-stance turn in the workspace gets everything but the hunt machinery (GENERAL_EXCLUDE)."""
    (
        CODE_TOOLS, GENERAL_EXCLUDE, HUNT_TOOLS, MCP_DIRTY, TOOLS, _SPAWN_TOOLS, offline, os, register_mcp_tools,
    ) = bind(
        "CODE_TOOLS", "GENERAL_EXCLUDE", "HUNT_TOOLS", "MCP_DIRTY", "TOOLS", "_SPAWN_TOOLS", "offline", "os",
        "register_mcp_tools",
    )
    if MCP_DIRTY[0]:   # an mcp listing refreshed the cache last turn: swap the native tools in here, between turns
        MCP_DIRTY[0] = False
        try:
            register_mcp_tools()
        except Exception:  # noqa: BLE001 - a broken cache never costs the turn its tools
            pass
    if small:
        return []
    if world:
        return [TOOLS[n][1] for n in ("web_search", "web_fetch") if n in TOOLS]
    trim = hunt and os.environ.get("GNOC_HUNT_TOOLS_ALL") != "1"
    ctrim = code and not hunt and os.environ.get("GNOC_CODE_TOOLS_ALL") != "1"
    gtrim = general and not hunt and not ctrim
    return [t[1] for n, t in TOOLS.items()
            if not (offline() and n == "claude_worker") and not (direct and n in _SPAWN_TOOLS)
            and not (trim and n not in HUNT_TOOLS) and not (ctrim and n not in CODE_TOOLS)
            and not (gtrim and n in GENERAL_EXCLUDE)]
