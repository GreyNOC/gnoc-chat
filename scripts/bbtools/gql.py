#!/usr/bin/env python3
"""
gql.py - GraphQL probe helper. Introspection, persisted-query (APQ) hash + register-on-miss,
alias batching, and schema mapping with induction when introspection is disabled.

  gql(session, url, query, variables, headers, extensions)   POST, return {status, json|text}
  introspect(session, url, full=True)                        schema dump (or the minimal probe)
  apq_hash(query)                                            Apollo persisted-query sha256 hex
  apq_probe(session, url, query)                             hash-only; on PERSISTED_QUERY_NOT_FOUND
                                                             register it and replay (the cache-
                                                             deception / auth-bypass seam)
  alias_batch(field, args_list, selection)                  N calls in ONE request (rate/oracle bypass)
  schema_map(session, endpoint, scope_file=None)            full schema recon: introspection +
                                                             induction from field-suggestion errors +
                                                             hidden-endpoint correlation. Returns
                                                             {introspection_on, types, queries,
                                                              mutations, sensitive_ops, hidden_endpoints}

CLI: gql.py selfcheck            (offline: apq hashing, alias batching, register-on-miss on a mock,
                                   induction from suggestion errors, introspection parse, scope-gate)
     gql.py schema-map <url>     [--scope SCOPE.txt]  live schema recon
"""
import hashlib, json, re, sys
from urllib.parse import urlparse

MINIMAL_INTROSPECT = "{__schema{queryType{name} types{name kind}}}"
FULL_INTROSPECT = ("query{__schema{queryType{name} mutationType{name} "
                   "types{name kind fields{name args{name} type{name kind ofType{name}}}}}}")

# Common paths to probe for hidden GraphQL endpoints on the same host
_GQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/gql",
    "/query",
    "/graphql/console",
    "/graphiql",
    "/playground",
    "/api/gql",
]

# Op-name fragments that flag a likely-sensitive operation
_SENSITIVE_RE = re.compile(
    r"(user|account|admin|internal|node|secret|token|payment|password|credit|ssn|pii"
    r"|billing|invoice|wallet|transfer|withdraw|balance|refund|charge|subscription"
    r"|role|permission|privilege|grant|impersonat|sudo|staff|employee|backdoor"
    r"|debug|test|dev|reset|verify|confirm)",
    re.IGNORECASE,
)

# Extract field/type names from "Did you mean X?" style error suggestions
_DID_YOU_MEAN_RE = re.compile(
    r'(?:Did you mean|suggestions?)[^\w"]*["\']?([A-Za-z_][A-Za-z0-9_]*)["\']?',
    re.IGNORECASE,
)
# "Cannot query field \"X\" on type \"Y\"" - grab X and Y
_CANNOT_QUERY_RE = re.compile(
    r'Cannot query field\s+"([A-Za-z_][A-Za-z0-9_]*)"\s+on type\s+"([A-Za-z_][A-Za-z0-9_]*)"',
    re.IGNORECASE,
)
# "Field \"X\" of type \"Y\"" or "Unknown field \"X\"" or "Unknown argument \"X\""
_FIELD_RE = re.compile(
    r'(?:Field|argument|directive)\s+"([A-Za-z_][A-Za-z0-9_]*)"',
    re.IGNORECASE,
)
# "Unknown type \"X\""
_TYPE_RE = re.compile(
    r'Unknown type[:\s]+"([A-Za-z_][A-Za-z0-9_]*)"',
    re.IGNORECASE,
)


def gql(session, url, query=None, variables=None, headers=None, extensions=None):
    body = {}
    if query:
        body["query"] = query
    if variables is not None:
        body["variables"] = variables
    if extensions is not None:
        body["extensions"] = extensions
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    r = session.post(url, json=body, headers=h, timeout=20)
    try:
        return {"status": r.status_code, "json": r.json()}
    except Exception:
        return {"status": r.status_code, "text": (getattr(r, "text", "") or "")[:800]}


def introspect(session, url, full=True):
    res = gql(session, url, FULL_INTROSPECT if full else MINIMAL_INTROSPECT)
    j = res.get("json") or {}
    types = ((j.get("data") or {}).get("__schema") or {}).get("types") if j else None
    return {"enabled": bool(types), "type_count": len(types) if types else 0, "raw": res}


def apq_hash(query):
    return hashlib.sha256(query.encode()).hexdigest()


def apq_probe(session, url, query, variables=None):
    """Send only the APQ sha256 hash. If the server answers PERSISTED_QUERY_NOT_FOUND it
    accepts client-registered queries (register-on-miss) - the cache-deception / auth-bypass
    seam. Returns {hash, hash_only_miss, register_on_miss, ...}."""
    ext = {"persistedQuery": {"version": 1, "sha256Hash": apq_hash(query)}}
    first = gql(session, url, query=None, variables=variables, extensions=ext)   # hash only
    miss = "PERSISTED_QUERY_NOT_FOUND" in json.dumps(first.get("json") or first.get("text") or "")
    out = {"hash": ext["persistedQuery"]["sha256Hash"], "hash_only_miss": miss, "first": first}
    if miss:
        out["register"] = gql(session, url, query=query, variables=variables, extensions=ext)
        replay = gql(session, url, query=None, variables=variables, extensions=ext)
        out["replay_hash_only"] = replay
        # register-on-miss is confirmed ONLY by a positive data resolve on replay - a non-JSON /
        # WAF / 500 body must NOT read as "registered" (that fabricated the primitive before).
        out["register_on_miss"] = bool((replay.get("json") or {}).get("data"))
    return out


class Raw(str):
    """Wrap a GraphQL enum / raw literal so alias_batch emits it UNQUOTED: Raw('ADMIN')
    renders `type: ADMIN`, not `type: "ADMIN"` (enums must be bare)."""


def alias_batch(field, args_list, selection="id", var_prefix="a"):
    """Build an aliased batched query: N copies of `field` with different args in ONE request
    (bypass per-request rate limits, brute an oracle). args_list = [{arg: value}, ...]. Wrap an
    enum value in Raw('X') so it renders unquoted."""
    parts = []
    for i, args in enumerate(args_list):
        argstr = ", ".join(f"{k}: {v if isinstance(v, Raw) else json.dumps(v)}" for k, v in args.items())
        parts.append(f"{var_prefix}{i}: {field}({argstr}) {{ {selection} }}")
    return "query { " + " ".join(parts) + " }"


# ---------------------------------------------------------------------------
# Schema induction helpers
# ---------------------------------------------------------------------------

def _extract_suggestions(error_text):
    """Mine field/type names from GraphQL error suggestion strings.

    Handles:
      'Cannot query field "emil" on type "User". Did you mean "email"?'
      'Unknown field "acccount". Did you mean "account"?'
      'Suggestions [email, id, name]'
    Returns a set of candidate field/type name strings."""
    names = set()
    for m in _DID_YOU_MEAN_RE.finditer(error_text):
        names.add(m.group(1))
    for m in _CANNOT_QUERY_RE.finditer(error_text):
        names.add(m.group(1))   # the queried (typo) field
        names.add(m.group(2))   # the type it was queried on
    for m in _FIELD_RE.finditer(error_text):
        names.add(m.group(1))
    for m in _TYPE_RE.finditer(error_text):
        names.add(m.group(1))
    # strip GraphQL internal names
    names.discard("String")
    names.discard("Int")
    names.discard("Boolean")
    names.discard("Float")
    names.discard("ID")
    return names


def _induction_probes():
    """Return a list of (query_string, description) pairs that trigger error suggestions
    when introspection is disabled. Each query uses a near-miss field name to provoke
    'Did you mean X?' responses from common GraphQL server implementations."""
    return [
        # Common root query fields with typos
        ('query{us{id}}', 'near-miss root: us -> user/users'),
        ('query{acccount{id}}', 'near-miss root: acccount -> account'),
        ('query{admn{id}}', 'near-miss root: admn -> admin'),
        ('query{nde(id:"1"){id}}', 'near-miss root: nde -> node'),
        ('query{vewer{id}}', 'near-miss root: vewer -> viewer'),
        ('query{profle{id}}', 'near-miss root: profle -> profile'),
        ('query{searc(q:"x"){id}}', 'near-miss root: searc -> search'),
        ('query{ordr{id}}', 'near-miss root: ordr -> order/orders'),
        ('query{paymnt{id}}', 'near-miss root: paymnt -> payment'),
        ('query{tokn{id}}', 'near-miss root: tokn -> token'),
        # Common mutation fields with typos
        ('mutation{creatUser(input:{}){id}}', 'near-miss mutation: creatUser -> createUser'),
        ('mutation{delet(id:"1"){id}}', 'near-miss mutation: delet -> delete/deleteUser'),
        ('mutation{updat(input:{}){id}}', 'near-miss mutation: updat -> update'),
        ('mutation{logn(email:"x",password:"y"){token}}', 'near-miss mutation: logn -> login'),
        ('mutation{signUp(input:{}){id}}', 'near-miss mutation: signUp exact + field suggestions'),
        # Type probing - force type errors to reveal type names
        ('{__typename}', 'root typename probe'),
        ('query{user(id:"1"){emil}}', 'field-on-type near-miss: emil -> email on User'),
        ('query{user(id:"1"){passwrd}}', 'field-on-type near-miss: passwrd -> password'),
        ('query{user(id:"1"){accesToken}}', 'field-on-type near-miss: accesToken -> accessToken'),
        # APQ hash probe to reveal if persisted queries expose op names
        ('{__schema{queryType{nme}}}', 'introspect near-miss: nme -> name (reveals if __schema works)'),
    ]


def _parse_introspection_schema(raw_json):
    """Parse a full introspection response into {types, queries, mutations}.
    Returns None if the JSON does not contain __schema data."""
    schema = (((raw_json or {}).get("data") or {}).get("__schema") or {})
    if not schema:
        return None
    all_types = schema.get("types") or []
    types = {}
    queries = []
    mutations = []
    for t in all_types:
        name = t.get("name", "")
        if name.startswith("__"):
            continue
        kind = t.get("kind", "")
        fields = [f.get("name") for f in (t.get("fields") or []) if f.get("name")]
        types[name] = {"kind": kind, "fields": fields}

    qt_name = (schema.get("queryType") or {}).get("name", "Query")
    mt_name = ((schema.get("mutationType") or {}) or {}).get("name", "Mutation")

    qt = types.get(qt_name, {})
    for f in qt.get("fields") or []:
        queries.append(f)
    mt = types.get(mt_name, {})
    for f in mt.get("fields") or []:
        mutations.append(f)

    return {"types": types, "queries": queries, "mutations": mutations}


def _is_graphql_endpoint(res):
    """Return True if the response looks like a GraphQL server (not a 404/HTML wall)."""
    if res.get("status") in (400, 422, 200):
        j = res.get("json") or {}
        if "errors" in j or "data" in j:
            return True
        text = res.get("text", "") or ""
        if "graphql" in text.lower() or "query" in text.lower():
            return True
    return False


def schema_map(session, endpoint, scope_file=None):
    """Programmatic GraphQL schema recon. Scope-gates the endpoint, tries introspection,
    falls back to schema induction from field-suggestion errors, and correlates hidden
    GraphQL endpoints on the same host.

    Returns:
        {
          introspection_on: bool,
          types: {TypeName: {kind, fields}},
          queries: [str],
          mutations: [str],
          sensitive_ops: [str],
          hidden_endpoints: [str],    # paths that answered as a GQL server
        }
    """
    # 1. Scope-gate
    if scope_file is not None:
        import os as _os
        _HERE = _os.path.dirname(_os.path.abspath(__file__))
        if _HERE not in sys.path:
            sys.path.insert(0, _HERE)
        from lib_scope import in_scope as _in_scope, extract_host as _extract_host
        host = _extract_host(endpoint)
        if not _in_scope(host, scope_file):
            raise ValueError(f"OUT_OF_SCOPE {host} (not in {scope_file})")

    result = {
        "introspection_on": False,
        "types": {},
        "queries": [],
        "mutations": [],
        "sensitive_ops": [],
        "hidden_endpoints": [],
    }
    induced_names = set()

    # 2. Try full introspection
    intro_res = gql(session, endpoint, FULL_INTROSPECT)
    intro_json = intro_res.get("json") or {}
    parsed = _parse_introspection_schema(intro_json)

    if parsed:
        result["introspection_on"] = True
        result["types"] = parsed["types"]
        result["queries"] = parsed["queries"]
        result["mutations"] = parsed["mutations"]
    else:
        # 3. Schema induction: mine "Did you mean X?" errors
        for query, _desc in _induction_probes():
            try:
                res = gql(session, endpoint, query)
            except Exception:
                continue
            err_blob = json.dumps(res.get("json") or res.get("text") or "")
            names = _extract_suggestions(err_blob)
            induced_names.update(names)

        # Also try APQ to discover op names server has cached
        try:
            apq_res = apq_probe(session, endpoint, "{__typename}")
            apq_blob = json.dumps(apq_res)
            induced_names.update(_extract_suggestions(apq_blob))
        except Exception:
            pass

        # Bucket induced names into likely queries vs mutations vs types
        mutation_verbs = re.compile(
            r"^(create|update|delete|remove|add|set|reset|send|submit|upload"
            r"|mutate|change|edit|revoke|issue|transfer|withdraw|grant|invite"
            r"|disable|enable|deactivate|activate|assign|unassign|merge|move)",
            re.IGNORECASE,
        )
        for name in sorted(induced_names):
            if mutation_verbs.match(name):
                if name not in result["mutations"]:
                    result["mutations"].append(name)
            elif name[0].isupper():
                # Likely a type name
                if name not in result["types"]:
                    result["types"][name] = {"kind": "induced", "fields": []}
            else:
                if name not in result["queries"]:
                    result["queries"].append(name)

    # 4. Flag sensitive ops
    all_ops = result["queries"] + result["mutations"]
    result["sensitive_ops"] = [op for op in all_ops if _SENSITIVE_RE.search(op)]

    # 5. Correlate hidden endpoints on the same host
    parsed_url = urlparse(endpoint)
    base = f"{parsed_url.scheme}://{parsed_url.netloc}"
    current_path = parsed_url.path.rstrip("/")
    for path in _GQL_PATHS:
        if path == current_path:
            continue
        candidate = base + path
        try:
            # Send a cheap minimal probe; look for a GraphQL-shaped response
            res = gql(session, candidate, "{__typename}")
            if _is_graphql_endpoint(res):
                result["hidden_endpoints"].append(candidate)
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# Mock helpers (shared by existing + new selfcheck)
# ---------------------------------------------------------------------------

class _MockResp:
    def __init__(self, status, payload):
        self.status_code, self._p = status, payload

    def json(self):
        return self._p

    @property
    def text(self):
        return json.dumps(self._p)


class _MockSession:
    def __init__(self, script):
        self.script, self.calls = list(script), []

    def post(self, url, json=None, headers=None, timeout=None):
        self.calls.append(json)
        return self.script.pop(0)


# ---------------------------------------------------------------------------
# Selfcheck
# ---------------------------------------------------------------------------

def _selfcheck():
    # --- existing checks (preserved exactly) ---
    assert apq_hash("query{a}") == hashlib.sha256(b"query{a}").hexdigest()
    q = alias_batch("user", [{"id": 1}, {"id": 2}], "email")
    assert q.count("user(") == 2 and "a0:" in q and "a1:" in q and "id: 1" in q, q
    # enum renders unquoted, string stays quoted
    qe = alias_batch("search", [{"type": Raw("ADMIN"), "q": "x"}], "id")
    assert "type: ADMIN" in qe and 'q: "x"' in qe, qe
    # register-on-miss: hash-only misses -> register -> replay resolves (positive data)
    miss = _MockResp(200, {"errors": [{"message": "PERSISTED_QUERY_NOT_FOUND"}]})
    ok = _MockResp(200, {"data": {"x": 1}})
    out = apq_probe(_MockSession([miss, ok, ok]), "http://x/graphql", "query{x}")
    assert out["hash_only_miss"] and out["register_on_miss"], out
    # a non-JSON / WAF replay must NOT read as registered

    class _Bad:
        status_code = 403

        def json(self):
            raise ValueError("not json")

        @property
        def text(self):
            return "blocked"

    out2 = apq_probe(_MockSession([miss, ok, _Bad()]), "http://x/graphql", "query{x}")
    assert out2["register_on_miss"] is False, out2
    print("SELFCHECK OK  apq_hash, alias_batch(enum-unquoted), apq register-on-miss (+non-json guard) pass")

    # --- new check 1: induction extracts field name from "Did you mean" error ---
    error_msg = 'Cannot query field "emil" on type "User". Did you mean "email"?'
    induced = _extract_suggestions(error_msg)
    assert "email" in induced, f"induction failed to extract 'email' from: {error_msg!r}; got {induced}"
    assert "emil" in induced or "User" in induced  # the queried name and type also captured
    print("SELFCHECK OK  schema induction: _extract_suggestions mines 'email' from Did-you-mean error")

    # --- new check 2: induction with Suggestions-list format ---
    error_msg2 = 'Unknown field "acccount". Suggestions [account, accountId, accountStatus]'
    induced2 = _extract_suggestions(error_msg2)
    # The DID_YOU_MEAN_RE or FIELD_RE must capture at least one of the suggestion names
    assert induced2, f"induction returned empty set from: {error_msg2!r}"
    print("SELFCHECK OK  schema induction: _extract_suggestions handles Suggestions-list format")

    # --- new check 3: introspection parse on a canned introspection JSON ---
    canned_introspect = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": [
                    {
                        "name": "Query",
                        "kind": "OBJECT",
                        "fields": [
                            {"name": "user", "args": [], "type": {"name": "User", "kind": "OBJECT", "ofType": None}},
                            {"name": "adminPanel", "args": [], "type": {"name": "Admin", "kind": "OBJECT", "ofType": None}},
                        ],
                    },
                    {
                        "name": "Mutation",
                        "kind": "OBJECT",
                        "fields": [
                            {"name": "createUser", "args": [], "type": {"name": "User", "kind": "OBJECT", "ofType": None}},
                            {"name": "deleteUser", "args": [], "type": {"name": "Boolean", "kind": "SCALAR", "ofType": None}},
                        ],
                    },
                    {
                        "name": "User",
                        "kind": "OBJECT",
                        "fields": [
                            {"name": "id", "args": [], "type": {"name": "ID", "kind": "SCALAR", "ofType": None}},
                            {"name": "email", "args": [], "type": {"name": "String", "kind": "SCALAR", "ofType": None}},
                        ],
                    },
                    {"name": "__Schema", "kind": "OBJECT", "fields": []},
                ],
            }
        }
    }
    parsed = _parse_introspection_schema(canned_introspect)
    assert parsed is not None, "introspection parse returned None on valid canned JSON"
    assert "user" in parsed["queries"], f"'user' not in queries: {parsed['queries']}"
    assert "adminPanel" in parsed["queries"], f"'adminPanel' not in queries: {parsed['queries']}"
    assert "createUser" in parsed["mutations"], f"'createUser' not in mutations: {parsed['mutations']}"
    assert "deleteUser" in parsed["mutations"], f"'deleteUser' not in mutations: {parsed['mutations']}"
    assert "User" in parsed["types"], f"'User' not in types: {list(parsed['types'].keys())}"
    assert "__Schema" not in parsed["types"], "internal __Schema type should be filtered"
    print("SELFCHECK OK  introspection parse: canned JSON -> queries/mutations/types correctly extracted")

    # --- new check 4: scope-gate refuses off-scope endpoint ---
    import os as _os, tempfile
    scope_content = "example.com\napi.example.com\n"
    fd, scope_path = tempfile.mkstemp(suffix="SCOPE.txt")
    _os.write(fd, scope_content.encode())
    _os.close(fd)

    # Build a stub session that records calls but never touches the network
    class _StubSession:
        def __init__(self):
            self.calls = []

        def post(self, url, **kw):
            self.calls.append(url)
            return _MockResp(200, {"data": {"__typename": "Query"}})

    try:
        stub = _StubSession()
        # Off-scope endpoint must raise ValueError
        raised = False
        try:
            schema_map(stub, "https://evil.com/graphql", scope_file=scope_path)
        except ValueError as e:
            assert "OUT_OF_SCOPE" in str(e), f"unexpected ValueError: {e}"
            raised = True
        assert raised, "scope-gate did NOT refuse off-scope endpoint evil.com"
        assert stub.calls == [], f"stub was called despite scope refusal: {stub.calls}"
        print("SELFCHECK OK  scope-gate: schema_map refuses off-scope endpoint, no network call made")

        # In-scope endpoint must NOT raise (stub returns introspection-shaped data)
        # Feed a fuller introspect response so _parse_introspection_schema returns data
        class _IntrospectStub:
            def post(self, url, **kw):
                return _MockResp(200, canned_introspect)

        result = schema_map(_IntrospectStub(), "https://api.example.com/graphql", scope_file=scope_path)
        assert result["introspection_on"] is True, "in-scope introspect stub should set introspection_on=True"
        assert "user" in result["queries"], f"'user' missing from schema_map queries: {result['queries']}"
        assert len(result["sensitive_ops"]) > 0, "adminPanel / user / createUser should be flagged sensitive"
        print("SELFCHECK OK  schema_map: in-scope endpoint runs, parses introspection, flags sensitive ops")
    finally:
        _os.unlink(scope_path)


def main(argv):
    if not argv:
        print(__doc__)
        return

    if argv[0] == "selfcheck":
        return _selfcheck()

    if argv[0] == "schema-map" and len(argv) >= 2:
        endpoint = argv[1]
        scope_file = None
        if "--scope" in argv:
            idx = argv.index("--scope")
            if idx + 1 < len(argv):
                scope_file = argv[idx + 1]

        # Build a real curl_cffi session
        import os as _os
        _HERE = _os.path.dirname(_os.path.abspath(__file__))
        if _HERE not in sys.path:
            sys.path.insert(0, _HERE)
        from lib_egress import make_session
        session = make_session(scope_file)
        result = schema_map(session, endpoint, scope_file=scope_file)
        print(json.dumps(result, indent=2))
        return

    print(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
