"""GraphQL query builder and checker: the model names the parts, the harness writes the query.

Why (initech replay, 2026-11-25): the 35B lead and its bots hand-wrote GraphQL in http_request bodies and twelve
of their requests came back "Invalid GraphQL request", "Syntax Error: Unexpected }" or a selection set on a
scalar field. Every one was a wasted probe and none tested the hypothesis. Here the model passes the root field,
its arguments, the selection and an optional inline-fragment wrapper; the query is serialised by code (valid by
construction), a hand-written query is syntax-checked before it can be sent, and what the server's own errors
teach (this field is a scalar, that field does not exist) is kept per programme and checked before the next send.

Stdlib only; gnoc_core never imports gnoc_agent.
"""
import json
import os
import re
import threading

NAME = re.compile(r"^[_A-Za-z][_0-9A-Za-z]*$")
_LOCK = threading.Lock()


class BuildError(ValueError):
    pass


# ---------------------------------------------------------------- serialise

def literal(v, path="args"):
    """A JSON value as a GraphQL literal. {"enum": "X"} is the enum value X (unquoted); {"var": "x"} is $x."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return json.dumps(v)
    if isinstance(v, str):
        return json.dumps(v)
    if isinstance(v, list):
        return "[" + ", ".join(literal(x, path) for x in v) + "]"
    if isinstance(v, dict):
        if set(v) == {"enum"}:
            e = str(v["enum"])
            if not NAME.match(e) or e in ("true", "false", "null"):
                raise BuildError(f"{path}: enum value {e!r} is not a GraphQL name")
            return e
        if set(v) == {"var"}:
            n = str(v["var"]).lstrip("$")
            if not NAME.match(n):
                raise BuildError(f"{path}: variable name {n!r} is not a GraphQL name")
            return "$" + n
        parts = []
        for k, x in v.items():
            if not NAME.match(str(k)):
                raise BuildError(f"{path}: input field {k!r} is not a GraphQL name")
            parts.append(f"{k}: {literal(x, path + '.' + str(k))}")
        return "{" + ", ".join(parts) + "}"
    raise BuildError(f"{path}: cannot write a {type(v).__name__} as a GraphQL value")


def _sel_tree(select):
    """select as a nested dict {field: subtree-or-None}. Accepts ["id", "items.id", "items.name"], a dict
    {"id": null, "items": ["id", "name"]} or a mix. A field with a None subtree is a leaf."""
    tree = {}

    def put(path, sub=None):
        node = tree
        bits = [b.strip() for b in str(path).split(".")]
        for i, b in enumerate(bits):
            alias = None
            if ":" in b:
                alias, b = [x.strip() for x in b.split(":", 1)]
                if not NAME.match(alias):
                    raise BuildError(f"select: alias {alias!r} is not a GraphQL name")
            if not NAME.match(b):
                raise BuildError(f"select: {b!r} in {path!r} is not a field name")
            key = f"{alias}: {b}" if alias else b
            last = i == len(bits) - 1
            if last and sub is None:
                node.setdefault(key, None)
            else:
                if node.get(key) is None:
                    node[key] = {}
                node = node[key]
        if sub is not None:
            for k, v in _sel_tree(sub).items():
                node[k] = v

    if select is None or select == [] or select == {}:
        return {}
    if isinstance(select, str):
        select = [s for s in re.split(r"[\s,]+", select) if s]
    if isinstance(select, dict):
        for k, v in select.items():
            put(k, v if v not in (None, True, 1, "") else None)
    elif isinstance(select, list):
        for s in select:
            if isinstance(s, dict):
                for k, v in s.items():
                    put(k, v if v not in (None, True, 1, "") else None)
            else:
                put(s)
    else:
        raise BuildError("select must be a list of field paths like [\"id\", \"items.name\"] or an object")
    return tree


def _render(tree, indent=2):
    pad = " " * indent
    out = []
    for k, sub in tree.items():
        if sub:
            out.append(f"{pad}{k} {{\n{_render(sub, indent + 2)}\n{pad}}}")
        else:
            out.append(pad + k)
    return "\n".join(out)


def build(field, args=None, select=None, op="query", wrap=None, operation_name=None, var_types=None):
    """The query text. field is the root field; wrap="RootQuery" puts the root selection inside
    `... on RootQuery { }` (T-346: a gateway auth gate that reads only top-level root fields)."""
    op = str(op or "query").lower()
    if op not in ("query", "mutation", "subscription"):
        raise BuildError(f"op must be query, mutation or subscription, not {op!r}")
    if not NAME.match(str(field or "")):
        raise BuildError(f"field {field!r} is not a GraphQL field name (the root field, e.g. sampleObjects)")
    a = ""
    if args:
        if not isinstance(args, dict):
            raise BuildError("args must be an object of argument name -> value")
        bits = []
        for k, v in args.items():
            if not NAME.match(str(k)):
                raise BuildError(f"args: {k!r} is not an argument name")
            bits.append(f"{k}: {literal(v, 'args.' + str(k))}")
        a = "(" + ", ".join(bits) + ")"
    tree = _sel_tree(select)
    base = 4 if wrap else 2
    body = f"{field}{a}" + (f" {{\n{_render(tree, base + 2)}\n{' ' * base}}}" if tree else "")
    if wrap:
        if not NAME.match(str(wrap)):
            raise BuildError(f"wrap {wrap!r} is not a type name (e.g. RootQuery, Query, Mutation)")
        inner = f"  ... on {wrap} {{\n    {body}\n  }}"
    else:
        inner = "  " + body
    head = op
    if operation_name:
        if not NAME.match(str(operation_name)):
            raise BuildError(f"operation_name {operation_name!r} is not a GraphQL name")
        head += " " + operation_name
    if var_types:
        if not isinstance(var_types, dict):
            raise BuildError("var_types must be an object like {\"id\": \"ID!\"}")
        vd = []
        for k, t in var_types.items():
            if not NAME.match(str(k).lstrip("$")) or not re.match(r"^\[?[_A-Za-z][_0-9A-Za-z]*!?\]?!?$", str(t)):
                raise BuildError(f"var_types: {k!r}: {t!r} is not a variable type like ID! or [String]")
            vd.append(f"${str(k).lstrip('$')}: {t}")
        head += "(" + ", ".join(vd) + ")"
    q = f"{head} {{\n{inner}\n}}"
    err = check_syntax(q)
    if err:   # cannot happen by construction; a guard against a builder bug reaching the wire
        raise BuildError("internal: built query failed the syntax check: " + err)
    return q


# ---------------------------------------------------------------- syntax check (hand-written queries)

_TOKEN = re.compile(r'"""(?:[^"\\]|\\.|"(?!""))*"""|"(?:[^"\\\n]|\\.)*"|#[^\n]*|\.\.\.|[{}()\[\]:!$=@,]'
                    r'|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[_A-Za-z][_0-9A-Za-z]*|\s+|.', re.S)


def check_syntax(q):
    """'' when the document is plausibly well-formed, else what is wrong. Catches what the replay hit: unbalanced
    braces, an empty selection set `{ }`, an unclosed string, a stray character, nothing after an operation."""
    q = str(q or "")
    if not q.strip():
        return "the query is empty"
    stack, prev = [], ""
    pairs = {"}": "{", ")": "(", "]": "["}
    for m in _TOKEN.finditer(q):
        t = m.group(0)
        if t.isspace() or t.startswith("#") or t == ",":
            continue
        if t.startswith('"') and not (len(t) >= 2 and t.endswith('"')):
            return f"unclosed string at offset {m.start()}"
        if len(t) == 1 and not re.match(r'[{}()\[\]:!$=@_A-Za-z0-9"-]', t):
            return f"unexpected character {t!r} at offset {m.start()}"
        if t in "{([":
            stack.append((t, m.start()))
        elif t in "})]":
            if not stack or stack[-1][0] != pairs[t]:
                return f"unexpected {t!r} at offset {m.start()} (nothing open to close)"
            stack.pop()
            if t == "}" and prev == "{":
                return f"empty selection set '{{ }}' at offset {m.start()}: every {{ }} needs at least one field"
            if t == ")" and prev == "(":
                return f"empty argument list '()' at offset {m.start()}"
        prev = t
    if stack:
        return f"unclosed {stack[-1][0]!r} opened at offset {stack[-1][1]}"
    if not re.search(r"\{", q):
        return "no selection set: a query is `query { field { subfield } }`"
    return ""


# ---------------------------------------------------------------- what the server taught us

_SCALAR_ERR = re.compile(r'Field "?([_A-Za-z][_0-9A-Za-z]*)"? must not have a selection since type "?([^"\s]+)"? '
                         r'has no subfields')
_NEEDS_SEL = re.compile(r'Field "?([_A-Za-z][_0-9A-Za-z]*)"? of type "?([^"\s]+)"? must have a selection of '
                        r'subfields')
_NO_FIELD = re.compile(r'Cannot query field "?([_A-Za-z][_0-9A-Za-z]*)"? on type "?([_A-Za-z][_0-9A-Za-z]*)"?'
                       r'\.?(?:\s*Did you mean ([^?]+)\?)?')
_UNKNOWN_ARG = re.compile(r'Unknown argument "?([_A-Za-z][_0-9A-Za-z]*)"? on field "?([_A-Za-z][_0-9A-Za-z.]*)"?')


def _store(ws, program):
    return os.path.join(ws, "targets", program, "hunts", "gnoc", "graphql-learned.json")


def load(ws, program):
    try:
        with open(_store(ws, program)) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def learn(ws, program, body):
    """Record what a response's errors say about the schema. Returns short notes for the model."""
    try:
        d = json.loads(body) if isinstance(body, str) else body
    except ValueError:
        return []
    errs = d.get("errors") if isinstance(d, dict) else None
    if not isinstance(errs, list) or not program:
        return []
    notes = []
    with _LOCK:
        st = load(ws, program)
        scal, obj = set(st.get("scalars", [])), set(st.get("objects", []))
        bad, sugg, badarg = dict(st.get("no_field", {})), dict(st.get("suggest", {})), set(st.get("no_arg", []))
        for e in errs:
            msg = str((e or {}).get("message") if isinstance(e, dict) else e)
            for f, t in _SCALAR_ERR.findall(msg):
                scal.add(f)
                notes.append(f"{f} is a scalar ({t}): select it with no subfields")
            for f, t in _NEEDS_SEL.findall(msg):
                obj.add(f)
                notes.append(f"{f} ({t}) is an object: it needs a selection, e.g. {f}.id")
            for f, t, mean in _NO_FIELD.findall(msg):
                bad[f"{t}.{f}"] = 1
                if mean:
                    sugg[f"{t}.{f}"] = re.findall(r'"([_A-Za-z][_0-9A-Za-z]*)"', mean)[:5]
                notes.append(f"{t} has no field {f}" + (f" (the server suggests {mean.strip()})" if mean else ""))
            for a, f in _UNKNOWN_ARG.findall(msg):
                badarg.add(f"{f}({a})")
                notes.append(f"{f} takes no argument {a}")
        if notes:
            os.makedirs(os.path.dirname(_store(ws, program)), exist_ok=True)
            tmp = _store(ws, program) + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"scalars": sorted(scal), "objects": sorted(obj), "no_field": bad, "suggest": sugg,
                           "no_arg": sorted(badarg)}, f, indent=1)
            os.replace(tmp, _store(ws, program))
    return notes


def precheck(ws, program, field, args, select):
    """What the learned schema already says is wrong with this request, or ''. Never blocks on an unknown."""
    st = load(ws, program)
    if not st:
        return ""
    scal, obj = set(st.get("scalars", [])), set(st.get("objects", []))
    problems = []

    def walk(tree):
        for k, sub in tree.items():
            name = k.split(":")[-1].strip()
            if sub and name in scal:
                problems.append(f"{name} is a scalar (the server said so): drop its subfields")
            if not sub and name in obj:
                problems.append(f"{name} is an object (the server said so): select a subfield, e.g. {name}.id")
            if sub:
                walk(sub)
    try:
        tree = _sel_tree(select)
    except BuildError:
        tree = {}
    if tree and field in scal:
        problems.append(f"{field} is a scalar (the server said so): send it with no select")
    walk(tree)
    for key in st.get("no_field", {}):
        if key.split(".")[-1] == field and key.split(".")[0] in ("Query", "RootQuery", "Mutation", "RootMutation"):
            s = st.get("suggest", {}).get(key)
            problems.append(f"{key} does not exist (the server said so)" + (f"; it suggested {', '.join(s)}" if s
                                                                                 else ""))
    for a in (args or {}):
        if f"{field}({a})" in set(st.get("no_arg", [])):
            problems.append(f"{field} takes no argument {a} (the server said so)")
    return "; ".join(dict.fromkeys(problems))
