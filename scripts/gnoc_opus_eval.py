"""gnoc_opus_eval.py - how close is a local model to Opus on THIS workspace? Graded by code, on held-out sessions.

Each eval item (built by `gnoc_distill.py evalset`) is a real Opus session cut just before one of its tool calls. The
model under test gets the same context and the same tools, and must make the next move. Score per item:

  acted   0/1   it called a tool (Opus did, in every item)
  tool    0/1   same tool as Opus
  args    0..1  argument similarity to Opus's call (command tokens for bash, path for file tools, query tokens ...)
  item = 0.2*acted + 0.4*tool + 0.4*tool*args       (reported x100 as the Opus-agreement score)

Agreement is a proxy: Opus's move is one good move, not the only one. Use it to compare ARMS on the same items, never
as an absolute grade. Arms:

  base             one sample
  vote:K           K samples spread over the laptop and desktop GPUs at once, majority by (tool, key argument)
  fewshot:N        N retrieved Opus steps from the TRAIN split (similar task text) shown before the context
  fewshot:N+vote:K both

    python3 scripts/gnoc_opus_eval.py run <model>[@desktop] [--arm base] [--n 60] [--think]
    python3 scripts/gnoc_opus_eval.py report
Results append to .claude/state/orch/distill/opus-eval.jsonl.
"""
import collections
import concurrent.futures as cf
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(WS, "scripts"))
import gnoc_distill as D  # noqa: E402

OUT = os.path.join(D.OUT, "opus-eval.jsonl")
import llm_endpoints  # noqa: E402
HOSTS = llm_endpoints.HOSTS   # the same servers gnoc chat uses (local Ollama, GNOC_LOCAL_OLLAMA)
NUM_CTX = 16384


# ---------------------------------------------------------------- model call
def call(model, host, messages, tools, think=False, temperature=0.3, timeout=300):
    body = {"model": model, "messages": messages, "tools": tools, "stream": False, "think": think,
            "options": {"num_ctx": NUM_CTX, "temperature": temperature, "num_predict": 1200}}
    req = urllib.request.Request(f"http://{HOSTS[host]}/api/chat", json.dumps(body).encode(),
                                 {"Content-Type": "application/json"})
    t0 = time.time()
    for attempt in (0, 1):   # one retry: a busy desktop answers a transient 500 while it swaps models
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                msg = json.loads(r.read())["message"]
            break
        except urllib.error.HTTPError as e:
            e.close()
            if attempt or e.code < 500:
                raise
            time.sleep(3)
    calls = msg.get("tool_calls") or []
    fn = calls[0]["function"] if calls else None
    if fn and isinstance(fn.get("arguments"), str):
        try:
            fn["arguments"] = json.loads(fn["arguments"])
        except ValueError:
            fn["arguments"] = {}
    return fn, msg.get("content", ""), time.time() - t0


def to_ollama(messages):
    """Our corpus keeps OpenAI-style ids; Ollama wants arguments as objects and tool messages with tool_name."""
    out = []
    for m in messages:
        if m["role"] == "tool":
            out.append({"role": "tool", "content": m["content"], "tool_name": m.get("name", "")})
        elif m.get("tool_calls"):
            out.append({"role": "assistant", "content": m.get("content", ""),
                        "tool_calls": [{"function": {"name": c["function"]["name"],
                                                     "arguments": c["function"]["arguments"]}}
                                       for c in m["tool_calls"]]})
        else:
            out.append({"role": m["role"], "content": m.get("content", "")})
    return out


# ---------------------------------------------------------------- scoring
_TOK = re.compile(r"[A-Za-z0-9_.\-/]{2,}")


def _toks(s):
    return set(_TOK.findall(str(s).lower()))


def _jac(a, b):
    a, b = _toks(a), _toks(b)
    return len(a & b) / len(a | b) if a | b else 1.0


def _prog(cmd):
    """The first real program of a shell command (skips cd, env assignments, timeout)."""
    for part in re.split(r"&&|;|\|", str(cmd)):
        ws = [w for w in part.split() if "=" not in w.split("/")[0]]
        while ws and ws[0] in ("timeout", "env", "sudo", "nohup", "time"):
            ws = ws[2:] if ws[0] == "timeout" else ws[1:]
        if ws and ws[0] != "cd":
            return os.path.basename(ws[0])
    return ""


def _path(p):
    return D._rel(str(p or "")).lstrip("./")


def arg_sim(name, got, want):
    got, want = got or {}, want or {}
    if name == "bash":
        g, w = got.get("command", ""), want.get("command", "")
        return 0.4 * (_prog(g) == _prog(w)) + 0.6 * _jac(g, w)
    if name in ("read_file", "write_file", "edit_file"):
        g, w = _path(got.get("path")), _path(want.get("path"))
        s = 1.0 if g == w else (0.5 if os.path.basename(g) == os.path.basename(w) and g else 0.0)
        if name == "edit_file" and s:
            s = 0.7 * s + 0.3 * _jac(got.get("old", ""), want.get("old", ""))
        return s
    if name == "grep":
        return _jac(got.get("pattern", ""), want.get("pattern", ""))
    if name == "web_search":
        return _jac(got.get("query", ""), want.get("query", ""))
    if name == "web_fetch":
        return 1.0 if got.get("url") == want.get("url") else 0.5 * _jac(got.get("url"), want.get("url"))
    if name == "delegate":
        return 0.5 + 0.5 * _jac(got.get("task", ""), want.get("task", ""))
    return 0.0


def score(fn, target):
    if not fn:
        return {"acted": 0, "tool": 0, "args": 0.0, "item": 0.0}
    same = int(fn.get("name") == target["name"])
    a = arg_sim(target["name"], fn.get("arguments"), target["arguments"]) if same else 0.0
    return {"acted": 1, "tool": same, "args": round(a, 3), "item": round(0.2 + 0.4 * same + 0.4 * same * a, 3)}


# ---------------------------------------------------------------- arms
def vote_key(fn):
    if not fn:
        return ("<none>",)
    a = fn.get("arguments") or {}
    n = fn.get("name")
    if n == "bash":
        return (n, _prog(a.get("command", "")))
    if n in ("read_file", "write_file", "edit_file"):
        return (n, _path(a.get("path")))
    return (n,)


def pick(cands):
    """Majority over (tool, key arg); inside the winning group, the candidate closest to the others (medoid)."""
    groups = collections.defaultdict(list)
    for fn in cands:
        groups[vote_key(fn)].append(fn)
    best = max(groups.values(), key=len)
    if len(best) == 1 or not best[0]:
        return best[0]
    return max(best, key=lambda f: sum(arg_sim(f["name"], f.get("arguments"), o.get("arguments"))
                                       for o in best if o is not f))


_RETR = None


def retriever():
    """BM25 over train-split steps: (task text + last tool result) -> Opus's call there."""
    global _RETR
    if _RETR:
        return _RETR
    docs = []
    with open(os.path.join(D.OUT, "train.jsonl")) as fh:
        for k, line in enumerate(fh):
            if k % 3:            # every third sample keeps the index small and fast
                continue
            msgs = json.loads(line)["messages"]
            task = msgs[1]["content"][:600]
            for i, m in enumerate(msgs):
                if m["role"] == "assistant" and m.get("tool_calls") and i >= 2:
                    prev = msgs[i - 1]["content"][:400] if msgs[i - 1]["role"] == "tool" else ""
                    docs.append((task + "\n" + prev, task[:300], prev[:300], m["tool_calls"][0]["function"]))
    toks = [collections.Counter(_TOK.findall(d[0].lower())) for d in docs]
    df = collections.Counter(t for c in toks for t in c)
    avg = sum(sum(c.values()) for c in toks) / max(1, len(toks))
    _RETR = (docs, toks, df, avg)
    return _RETR


def retrieve(query, n):
    docs, toks, df, avg = retriever()
    q = set(_TOK.findall(query.lower()))
    N = len(docs)

    def bm25(c):
        L = sum(c.values())
        return sum(math.log(1 + (N - df[t] + .5) / (df[t] + .5)) * c[t] * 2.2 / (c[t] + 1.2 * (.25 + .75 * L / avg))
                   for t in q if t in c)
    ranked = sorted(range(N), key=lambda i: -bm25(toks[i]))
    out, seen = [], set()
    for i in ranked:
        key = vote_key(docs[i][3])
        if key in seen:
            continue
        seen.add(key)
        out.append(docs[i])
        if len(out) == n:
            break
    return out


def fewshot_block(item, n):
    q = item["messages"][1]["content"][:600] + "\n" + (item["messages"][-1]["content"][:400]
                                                      if item["messages"][-1]["role"] == "tool" else "")
    ex = retrieve(q, n)
    lines = ["Examples of the next move an expert made in similar situations in this repo:"]
    for _, task, prev, fn in ex:
        args = json.dumps(fn["arguments"])[:300]
        lines.append(f"- task: {task[:160]!r}\n  last result: {prev[:160]!r}\n  next call: {fn['name']} {args}")
    return "\n".join(lines)


def run_item(item, model, host, arm, think):
    msgs = to_ollama(item["messages"])
    m = re.search(r"fewshot:(\d+)", arm)
    if m:
        msgs = [dict(msgs[0], content=msgs[0]["content"] + "\n\n" + fewshot_block(item, int(m.group(1))))] + msgs[1:]
    v = re.search(r"vote:(\d+)", arm)
    k = int(v.group(1)) if v else 1
    if k == 1:
        fn, _, dt = call(model, host, msgs, D.TOOLS, think)
        return fn, dt
    # spread the K samples over both GPUs: the other host runs the same weights (its own quant)
    hosts = [host] + [h for h in HOSTS if h != host and up(h, model_for(h, model))]
    t0 = time.time()
    with cf.ThreadPoolExecutor(k) as ex:
        futs = [ex.submit(call, model_for(hosts[i % len(hosts)], model), hosts[i % len(hosts)], msgs, D.TOOLS,
                          think, 0.8) for i in range(k)]
        cands = []
        for f in futs:
            try:
                cands.append(f.result()[0])
            except Exception:
                pass
    return (pick(cands) if cands else None), time.time() - t0


# the same Huihui Qwen3.5-9B on each machine, under the name each Ollama knows it by
TWINS = {"local": "qwen3:8b",
         "desktop": "qwen3:8b"}


def model_for(host, model):
    if model in TWINS.values():
        return TWINS.get(host, model)   # a host with no twin (the phone) is then skipped by up()
    return model


_UP = {}


def up(host, model):
    if (host, model) not in _UP:
        try:
            with urllib.request.urlopen(f"http://{HOSTS[host]}/api/tags", timeout=4) as r:
                names = {m["name"].split(":latest")[0] for m in json.loads(r.read())["models"]}
            _UP[(host, model)] = model.split(":latest")[0] in names
        except Exception:
            _UP[(host, model)] = False
    return _UP[(host, model)]


def run(spec, arm="base", n=60, think=False, workers=1):
    model, host = (spec.rsplit("@", 1) + ["local"])[:2] if "@" in spec else (spec, "local")
    items = [json.loads(l) for l in open(os.path.join(D.OUT, "evalset.jsonl"))][:n]
    rows, lat = [], []

    def one(it):
        try:
            fn, dt = run_item(it, model, host, arm, think)
        except Exception as e:
            return it, None, 0.0, str(e)[:120]
        return it, fn, dt, None

    with cf.ThreadPoolExecutor(workers) as ex:
        for it, fn, dt, err in ex.map(one, items):
            s = score(fn, it["target"])
            s.update(id=it["id"], want=it["target"]["name"], got=(fn or {}).get("name"), err=err)
            rows.append(s)
            lat.append(dt)
            print(f"  #{it['id']:3d} want {it['target']['name']:10s} got {str(s['got']):10s} "
                  f"item {s['item']:.2f} {dt:5.1f}s{' ERR ' + err if err else ''}", flush=True)
    tot = {k: round(100 * sum(r[k] for r in rows) / len(rows), 1) for k in ("item", "acted", "tool", "args")}
    per = {}
    for r in rows:
        per.setdefault(r["want"], []).append(r["item"])
    res = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "model": model, "host": host, "arm": arm,
           "think": think, "n": len(rows), "score": tot["item"], "acted": tot["acted"], "tool": tot["tool"],
           "args_when_tool": round(100 * sum(r["args"] for r in rows if r["tool"]) / max(1, sum(r["tool"] for r in rows)), 1),
           "per_tool": {k: round(100 * sum(v) / len(v), 1) for k, v in per.items()},
           "errors": sum(1 for r in rows if r["err"]),
           "p50_s": round(sorted(lat)[len(lat) // 2], 1) if lat else None}
    with open(OUT, "a") as fh:
        fh.write(json.dumps(res) + "\n")
    return res


def report():
    rows = [json.loads(l) for l in open(OUT)] if os.path.exists(OUT) else []
    print(f"{'model':48s} {'host':8s} {'arm':18s} {'n':>4s} {'score':>6s} {'tool%':>6s} {'args%':>6s} {'p50':>6s}")
    for r in rows:
        print(f"{r['model'][-48:]:48s} {r['host']:8s} {r['arm'] + ('+think' if r['think'] else ''):18s} {r['n']:4d} "
              f"{r['score']:6.1f} {r['tool']:6.1f} {r['args_when_tool']:6.1f} {str(r['p50_s']):>6s}")


if __name__ == "__main__":
    a = sys.argv[1:]
    if not a or a[0] == "report":
        report()
    elif a[0] == "run":
        opt = lambda k, d: a[a.index(k) + 1] if k in a else d  # noqa: E731
        r = run(a[1], opt("--arm", "base"), int(opt("--n", 60)), "--think" in a, int(opt("--workers", 1)))
        print(json.dumps(r, indent=1))
