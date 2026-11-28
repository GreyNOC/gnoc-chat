#!/usr/bin/env python3
"""lab.py - the user Model Lab: benchmark the local Ollama models on the jobs they do in this rig.

  lab.py bench <model> [--suite quick|full] [--tag TEXT]   run a benchmark, stream events (live terminal panel)
  lab.py serve [--port 8765]                               live web dashboard on 127.0.0.1 (SSE, offline, no CDN)
  lab.py export <run_id|latest>                            charts (PNG) + report.pdf + zip under .claude/state/lab/exports/,
                                                           and the PDF in ~/Downloads (LAB_PDF_DIR overrides)
  lab.py list                                              past runs, one line each
  lab.py compare <run_id> <run_id> [...]                   leaderboard across runs ("latest" works as a run id)

Contract: scripts/model-lab/CONTRACT.md. Categories and graders: scripts/model-lab/suites.py.
Ollama: 127.0.0.1:11434 (ollama-oc), shared with the live orch-bot. Requests queue behind the bot, never break it.
Every call sets num_predict and num_ctx 16384 (the bot's value, so the loaded model is never reloaded).

SCORING. overall = 100 * sum(weight_c * score_c) / sum(weight_c over categories run) - speed_penalty
  weights: decision 30, grounding 20, security 20, json 10, instruction 10, refusal 10
  speed_penalty = min(15, max(0, (p50_latency_s - 20) * 0.5))
    i.e. no penalty while the median call answers within 20 s (what the bot tick tolerates comfortably),
    then half a point per extra second, capped at 15 points so a slow but correct model still ranks above a fast wrong one.
"""
import argparse
import html
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import suites  # noqa: E402

WS = suites.WS
LAB = os.path.join(WS, ".claude/state/lab")
RUNS = os.path.join(LAB, "runs")
EXPORTS = os.path.join(LAB, "exports")
# export also drops the PDF here for reading (GreyNOC 2026-10-24); LAB_PDF_DIR overrides, the zip stays in EXPORTS
PDF_DIR = os.environ.get("LAB_PDF_DIR") or os.path.expanduser("~/Downloads")
CURRENT = os.path.join(LAB, "CURRENT")
CHROME = os.environ.get("LAB_CHROME", "~/.local/bin/google-chrome")
CATS = ["decision", "grounding", "security", "json", "instruction", "refusal"]


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def slug(model):
    return re.sub(r"[^a-z0-9]+", "-", model.lower()).strip("-")[:40]


def speed_penalty(p50):
    return round(min(15.0, max(0.0, (p50 - 20.0) * 0.5)), 2)


def pct(xs, q):
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return 0.0
    k = (len(xs) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return round(xs[lo] + (xs[hi] - xs[lo]) * (k - lo), 3)


# ------------------------------------------------------------------ run store

def run_dir(run):
    return os.path.join(RUNS, run)


def all_runs():
    if not os.path.isdir(RUNS):
        return []
    return sorted(d for d in os.listdir(RUNS) if os.path.isfile(os.path.join(RUNS, d, "meta.json")))


def resolve_run(r):
    runs = all_runs()
    if r in ("latest", "last"):
        done = [x for x in runs if os.path.isfile(os.path.join(RUNS, x, "summary.json"))]
        if not done:
            sys.exit("no finished runs yet (lab.py bench <model>)")
        return done[-1]
    if r in runs:
        return r
    m = [x for x in runs if r in x]
    if len(m) == 1:
        return m[0]
    sys.exit(f"unknown run {r!r}" + (f"; matches: {', '.join(m)}" if m else "; see lab.py list"))


def load_json(p, default=None):
    try:
        return json.load(open(p))
    except (OSError, ValueError):
        return default


def load_events(run):
    out = []
    try:
        for ln in open(os.path.join(run_dir(run), "events.jsonl")):
            try:
                out.append(json.loads(ln))
            except ValueError:
                pass
    except OSError:
        pass
    return out


def summarize(meta, events):
    tasks = [e for e in events if e.get("phase") == "task"]
    cats = {}
    for c in CATS:
        ts = [e for e in tasks if e.get("category") == c]
        if ts:
            cats[c] = {"score": round(sum(e["score"] for e in ts) / len(ts), 4), "n": len(ts), "passed": sum(1 for e in ts if e["ok"])}
    lat = [e["latency_s"] for e in tasks if e.get("latency_s")]
    toks = [e["tok_s"] for e in tasks if e.get("tok_s")]
    ttft = [e["ttft_s"] for e in tasks if e.get("ttft_s")]
    wsum = sum(suites.WEIGHTS[c] for c in cats) or 1
    raw = 100 * sum(suites.WEIGHTS[c] * cats[c]["score"] for c in cats) / wsum
    p50 = pct(lat, 0.5)
    pen = speed_penalty(p50)

    def rate(key, cat):
        xs = [e.get(key) for e in tasks if e.get("category") in cat and e.get(key) is not None]
        return round(sum(1 for x in xs if x) / len(xs), 3) if xs else None
    ref = rate("refused", ("refusal",))
    vr = [e["vram_gb"] for e in tasks if e.get("vram_gb")]
    return {"run": meta["run"], "model": meta["model"], "suite": meta["suite"], "tag": meta.get("tag", ""),
            "started": meta["started"], "ended": utcnow(),
            "duration_s": round(sum(e.get("latency_s", 0) for e in tasks), 1),
            "wall_s": round(time.time() - meta.get("_t0", time.time()), 1) if meta.get("_t0") else None,
            "tasks": len(tasks), "passed": sum(1 for e in tasks if e["ok"]), "errors": sum(1 for e in events if e.get("phase") == "error"),
            "categories": cats, "weights": suites.WEIGHTS,
            "overall_raw": round(raw, 2), "speed_penalty": pen, "overall": round(max(0.0, raw - pen), 2),
            "latency_p50": p50, "latency_p95": pct(lat, 0.95), "ttft_p50": pct(ttft, 0.5),
            "tok_s_mean": round(statistics.mean(toks), 2) if toks else 0.0,
            "json_valid_rate": rate("json_valid", ("decision", "json")),
            "precheck_pass_rate": rate("precheck", ("decision",)),
            "grounding_rate": rate("grounded", ("grounding",)),
            "refusal_rate": ref, "vram_gb": max(vr) if vr else None}


# ------------------------------------------------------------------ terminal live panel

class Panel:
    def __init__(self, meta, total):
        self.meta, self.total, self.done, self.passed = meta, total, 0, 0
        self.cur, self.toks, self.last = "starting", [], []
        self.live = None
        try:
            from rich.console import Console
            self.console = Console()
            if self.console.is_terminal:
                from rich.live import Live
                self.live = Live(self.render(), console=self.console, refresh_per_second=4)
                self.live.start()
        except Exception:
            self.live = None

    def render(self):
        from rich.panel import Panel as RP
        from rich.progress_bar import ProgressBar
        from rich.table import Table
        from rich.console import Group
        t = Table.grid(padding=(0, 2))
        t.add_column(style="bold cyan")
        t.add_column()
        rt = statistics.mean(self.toks[-5:]) if self.toks else 0
        t.add_row("model", f"{self.meta['model']}  ({self.meta['suite']})")
        t.add_row("progress", f"{self.done}/{self.total}")
        t.add_row("current", self.cur)
        t.add_row("tok/s (rolling)", f"{rt:.1f}")
        t.add_row("pass rate", f"{self.passed}/{self.done}" + (f"  {100 * self.passed / self.done:.0f}%" if self.done else ""))
        feed = Table(show_header=False, box=None, padding=(0, 1))
        for e in self.last[-8:]:
            feed.add_row("[green]PASS[/]" if e["ok"] else "[red]FAIL[/]", e["category"], e["task"], f"{e['latency_s']:.1f}s",
                         f"{e.get('tok_s', 0):.1f} t/s", (e.get("note") or "")[:60])
        return RP(Group(t, ProgressBar(total=max(self.total, 1), completed=self.done, width=60), feed),
                  title=f"[bold]the user Model Lab[/]  {self.meta['run']}", border_style="cyan")

    def start_task(self, t, i):
        self.cur = f"[{i}/{self.total}] {t['category']} / {t['id']}"
        if self.live:
            self.live.update(self.render())
        else:
            print(f"  .. {self.cur}", flush=True)

    def task(self, e):
        self.done += 1
        self.passed += e["ok"]
        if e.get("tok_s"):
            self.toks.append(e["tok_s"])
        self.last.append(e)
        if self.live:
            self.live.update(self.render())
        else:
            print(f"  {'PASS' if e['ok'] else 'FAIL'} {e['category']:<11} {e['task']:<24} {e['latency_s']:6.1f}s "
                  f"{e.get('tok_s', 0):5.1f} t/s  {(e.get('note') or '')[:70]}", flush=True)

    def stop(self):
        if self.live:
            self.cur = "done"
            self.live.update(self.render())
            self.live.stop()


# ------------------------------------------------------------------ bench

def cmd_bench(a):
    model = a.model
    try:
        tags = {m["name"] for m in json.loads(subprocess.run(["curl", "-s", f"http://{suites.HOST}/api/tags"], capture_output=True,
                                                            text=True, timeout=10).stdout).get("models", [])}
    except Exception as e:
        sys.exit(f"ollama-oc on {suites.HOST} is not answering ({e})")
    if model not in tags and model + ":latest" not in tags:
        sys.exit(f"{model} is not installed in ollama-oc; installed: {', '.join(sorted(tags))}")
    if os.path.isfile(CURRENT):
        other = open(CURRENT).read().strip()
        meta_o = load_json(os.path.join(run_dir(other), "meta.json"), {})
        if other and not os.path.isfile(os.path.join(run_dir(other), "summary.json")) and _alive(meta_o.get("pid")):
            sys.exit(f"another bench is running ({other}); one at a time, the GPU has one slot")
    tasks = suites.all_tasks(a.suite)
    run = f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S}-{slug(model)}"
    d = run_dir(run)
    os.makedirs(d, exist_ok=True)
    meta = {"run": run, "model": model, "suite": a.suite, "started": utcnow(), "host": suites.HOST, "tag": a.tag or "",
            "tasks": len(tasks), "pid": os.getpid()}
    json.dump(meta, open(os.path.join(d, "meta.json"), "w"), indent=1)
    meta["_t0"] = time.time()
    with open(CURRENT + ".tmp", "w") as f:
        f.write(run + "\n")
    os.replace(CURRENT + ".tmp", CURRENT)
    evf = open(os.path.join(d, "events.jsonl"), "a")
    events = []

    def emit(**kw):
        e = dict({"ts": utcnow(), "run": run, "model": model, "suite": a.suite}, **kw)
        evf.write(json.dumps(e) + "\n")
        evf.flush()
        events.append(e)
        return e

    # warm-up (not scored): loads the model into VRAM so a swap from the bot's model is not billed to task 1
    tw = time.time()
    try:
        suites.chat(model, [{"role": "user", "content": "ok"}], num_predict=1)
        warm = f"warm-up {time.time() - tw:.1f}s"
    except Exception as ex:
        warm = f"warm-up failed: {str(ex)[:80]}"
    emit(phase="start", task="", category="", i=0, of=len(tasks), ok=True, score=0, latency_s=round(time.time() - tw, 3),
         tok_s=0, ttft_s=0, eval_tokens=0, prompt_tokens=0, vram_gb=suites.vram_gb(model),
         note=f"{a.suite} suite, {len(tasks)} tasks, {warm}")
    panel = Panel(meta, len(tasks))
    try:
        for i, t in enumerate(tasks, 1):
            panel.start_task(t, i)
            suites.LAST_OUT.clear()
            try:
                score, perf, note, extra = t["run"](model)
            except Exception as ex:
                emit(phase="error", task=t["id"], category=t["category"], i=i, of=len(tasks), ok=False, score=0,
                     note=f"{type(ex).__name__}: {str(ex)[:150]}")
                score, perf, note, extra = 0.0, {"latency_s": 0, "ttft_s": 0, "tok_s": 0, "eval_tokens": 0, "prompt_tokens": 0}, \
                    f"error: {str(ex)[:80]}", {}
            perf = dict({"latency_s": 0, "ttft_s": 0, "tok_s": 0, "eval_tokens": 0, "prompt_tokens": 0}, **(perf or {}))
            e = emit(phase="task", task=t["id"], category=t["category"], i=i, of=len(tasks), ok=score >= 0.6,
                     score=round(float(score), 3), vram_gb=suites.vram_gb(model), note=note, **perf, **extra,
                     out=suites.strip_think(suites.LAST_OUT[-1])[:300] if suites.LAST_OUT else "")
            panel.task(e)
    except KeyboardInterrupt:
        emit(phase="error", task="", category="", i=len([x for x in events if x["phase"] == "task"]), of=len(tasks),
             ok=False, score=0, note="interrupted")
    finally:
        panel.stop()
        s = summarize(meta, events)
        json.dump(s, open(os.path.join(d, "summary.json"), "w"), indent=1)
        emit(phase="end", task="", category="", i=s["tasks"], of=len(tasks), ok=True, score=round(s["overall"] / 100, 4),
             latency_s=s["latency_p50"], tok_s=s["tok_s_mean"], ttft_s=s["ttft_p50"], eval_tokens=0, prompt_tokens=0,
             vram_gb=s["vram_gb"], note=f"overall {s['overall']}")
        evf.close()
        try:
            if open(CURRENT).read().strip() == run:
                os.remove(CURRENT)
        except OSError:
            pass
    print_summary(s)
    return 0


def _alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except (TypeError, ValueError, OSError):
        return False


def print_summary(s):
    print(f"\n{s['model']}  run {s['run']}  ({s['suite']}, {s['tasks']} tasks, {s['passed']} passed, wall {s.get('wall_s')} s)")
    print(f"  OVERALL {s['overall']:.1f} / 100   (raw {s['overall_raw']:.1f}, speed penalty -{s['speed_penalty']})")
    for c in CATS:
        if c in s["categories"]:
            v = s["categories"][c]
            print(f"  {c:<12} {100 * v['score']:5.1f}   {v['passed']}/{v['n']} passed   weight {suites.WEIGHTS[c]}")
    print(f"  latency p50 {s['latency_p50']} s  p95 {s['latency_p95']} s   ttft p50 {s['ttft_p50']} s   tok/s {s['tok_s_mean']}"
          f"   vram {s['vram_gb']} GB")
    print(f"  json valid {s['json_valid_rate']}  precheck {s['precheck_pass_rate']}  grounding {s['grounding_rate']}"
          f"  refused {s['refusal_rate']}")
    print(f"  files: {os.path.relpath(run_dir(s['run']), WS)}/   next: lab.py export {s['run']}")


# ------------------------------------------------------------------ list / compare

def summaries():
    out = []
    for r in all_runs():
        s = load_json(os.path.join(run_dir(r), "summary.json"))
        if s:
            out.append(s)
    return out


def cmd_list(a):
    rs = all_runs()
    if not rs:
        print("no runs yet: lab.py bench <model> --suite quick")
        return 0
    cur = open(CURRENT).read().strip() if os.path.isfile(CURRENT) else ""
    for r in rs:
        s = load_json(os.path.join(run_dir(r), "summary.json"))
        m = load_json(os.path.join(run_dir(r), "meta.json"), {})
        if s:
            print(f"{r:<44} {s['suite']:<5} overall {s['overall']:5.1f}  p50 {s['latency_p50']:6.1f}s  {s['tok_s_mean']:5.1f} t/s"
                  f"  pass {s['passed']}/{s['tasks']}" + (f"  [{s['tag']}]" if s.get("tag") else ""))
        else:
            n = sum(1 for e in load_events(r) if e.get("phase") == "task")
            print(f"{r:<44} {m.get('suite', '?'):<5} " + ("RUNNING" if r == cur else "INCOMPLETE") + f"  {n}/{m.get('tasks', '?')} tasks")
    return 0


def cmd_compare(a):
    ss = [load_json(os.path.join(run_dir(resolve_run(r)), "summary.json")) for r in a.runs]
    ss = [s for s in ss if s]
    if not ss:
        sys.exit("no finished runs among those ids")
    ss.sort(key=lambda s: -s["overall"])
    hdr = f"{'#':<3}{'run':<44}{'overall':>8}{'p50 s':>8}{'tok/s':>7}" + "".join(f"{c[:6]:>8}" for c in CATS)
    print(hdr)
    print("-" * len(hdr))
    for i, s in enumerate(ss, 1):
        print(f"{i:<3}{s['run']:<44}{s['overall']:>8.1f}{s['latency_p50']:>8.1f}{s['tok_s_mean']:>7.1f}"
              + "".join(f"{100 * s['categories'][c]['score']:>8.1f}" if c in s["categories"] else f"{'-':>8}" for c in CATS))
    return 0


# ------------------------------------------------------------------ export

# Verdict bands for the overall score (the cut points the old gauge colored by). Status colors are reserved for these.
BANDS = [(70.0, "Strong", "good", "Fit for the jobs this rig gives a local model."),
         (45.0, "Usable", "fair", "Does the work, but check the weak areas before leaving it unattended."),
         (0.0, "Weak", "poor", "Not ready: too many core tasks fail or need a retry.")]
# One line per category: what the task measures and how it is graded (from suites.py).
CAT_INFO = {"decision": "Picks the orch-bot's next action from a snapshot; graded by the bot's own normalize() + precheck() "
                        "and an expected action.",
            "grounding": "Writes report fields from an escalation record; local-draft check() rejects invented nouns or paths, "
                         "hedges and word-cap overruns.",
            "security": "Multiple-choice triage of captured HTTP: classify it, spot the false positive, pick the next GET-only step.",
            "json": "Returns JSON that matches a schema, both with Ollama format=schema and with a plain 'JSON only' prompt.",
            "instruction": "Obeys house writing rules: no em dash, no hedges, word caps, ASCII title, exact line format.",
            "refusal": "Answers benign authorized-research prompts; a refusal or over-hedging is penalised."}
PASS_AT = 0.6  # a task passes at score >= 0.6 (cmd_bench)
# print palette: one accent, neutral grays; status colors only for the verdict and PASS/FAIL
INK, INK2, MUT, LINE, SOFT, ACC, GRAY = "#16181d", "#4b5059", "#7a808a", "#e3e5e8", "#f4f5f7", "#2a78d6", "#c4c8ce"
STATUS = {"good": ("#1a7f37", "#e6f4ea"), "fair": ("#9a6700", "#fff4d6"), "poor": ("#c62828", "#fde8e8"), "none": (INK2, SOFT)}


def _n(v):
    """A summary/event number or None (older runs miss keys, booleans are not numbers)."""
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _f(v, fmt="{:.1f}", unit="", na="n/a"):
    v = _n(v)
    return na if v is None else fmt.format(v) + unit


def _rate(v):
    v = _n(v)
    return "n/a" if v is None else f"{100 * v:.0f}%"


def band(v):
    if _n(v) is None:
        return (0.0, "No score", "none", "This summary carries no overall score.")
    return next(b for b in BANDS if v >= b[0])


def _when(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError):
        return str(ts or "n/a")


def _clip(t, n=118):
    t = " ".join(str(t or "").split())
    return t if len(t) <= n else t[:n].rsplit(" ", 1)[0].rstrip(",;:") + " …"


def _cat_rows(s):
    """[(cat, score 0..1 or None, weight, n, passed)] in the fixed CATS order, extras after."""
    cats = s.get("categories") or {}
    w = s.get("weights") or suites.WEIGHTS
    out = []
    for c in [c for c in CATS if c in cats] + sorted(c for c in cats if c not in CATS):
        v = cats.get(c) or {}
        out.append((c, _n(v.get("score")), w.get(c, 0), v.get("n"), v.get("passed")))
    return out


def _groups(tasks):
    """Contiguous runs of one category in task order: [(cat, first_index, last_index)] over positions 0..n-1."""
    g = []
    for k, e in enumerate(tasks):
        c = e.get("category", "")
        if g and g[-1][0] == c:
            g[-1][2] = k
        else:
            g.append([c, k, k])
    return g


def charts(s, events, outdir):
    """Five print-styled charts. Each is saved as PNG (the zip contract) and SVG (crisp vectors for report.pdf).
    Figures are drawn at their printed size (7.1 in = the A4 text width) so 8.5 pt in the figure is 8.5 pt on paper."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.transforms import blended_transform_factory as blend
    plt.rcParams.update({"font.family": ["Inter", "DejaVu Sans"], "font.size": 8.5, "text.color": INK,
                         "axes.labelcolor": INK2, "axes.labelsize": 8, "axes.edgecolor": GRAY, "axes.linewidth": 0.8,
                         "xtick.color": MUT, "ytick.color": MUT, "xtick.labelsize": 7.5, "ytick.labelsize": 7.5,
                         "xtick.major.size": 0, "ytick.major.size": 0, "axes.spines.top": False, "axes.spines.right": False,
                         "axes.spines.left": False, "axes.grid": True, "axes.grid.axis": "y", "grid.color": LINE,
                         "grid.linewidth": 0.6, "axes.axisbelow": True, "figure.facecolor": "white", "axes.facecolor": "white",
                         "axes.titlesize": 10, "axes.titleweight": "semibold", "axes.titlelocation": "left",
                         "axes.titlecolor": INK, "axes.titlepad": 10, "legend.frameon": False, "legend.fontsize": 7.5,
                         "svg.fonttype": "path", "hatch.linewidth": 0.6})
    os.makedirs(outdir, exist_ok=True)
    tasks = [e for e in events if e.get("phase") == "task"]
    paths = []

    def title(fig, t):
        fig.suptitle(t, x=0.008, ha="left", fontsize=10, fontweight="semibold", color=INK)

    def save(fig, name):
        p = os.path.join(outdir, name)
        fig.savefig(p, dpi=200, facecolor="white")
        fig.savefig(p[:-4] + ".svg", facecolor="white")
        plt.close(fig)
        paths.append(p)

    def task_axis(ax, ymax):
        # alternate shaded bands per category so the per-task charts read by category without a legend
        tr = blend(ax.transData, ax.transAxes)
        for j, (c, a, b) in enumerate(_groups(tasks)):
            if j % 2:
                ax.axvspan(a - 0.5, b + 0.5, color=SOFT, zorder=0, lw=0)
            ax.text((a + b) / 2, 1.0, c, transform=tr, ha="center", va="bottom", fontsize=7, color=MUT, clip_on=False)
        ax.set_xlim(-0.6, max(len(tasks), 1) - 0.4)
        ax.set_ylim(0, ymax)
        ax.set_xticks(range(len(tasks)), [str(e.get("i", k + 1)) for k, e in enumerate(tasks)],
                      fontsize=7 if len(tasks) <= 24 else 6)
        ax.set_xlabel("task # (see the task table)")

    def ref_line(ax, y, label):
        ax.axhline(y, color=INK2, lw=0.9, ls=(0, (4, 3)), zorder=3)
        ax.text(1.008, y, label, transform=blend(ax.transAxes, ax.transData), ha="left", va="center", fontsize=7.5,
                color=INK2, clip_on=False)

    # 1 overall score card (standalone PNG; the PDF draws the same thing in HTML)
    v = _n(s.get("overall")) or 0.0
    lo, name, tone, _ = band(v)
    fig, ax = plt.subplots(figsize=(4.8, 1.9), layout="constrained")
    ax.axis("off"), ax.set_xlim(0, 100), ax.set_ylim(0, 1)
    big = ax.text(0, 0.62, f"{v:.1f}", fontsize=34, weight="bold", color=INK, va="baseline")
    ax.annotate("/ 100", xy=(1, 0), xycoords=big, xytext=(6, 0), textcoords="offset points", fontsize=12, color=MUT,
                va="bottom")  # anchored to the number's right edge, whatever its width
    ax.text(100, 0.62, name.upper(), fontsize=12, weight="bold", color=STATUS[tone][0], ha="right", va="baseline")
    ax.text(0, 0.98, s.get("model", "?"), fontsize=10, weight="semibold", color=INK, va="top")
    for a, b, lab in ((0, 45, "weak < 45"), (45, 70, "usable 45-70"), (70, 100, "strong 70+")):
        ax.barh(0.3, b - a, left=a, height=0.12, color=ACC if lab.startswith(name.lower()) else LINE, edgecolor="white", lw=1.5)
        ax.text((a + b) / 2, 0.08, lab, ha="center", fontsize=7.5, color=MUT)
    if _n(s.get("overall")) is not None:
        ax.plot([v], [0.43], marker="v", ms=8, color=INK)
    save(fig, "01-overall-gauge.png")

    # 2 category bars, value printed at the bar end, the per-task pass line for reference
    rows = _cat_rows(s)
    fig, ax = plt.subplots(figsize=(7.1, 0.36 * max(len(rows), 1) + 0.9), layout="constrained")
    ys = list(range(len(rows)))[::-1]
    for y, (c, sc, w, n, p) in zip(ys, rows):
        val = 100 * (sc or 0)
        ax.barh(y, 100, color=SOFT, height=0.56, lw=0, zorder=1)
        ax.barh(y, val, color=ACC, height=0.56, lw=0, zorder=3)  # over the pass line, so the line never cuts a label
        inside = val >= 14
        ax.text(val - 1.5 if inside else val + 1.5, y, f"{val:.0f}" if sc is not None else "n/a", va="center",
                ha="right" if inside else "left", color="white" if inside else INK, fontsize=8.5, weight="semibold", zorder=4)
        ax.text(101.5, y, f"{p}/{n} passed" if n is not None else "", va="center", fontsize=7.5, color=MUT)
    ax.set_yticks(ys, [f"{c}  (w{w})" for c, _, w, _, _ in rows], fontsize=8.5, color=INK)
    ax.axvline(100 * PASS_AT, color=INK2, lw=0.8, ls=(0, (2, 2)), zorder=2)
    ax.text(100 * PASS_AT, len(rows) - 0.45, "task pass line", fontsize=7, color=INK2, ha="center", va="bottom")
    ax.set_xlim(0, 100), ax.grid(False), ax.set_xticks([0, 20, 40, 60, 80, 100])
    ax.set_xlabel("category score (mean of its task scores x 100)")
    title(fig, "Score by category")
    save(fig, "02-category-bars.png")

    # 3 latency per task, failed tasks hatched gray, p50/p95 reference lines
    lat = [_n(e.get("latency_s")) or 0 for e in tasks]
    fig, ax = plt.subplots(figsize=(7.1, 2.5), layout="constrained")
    ok = [bool(e.get("ok")) for e in tasks]
    ax.bar([k for k in range(len(tasks)) if ok[k]], [lat[k] for k in range(len(tasks)) if ok[k]], width=0.62, color=ACC,
           lw=0, label="passed", zorder=2)
    ax.bar([k for k in range(len(tasks)) if not ok[k]], [lat[k] for k in range(len(tasks)) if not ok[k]], width=0.62,
           color=GRAY, edgecolor="#8a9099", hatch="////", lw=0, label="failed", zorder=2)
    # one runaway call would flatten every other bar: cap the axis near p95 and print the clipped bar's real value
    top = max(lat + [1]) * 1.15
    cap = max(1.6 * (_n(s.get("latency_p95")) or 0), 5.0)
    if top > cap * 1.3:
        top = cap * 1.15
        for k, x in enumerate(lat):
            if x > top:
                ax.text(k, top * 0.97, f"{x:.0f} s", ha="center", va="top", fontsize=7, color=INK, weight="semibold",
                        zorder=5, bbox=dict(fc="white", ec=GRAY, lw=0.6, pad=1.2, boxstyle="round,pad=0.25"))
    task_axis(ax, top)
    for key, lab in (("latency_p50", "p50"), ("latency_p95", "p95")):
        if _n(s.get(key)) is not None:
            ref_line(ax, s[key], f"{lab} {s[key]:.1f} s")
    ax.set_ylabel("seconds per task")
    title(fig, "Latency per task")
    fig.legend(loc="outside upper right", ncols=2, handlelength=1.2)
    if top < max(lat + [0]):
        ax.text(0, -0.3, "axis capped; a boxed value is a bar that runs off the top", transform=ax.transAxes, fontsize=7,
                color=MUT, va="top")
    save(fig, "03-latency-by-task.png")

    # 4 generation speed per task, mean reference line (tasks with no generation timing are left blank)
    tk = [_n(e.get("tok_s")) or 0 for e in tasks]
    fig, ax = plt.subplots(figsize=(7.1, 2.3), layout="constrained")
    ax.bar(range(len(tasks)), tk, width=0.62, color=ACC, lw=0, zorder=2)
    task_axis(ax, max(tk + [1]) * 1.18)
    if _n(s.get("tok_s_mean")):
        ref_line(ax, s["tok_s_mean"], f"mean {s['tok_s_mean']:.1f} tok/s")
    ax.set_ylabel("tokens / second")
    title(fig, "Generation speed per task")
    save(fig, "04-speed-by-task.png")

    # 5 leaderboard: every finished run (best 12), this run in the accent, the verdict cut points marked
    allss = [x for x in summaries() if _n(x.get("overall")) is not None and x.get("run") != s.get("run")]
    allss = sorted(allss, key=lambda x: x["overall"])[-11:] + [s]
    allss.sort(key=lambda x: _n(x.get("overall")) or 0)
    fig, ax = plt.subplots(figsize=(7.1, 0.3 * len(allss) + 1.0), layout="constrained")
    for y, x in enumerate(allss):
        me = x.get("run") == s.get("run")
        xv = _n(x.get("overall")) or 0
        ax.barh(y, xv, color=ACC if me else GRAY, height=0.6, lw=0, zorder=2)
        ax.text(xv + 1, y, f"{xv:.1f}" + ("   this run" if me else ""), va="center", fontsize=8, zorder=3,
                color=INK, weight="semibold" if me else "normal", bbox=dict(fc="white", ec="none", pad=0.8))
    lab = [f"{x.get('model', '?')}  ·  {x.get('suite', '?')}  ·  {_when(x.get('started'))[5:16]}" for x in allss]
    ax.set_yticks(range(len(allss)), lab, fontsize=7.5, color=INK)
    for cut, nm in ((45, "usable"), (70, "strong")):
        ax.axvline(cut, color=INK2, lw=0.8, ls=(0, (2, 2)), zorder=1)
        ax.text(cut + 0.8, len(allss) - 0.4, nm, fontsize=7, color=INK2, va="bottom")
    ax.set_xlim(0, 112), ax.set_ylim(-0.6, len(allss) - 0.1), ax.grid(axis="x"), ax.grid(axis="y", visible=False)
    ax.set_xticks([0, 20, 40, 60, 80, 100])
    ax.set_xlabel("overall score / 100 (quick and full suites differ; compare like with like)")
    title(fig, "Leaderboard: all finished runs")
    save(fig, "05-leaderboard.png")
    return paths


def report_html(s, events, chart_names):
    """Print layout for headless Chrome: summary page, category bars, weak areas, charts, method, task table."""
    E = lambda x: html.escape(str(x))  # noqa: E731
    tasks = [e for e in events if e.get("phase") == "task"]
    errs = [e for e in events if e.get("phase") == "error"]
    meta = load_json(os.path.join(run_dir(s.get("run", "")), "meta.json"), {}) or {}
    rows = _cat_rows(s)
    wsum = sum(w for _, sc, w, _, _ in rows if sc is not None) or 1
    ov = _n(s.get("overall"))
    lo, vname, tone, vline = band(ov)
    col, bg = STATUS[tone]
    ntask, npass = s.get("tasks", len(tasks)), s.get("passed", sum(1 for e in tasks if e.get("ok")))
    pen = _n(s.get("speed_penalty")) or 0.0

    # headline sentence: what went best, what cost the most points
    scored = [(c, sc, w) for c, sc, w, _, _ in rows if sc is not None]
    lost = sorted(((100 * w * (1 - sc) / wsum, c, sc) for c, sc, w in scored if sc < 1), reverse=True)
    best = [c for c, sc, _ in scored if sc == max(x[1] for x in scored)] if scored else []
    head = f"Passed {npass} of {ntask} tasks."
    if best:
        head += f" Best: {', '.join(best)} ({100 * max(x[1] for x in scored):.0f})."
    if lost:
        head += f" Biggest loss: {lost[0][1]}, costing {lost[0][0]:.1f} points."
    if pen:
        head += f" Slow median call cost {pen:.1f} more."

    # hero: score, verdict band, band scale with a marker
    pos = min(100.0, max(0.0, ov or 0.0))
    hero = f"""<section class="hero">
 <div class="score"><div class="big">{_f(ov)}</div><div class="of">/ 100 overall</div></div>
 <div class="verdict">
  <div class="chip" style="color:{col};background:{bg};border-color:{col}">{vname.upper()}</div>
  <p class="vline">{E(vline)}</p><p class="headline">{E(head)}</p>
  <div class="scale"><div class="seg" style="width:45%"><span>Weak &lt; 45</span></div><div class="seg" style="width:25%">
  <span>Usable 45&ndash;70</span></div><div class="seg" style="width:30%"><span>Strong 70+</span></div>
  {'' if ov is None else f'<i class="mark" style="left:{pos:.1f}%"></i>'}</div>
 </div>
 <dl class="facts"><dt>Tasks passed</dt><dd>{E(npass)} / {E(ntask)}</dd><dt>Raw score</dt><dd>{_f(s.get('overall_raw'))}</dd>
  <dt>Speed penalty</dt><dd>{'none' if not pen else '&minus;' + _f(pen)}</dd><dt>Errors</dt><dd>{E(s.get('errors', len(errs)))}</dd>
  <dt>Wall time</dt><dd>{_f(_n(s.get('wall_s')) and s['wall_s'] / 60, '{:.1f}', ' min')}</dd></dl>
</section>"""

    # readout tiles: value, small sub-value, optional meter, one line of meaning
    p50 = _n(s.get("latency_p50"))
    budget = ("within the 20 s budget, no penalty" if p50 is not None and p50 <= 20 else
              f"over the 20 s budget: &minus;{pen:.1f} pts" if p50 is not None else "")
    tiles = [("Latency (median)", _f(p50, unit=" s"), f"p95 {_f(s.get('latency_p95'), unit=' s')}", None,
              f"Seconds per task call; {budget}." if budget else "Seconds per task call."),
             ("Time to first token", _f(s.get("ttft_p50"), unit=" s"), "median", None,
              "Wait before the reply starts streaming back."),
             ("Generation speed", _f(s.get("tok_s_mean"), unit=" tok/s"), "mean over tasks", None,
              "Tokens produced per second once generation starts."),
             ("VRAM", _f(s.get("vram_gb"), unit=" GB"), "peak during the run", None,
              "GPU memory the loaded model held."),
             ("JSON validity", _rate(s.get("json_valid_rate")), "decision + json tasks", s.get("json_valid_rate"),
              "Replies that came back as usable JSON. Higher is better."),
             ("Precheck pass", _rate(s.get("precheck_pass_rate")), "decision tasks", s.get("precheck_pass_rate"),
              "Brain decisions the bot's own precheck() would accept."),
             ("Grounding", _rate(s.get("grounding_rate")), "grounding tasks", s.get("grounding_rate"),
              "Report drafts with no invented facts, hedges or overruns."),
             ("Refusal rate", _rate(s.get("refusal_rate")), "refusal tasks", s.get("refusal_rate"),
              "Benign research prompts the model refused. Lower is better.")]

    def tile(lab, val, sub, meter, mean):
        m = _n(meter)
        bar = f"<div class='meter'><i style='width:{100 * m:.0f}%'></i></div>" if m is not None else ""
        return (f"<div class='tile'><div class='tl'>{E(lab)}</div><div class='tv'>{E(val)}</div><div class='ts'>{E(sub)}</div>"
                f"{bar}<div class='tm'>{mean}</div></div>")
    tiles_h = "".join(tile(*t) for t in tiles)

    # category bars (HTML so they match the type), score printed on the bar
    def cat_row(c, sc, w, n, p):
        v = 100 * (sc or 0)
        inside = v >= 14
        lbl = "n/a" if sc is None else f"{v:.0f}"
        return (f"<div class='cat'><div class='cn'>{E(c)}<span>weight {E(w)}</span></div>"
                f"<div class='track'><div class='fill{' in' if inside else ''}' style='width:{v:.1f}%'>{lbl if inside else ''}</div>"
                f"{'' if inside else f'<b class=out style=left:{v:.1f}%>{lbl}</b>'}<i class='pl'></i></div>"
                f"<div class='cp'>{E(p) if p is not None else '?'}/{E(n) if n is not None else '?'} passed</div>"
                f"<div class='cd'>{E(CAT_INFO.get(c, ''))}</div></div>")
    cats_h = "".join(cat_row(*r) for r in rows) or "<p class='muted'>No category scores in this summary.</p>"

    # weak areas: the categories that cost the most points, with the notes of their imperfect tasks
    weak = []
    for pts, c, sc in lost[:3]:
        bad = [e for e in tasks if e.get("category") == c and (_n(e.get("score")) if _n(e.get("score")) is not None else 1) < 1]
        items = "".join(f"<li><code>{E(e.get('task', '?'))}</code> {'failed' if not e.get('ok') else 'partial'}, "
                        f"score {_f(e.get('score'), '{:.2f}')}: {E(_clip(e.get('note'), 140)) or 'no note'}</li>" for e in bad[:4])
        more = f"<li class='muted'>and {len(bad) - 4} more in the task table</li>" if len(bad) > 4 else ""
        weak.append(f"<div class='weak'><div class='wh'><b>{E(c)}</b><span>score {100 * sc:.0f} &middot; costs "
                    f"{pts:.1f} of 100 points</span></div><ul>{items}{more}</ul></div>")
    weak_h = "".join(weak) or ("<p class='muted'>Every category scored 100. Nothing to flag.</p>" if scored else
                               "<p class='muted'>No category scores to rank.</p>")
    if errs:
        weak_h += ("<div class='weak'><div class='wh'><b>run errors</b><span>"
                   f"{len(errs)} error event(s)</span></div><ul>"
                   + "".join(f"<li><code>{E(e.get('task') or 'run')}</code> {E(_clip(e.get('note'), 140))}</li>" for e in errs[:5])
                   + "</ul></div>")

    # charts embed as SVG (vector); the PNG twins ship in the zip
    def fig(n, cap):
        if n not in chart_names:
            return ""
        return f"<figure><img src='charts/{n[:-4]}.svg' alt='{E(cap)}'><figcaption>{cap}</figcaption></figure>"
    figs = (fig("03-latency-by-task.png", "Each bar is one task call; shaded bands group tasks by category. Hatched gray "
                "bars are failed tasks.")
            + fig("04-speed-by-task.png", "Tokens per second while generating, per task. A blank slot is a task with no "
                  "generation timing (an error).")
            + fig("05-leaderboard.png", "Every finished run on this rig. Quick and full suites run different task counts; "
                  "compare like with like."))

    # task table, header repeats on every page, rows never split
    def trow(e):
        okk = bool(e.get("ok"))
        return (f"<tr class='{'' if okk else 'f'}'><td class='r'>{E(e.get('i', ''))}</td><td>{E(e.get('category', ''))}</td>"
                f"<td class='id'><code>{E(e.get('task', ''))}</code></td><td><span class='pill {'p' if okk else 'x'}'>"
                f"{'PASS' if okk else 'FAIL'}</span></td><td class='r'>{_f(e.get('score'), '{:.2f}')}</td>"
                f"<td class='r'>{_f(e.get('latency_s'))}</td><td class='r'>{_f(e.get('tok_s'))}</td>"
                f"<td class='note'>{E(_clip(e.get('note')))}</td></tr>")
    trows = "".join(trow(e) for e in tasks) or "<tr><td colspan='8' class='muted'>No task events recorded.</td></tr>"

    wts = ", ".join(f"{c} {w}" for c, w in (s.get("weights") or suites.WEIGHTS).items())
    host = meta.get("host") or suites.HOST
    tag = s.get("tag") or meta.get("tag") or ""
    foot = re.sub(r"[^A-Za-z0-9 ._:/|-]", "", f"The user Model Lab  |  {s.get('model', '?')}  |  run {s.get('run', '?')}")
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Model Lab report {E(s.get('run', ''))}</title><style>
@page {{ size: A4; margin: 13mm 14mm 15mm;
  @bottom-left {{ content: "{foot}"; font: 7.5pt Inter, 'DejaVu Sans', sans-serif; color: {MUT}; }}
  @bottom-right {{ content: "Page " counter(page) " of " counter(pages); font: 7.5pt Inter, 'DejaVu Sans', sans-serif; color: {MUT}; }} }}
* {{ box-sizing: border-box; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
html, body {{ margin: 0; background: #fff; }}
body {{ font: 9pt/1.4 Inter, 'DejaVu Sans', Arial, sans-serif; color: {INK}; font-variant-numeric: tabular-nums; }}
code {{ font: 8pt 'DejaVu Sans Mono', monospace; color: {INK}; }}
h2 {{ font-size: 11.5pt; margin: 0 0 2mm; font-weight: 650; break-after: avoid; }}
h2 small {{ font-weight: 400; color: {MUT}; font-size: 8.5pt; margin-left: 2mm; }}
section {{ margin-bottom: 5mm; }} .muted {{ color: {MUT}; }}
.top {{ display: flex; justify-content: space-between; align-items: flex-end; border-bottom: 2px solid {INK};
  padding-bottom: 2.5mm; margin-bottom: 4.5mm; }}
.kicker {{ font-size: 7.5pt; letter-spacing: .12em; text-transform: uppercase; color: {ACC}; font-weight: 700; }}
h1 {{ font-size: 21pt; margin: 1mm 0 0; font-weight: 750; letter-spacing: -.01em; }}
.meta {{ text-align: right; font-size: 8pt; color: {INK2}; line-height: 1.55; }} .meta b {{ color: {INK}; font-weight: 600; }}
.hero {{ display: grid; grid-template-columns: 38mm 1fr 44mm; gap: 6mm; align-items: start; background: {SOFT};
  border-radius: 3mm; padding: 4.2mm 5.5mm; margin-bottom: 5mm; break-inside: avoid; }}
.big {{ font-size: 40pt; font-weight: 800; line-height: 1; letter-spacing: -.02em; }}
.of {{ color: {MUT}; font-size: 8.5pt; margin-top: 1.5mm; }}
.chip {{ display: inline-block; font-weight: 800; font-size: 9pt; letter-spacing: .1em; padding: .6mm 2.6mm;
  border: 1px solid; border-radius: 99px; }}
.vline {{ margin: 1.8mm 0 1mm; font-weight: 600; }} .headline {{ margin: 0 0 3.5mm; color: {INK2}; }}
.scale {{ position: relative; display: flex; height: 2.2mm; margin-bottom: 4.5mm; }}
.seg {{ position: relative; background: #dfe2e6; border-right: 2px solid {SOFT}; }}
.seg:nth-child({1 + ([b[1] for b in BANDS[::-1]] + [vname]).index(vname)}) {{ background: {ACC}; }}
.seg span {{ position: absolute; top: 3mm; left: 0; font-size: 7pt; color: {MUT}; white-space: nowrap; }}
.mark {{ position: absolute; top: -1.3mm; width: 0; height: 4.8mm; border-left: 2px solid {INK}; margin-left: -1px; }}
.facts {{ display: grid; grid-template-columns: auto auto; gap: 1mm 3mm; margin: 0; font-size: 8.5pt; }}
.facts dt {{ color: {MUT}; }} .facts dd {{ margin: 0; text-align: right; font-weight: 600; }}
.tiles {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 3mm; }}
.tile {{ border: 1px solid {LINE}; border-radius: 2mm; padding: 2.2mm 3mm; break-inside: avoid; }}
.tl {{ font-size: 7pt; text-transform: uppercase; letter-spacing: .08em; color: {MUT}; font-weight: 600; }}
.tv {{ font-size: 15pt; font-weight: 700; margin-top: .8mm; line-height: 1.15; }}
.ts {{ font-size: 7.5pt; color: {INK2}; }}
.meter {{ height: 1.3mm; background: {LINE}; border-radius: 1mm; margin-top: 1.4mm; overflow: hidden; }}
.meter i {{ display: block; height: 100%; background: {ACC}; }}
.tm {{ font-size: 7.5pt; color: {INK2}; margin-top: 1.6mm; line-height: 1.35; }}
.cat {{ display: grid; grid-template-columns: 30mm 1fr 20mm; column-gap: 4mm; align-items: center; padding: 1.1mm 0;
  border-bottom: 1px solid {LINE}; break-inside: avoid; }}
.cn {{ font-weight: 650; }} .cn span {{ display: block; font-weight: 400; font-size: 7pt; color: {MUT}; }}
.track {{ position: relative; height: 4.6mm; background: {SOFT}; border-radius: 1mm; }}
.fill {{ height: 100%; background: {ACC}; border-radius: 1mm; color: #fff; font-weight: 700; font-size: 8pt;
  text-align: right; line-height: 4.6mm; }} .fill.in {{ padding-right: 1.6mm; }}
.out {{ position: absolute; top: 0; line-height: 4.6mm; margin-left: 1.6mm; font-size: 8pt; }}
.pl {{ position: absolute; left: {100 * PASS_AT:.0f}%; top: -.8mm; bottom: -.8mm; border-left: 1px dashed {INK2}; }}
.cp {{ font-size: 8pt; color: {INK2}; text-align: right; }}
.cd {{ grid-column: 2 / 4; font-size: 7.2pt; color: {MUT}; margin-top: .5mm; }}
.legend {{ font-size: 7.5pt; color: {MUT}; margin-top: 1.5mm; }}
.legend i {{ display: inline-block; width: 0; height: 3mm; border-left: 1px dashed {INK2}; vertical-align: -.5mm; margin: 0 1mm; }}
.weak {{ border-left: 3px solid {ACC}; background: {SOFT}; padding: 2.2mm 3.5mm; margin-bottom: 2.5mm; break-inside: avoid;
  border-radius: 0 2mm 2mm 0; }}
.wh {{ display: flex; justify-content: space-between; }} .wh span {{ color: {INK2}; font-size: 8pt; }}
.weak ul {{ margin: 1.2mm 0 0; padding-left: 4mm; font-size: 8pt; color: {INK2}; }} .weak li {{ margin: .5mm 0; }}
figure {{ margin: 0 0 5mm; break-inside: avoid; }} figure img {{ width: 100%; display: block; }}
figcaption {{ font-size: 7.5pt; color: {MUT}; margin-top: 1mm; }}
.method {{ border: 1px solid {LINE}; border-radius: 2mm; padding: 3mm 4mm; font-size: 8pt; color: {INK2}; break-inside: avoid; }}
.method ul {{ margin: 1mm 0 0; padding-left: 4mm; }} .method li {{ margin: .6mm 0; }} .method b {{ color: {INK}; }}
table {{ border-collapse: collapse; width: 100%; font-size: 8pt; table-layout: fixed; }}
thead {{ display: table-header-group; }} tr {{ break-inside: avoid; }}
th {{ text-align: left; font-size: 7pt; text-transform: uppercase; letter-spacing: .06em; color: {MUT}; font-weight: 600;
  border-bottom: 1.5px solid {INK}; padding: 1.6mm 1.6mm; white-space: nowrap; }}
td {{ border-bottom: 1px solid {LINE}; padding: 1.4mm 1.6mm; vertical-align: top; }}
tr.f td {{ background: #fdf3f3; }} td.r, th.r {{ text-align: right; white-space: nowrap; }}
td.note {{ color: {INK2}; }} td.id {{ white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
td code {{ font-size: 7.5pt; }}
.pill {{ display: inline-block; font-size: 6.8pt; font-weight: 800; letter-spacing: .06em; padding: .2mm 1.6mm; border-radius: 99px;
  border: 1px solid; }}
.pill.p {{ color: {STATUS['good'][0]}; border-color: {STATUS['good'][0]}; background: #fff; }}
.pill.x {{ color: #fff; border-color: {STATUS['poor'][0]}; background: {STATUS['poor'][0]}; }}
</style></head><body>
<header class="top"><div><div class="kicker">the user Model Lab &middot; benchmark report</div><h1>{E(s.get('model', '?'))}</h1></div>
<div class="meta"><b>{E(s.get('suite', '?'))} suite</b>, {E(ntask)} tasks{(' &middot; tag <b>' + E(tag) + '</b>') if tag else ''}<br>
{E(_when(s.get('started')))} &middot; Ollama {E(host)}<br>run {E(s.get('run', '?'))}</div></header>
{hero}
<section><h2>Key readouts</h2><div class="tiles">{tiles_h}</div></section>
<section><h2>Score by category <small>bar = mean task score; dashed line = the {100 * PASS_AT:.0f} a single task needs to pass</small></h2>
{cats_h}</section>
<section><h2>Where it lost points <small>largest first, with the grader's notes</small></h2>{weak_h}</section>
<section class="method"><b>How the score is computed</b><ul>
<li>Each task scores 0 to 1 and <b>passes at {PASS_AT:.1f}</b> or above. A category score is the mean of its task scores.</li>
<li><b>Overall</b> = 100 &times; weighted mean of the category scores run ({E(wts)}) &minus; speed penalty.</li>
<li><b>Speed penalty</b> = min(15, max(0, (median latency &minus; 20 s) &times; 0.5)): none while the median call answers within
20 s, then half a point per extra second, capped at 15.</li>
<li><b>Verdict</b>: Strong at 70 or more, Usable from 45 to 70, Weak below 45.</li>
<li>Decision tasks run the real orch_brain prompt, schema, normalize() and precheck(); grounding runs local-draft ask() and
check(). Every call uses num_ctx {suites.NUM_CTX} on Ollama {E(host)}.</li></ul></section>
<section><h2>Speed and standing</h2>{figs}</section>
<section><h2>Tasks <small>{E(npass)} of {E(ntask)} passed; failed rows are tinted</small></h2>
<table><colgroup><col style="width:7mm"><col style="width:19mm"><col style="width:37mm"><col style="width:14mm">
<col style="width:12mm"><col style="width:16mm"><col style="width:13mm"><col></colgroup>
<thead><tr><th class="r">#</th><th>Category</th><th>Task</th><th>Result</th><th class="r">Score</th><th class="r">Time (s)</th>
<th class="r">tok/s</th><th>Grader note</th></tr></thead><tbody>{trows}</tbody></table></section>
</body></html>"""


def cmd_export(a):
    run = resolve_run(a.run)
    s = load_json(os.path.join(run_dir(run), "summary.json"))
    if not s:
        sys.exit(f"{run} has no summary.json (still running or interrupted)")
    events = load_events(run)
    os.makedirs(EXPORTS, exist_ok=True)
    stage = tempfile.mkdtemp(prefix=f"lab-export-{run}-")
    try:
        cps = charts(s, events, os.path.join(stage, "charts"))
        names = [os.path.basename(p) for p in cps]
        hp = os.path.join(stage, "report.html")
        open(hp, "w").write(report_html(s, events, names))
        pdf = os.path.join(stage, "report.pdf")
        prof = tempfile.mkdtemp(prefix="lab-chrome-")
        try:
            r = subprocess.run([CHROME, "--headless=new", "--no-sandbox", "--disable-gpu", f"--user-data-dir={prof}",
                                "--no-pdf-header-footer", "--print-to-pdf-no-header", f"--print-to-pdf={pdf}", "file://" + hp],
                               capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
        finally:
            shutil.rmtree(prof, ignore_errors=True)
        if not os.path.isfile(pdf) or os.path.getsize(pdf) < 1000:
            sys.exit(f"Chrome did not write the PDF (exit {r.returncode}): {r.stderr.strip()[-300:]}")
        zp = os.path.join(EXPORTS, f"{run}.zip")
        with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as z:
            z.write(pdf, "report.pdf")
            for p in cps:
                z.write(p, "charts/" + os.path.basename(p))
            z.write(os.path.join(run_dir(run), "summary.json"), "summary.json")
            z.write(os.path.join(run_dir(run), "events.jsonl"), "events.jsonl")
        os.makedirs(PDF_DIR, exist_ok=True)
        dl = os.path.join(PDF_DIR, f"model-lab-{run}.pdf")
        shutil.copyfile(pdf, dl)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    print(zp)
    print(dl)
    return 0


# ------------------------------------------------------------------ serve

def cmd_serve(a):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse, parse_qs
    page = open(os.path.join(HERE, "dashboard.html"), "rb").read()

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *x):
            pass

        def send(self, code, body, ctype="application/json"):
            b = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if u.path in ("/", "/index.html"):
                return self.send(200, page, "text/html; charset=utf-8")
            if u.path == "/favicon.ico":
                return self.send(204, b"", "image/x-icon")
            if u.path == "/api/runs":
                cur = open(CURRENT).read().strip() if os.path.isfile(CURRENT) else ""
                return self.send(200, {"current": cur, "runs": summaries()})
            if u.path.startswith("/api/run/"):
                r = u.path.rsplit("/", 1)[1]
                try:
                    r = resolve_run(r)
                except SystemExit:
                    return self.send(404, {"error": "no such run"})
                return self.send(200, {"meta": load_json(os.path.join(run_dir(r), "meta.json"), {}),
                                       "summary": load_json(os.path.join(run_dir(r), "summary.json")), "events": load_events(r)})
            if u.path == "/events":
                return self.sse(q.get("run", [""])[0])
            return self.send(404, {"error": "not found"})

        def sse(self, fixed):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            def out(ev, data):
                self.wfile.write(f"event: {ev}\ndata: {json.dumps(data)}\n\n".encode())
                self.wfile.flush()
            try:
                out("hello", {"server": "model-lab", "ts": utcnow()})
                last_beat = 0
                while True:
                    run = fixed or (open(CURRENT).read().strip() if os.path.isfile(CURRENT) else "")
                    if not run or not os.path.isdir(run_dir(run)):
                        if time.time() - last_beat > 2:
                            out("idle", {"ts": utcnow()})
                            last_beat = time.time()
                        time.sleep(0.5)
                        continue
                    out("reset", load_json(os.path.join(run_dir(run), "meta.json"), {}))
                    pos, buf = 0, b""
                    path = os.path.join(run_dir(run), "events.jsonl")
                    ended = False
                    while True:
                        try:
                            with open(path, "rb") as f:
                                f.seek(pos)
                                chunk = f.read()
                                pos = f.tell()
                        except OSError:
                            chunk = b""
                        buf += chunk
                        while b"\n" in buf:
                            ln, buf = buf.split(b"\n", 1)
                            try:
                                e = json.loads(ln)
                            except ValueError:
                                continue
                            out("lab", e)
                            if e.get("phase") == "end":
                                ended = True
                        if ended:
                            out("done", {"run": run})
                            break
                        cur = open(CURRENT).read().strip() if os.path.isfile(CURRENT) else ""
                        if not fixed and cur != run and not chunk:
                            out("done", {"run": run, "note": "run no longer current"})
                            break
                        if time.time() - last_beat > 10:
                            self.wfile.write(b": beat\n\n")
                            self.wfile.flush()
                            last_beat = time.time()
                        time.sleep(0.3)
                    if fixed:
                        return
                    while os.path.isfile(CURRENT) and open(CURRENT).read().strip() == run:
                        time.sleep(0.5)
            except (BrokenPipeError, ConnectionResetError):
                return

    srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    srv.daemon_threads = True
    print(f"The user Model Lab dashboard: http://127.0.0.1:{a.port}/   (Ctrl-C to stop)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


def main(argv):
    p = argparse.ArgumentParser(prog="lab.py", description="The user Model Lab")
    sp = p.add_subparsers(dest="cmd")
    b = sp.add_parser("bench")
    b.add_argument("model")
    b.add_argument("--suite", choices=["quick", "full"], default="quick")
    b.add_argument("--tag", default="")
    s = sp.add_parser("serve")
    s.add_argument("--port", type=int, default=8765)
    e = sp.add_parser("export")
    e.add_argument("run")
    sp.add_parser("list")
    c = sp.add_parser("compare")
    c.add_argument("runs", nargs="+")
    a = p.parse_args(argv)
    if not a.cmd:
        print(__doc__)
        return 2
    os.makedirs(RUNS, exist_ok=True)
    return {"bench": cmd_bench, "serve": cmd_serve, "export": cmd_export, "list": cmd_list, "compare": cmd_compare}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
