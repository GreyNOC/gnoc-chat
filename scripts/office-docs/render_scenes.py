"""Render the office from FIXTURE state for named scenarios, for any version of gnoc-office.py.

    python3 scenes.py <gnoc-office.py> <outdir> [scenario ...]
    python3 render_scenes.py                 (no arguments: the COMPANY and FLOOR fixture scenes into ./screens/)

Only the STATE is faked (files under a temp state root + a pm2 row list); the office code runs unmodified.
Writes <outdir>/<scenario>.txt (plain), .png (256-colour render) and prints a one-line summary per scenario.
"""
import importlib.machinery, importlib.util, json, os, shutil, sqlite3, sys, tempfile, time
from datetime import datetime, timezone, timedelta

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
W, H = 200, 60
NOW = datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ago(**kw):
    return iso(NOW - timedelta(**kw))


PROCS = ["greynoc", "keepalive", "greynoc-onion", "greynoc-tunnel", "qwen3:8b", "desktop-proxy", "control-panel",
         "orch-bot", "pipeline-sweep", "oss-bot", "office-stream", "split-llm"]


def pm2_rows(cpu=None, down=()):
    cpu = cpu or {}
    return [{"name": n, "status": "stopped" if n in down else "online", "cpu": cpu.get(n, 0.3), "mem_mb": 80,
             "restarts": 0, "uptime_ms": (time.time() - 7200) * 1000, "pid": 1000 + i} for i, n in enumerate(PROCS)]


def write(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        fh.write(text)


def jl(rows):
    return "".join(json.dumps(r) + "\n" for r in rows)


def base_state(root, *, boss_in=True, stop=False, oss_open=12):
    write(root, "orch/brain.jsonl", jl([{"ts": ago(minutes=40), "action": "wait", "status": "ok",
                                          "reason": "nothing due; queue is empty"}]))
    write(root, "orch/orch.log", f"[{ago(minutes=41)}] auto-target pick started pid 4242\n"
                                 f"[{ago(minutes=40)}] auto-target done: nothing viable right now\n")
    write(root, "orch/state.json", json.dumps({"current": {}}))
    write(root, "orch/models.json", json.dumps({"hunter": "local", "brain": "local"}))
    write(root, "orch/hosts.json", "{}")
    write(root, "orch/office-intensity", "3")
    write(root, "orch/INBOX.md", "# inbox\n")
    write(root, "hunt-loop/outcomes.jsonl", "")
    write(root, "hunt-loop/ships.jsonl", "")
    write(root, "hunt-loop/rescue-ledger.json", json.dumps({"_meta": {"dispatch_log": []}}))
    write(root, "hunt-loop/RESCUE-BOARD.md", "| state | count |\n|---|---|\n| ACTIVE | 3 |\n| NEEDS | 1 |\n")
    if stop:
        write(root, "hunt-loop/STOP", "")
    write(root, "office/mood.json", "{}")
    write(root, "office/settings.json", json.dumps({"intensity": 3}))
    write(root, "office/boss.json", json.dumps({"here": boss_in, "since": time.time() - 1800}))
    write(root, "office/h1-activity.json", json.dumps({"seen": {}, "events": []}))
    os.makedirs(os.path.join(root, "oss-bot"), exist_ok=True)
    db = sqlite3.connect(os.path.join(root, "oss-bot/bot.db"))
    db.execute("CREATE TABLE leads (id INTEGER, state TEXT, suppressed TEXT, program TEXT)")
    db.execute("CREATE TABLE runs (id INTEGER, program TEXT, job TEXT, rc INTEGER, audit TEXT, leads_new INTEGER, ended TEXT)")
    db.executemany("INSERT INTO leads VALUES (?,?,?,?)", [(i, "LEAD", None, "gatewayco") for i in range(oss_open)])
    db.execute("INSERT INTO runs VALUES (1,'gatewayco','js-endpoints',0,'AUDIT OK',0,?)", (ago(hours=2),))
    db.commit()
    db.close()
    write(root, "oss-bot/triage.json", json.dumps({}))
    write(root, "oss-bot/review.json", json.dumps({}))


# each scenario: (state builder, live-change applied AFTER the first poll so events fire, pm2 rows, h1 data)
def sc_idle(root):
    base_state(root, stop=True)
    return None, pm2_rows(), {"up": True, "n_reports": 7, "states": {"duplicate": 5, "not-applicable": 2}, "events": []}


def sc_midhunt(root):
    base_state(root)
    rows = [{"ts": ago(minutes=m), "lane": "auto", "target": "gatewayco", "vector": "unauth sweep", "verdict": v,
             "probes": p, "burst": False} for m, v, p in ((50, "DEAD", 24), (35, "UNFIRED", 0), (20, "DEAD", 31))]
    write(root, "hunt-loop/outcomes.jsonl", jl(rows))
    write(root, "orch/state.json", json.dumps({"current": {"program": "gatewayco", "kind": "hunt"}}))

    def later(r):
        with open(os.path.join(r, "orch/orch.log"), "a") as fh:
            fh.write(f"[{ago(minutes=3)}] auto-hunt started pid 777 gatewayco: /x\n")
            fh.write(f"[{ago(minutes=2)}] auto-hunt done: api.acmehq.com: fired 42, hits 0, leads 0\n")
            fh.write(f"[{ago(minutes=1)}] auto-hunt done: cloud.acmehq.com: fired 17, hits 0, leads 1\n")
        with open(os.path.join(r, "hunt-loop/outcomes.jsonl"), "a") as fh:  # auto-hunt.py writes one per swept host
            for host, fired, weak in (("api.acmehq.com", 42, 0), ("cloud.acmehq.com", 17, 1)):
                fh.write(json.dumps({"ts": ago(minutes=1), "lane": "auto-exposure-kong", "target": "gatewayco",
                                     "vector": f"auto-hunt unauth exposure sweep {host}", "verdict": "UNFIRED",
                                     "probes": fired, "burst": False, "notes": f"orch-bot auto-hunt; full sweep; weak leads {weak}"}) + "\n")
        with open(os.path.join(r, "orch/brain.jsonl"), "a") as fh:
            fh.write(json.dumps({"ts": ago(seconds=20), "action": "sweep_host", "status": "ok",
                                 "reason": "gatewayco has two unswept in-scope hosts"}) + "\n")
    return later, pm2_rows(cpu={"orch-bot": 22, "qwen3:8b": 64}), {"up": True, "n_reports": 7,
                                                                     "states": {"duplicate": 5, "not-applicable": 2}, "events": []}


def sc_triage(root):
    base_state(root, oss_open=83)
    write(root, "hunt-loop/outcomes.jsonl", jl([{"ts": ago(minutes=30), "lane": "auto", "target": "gatewayco",
                                                 "vector": "cors", "verdict": "LEAD", "probes": 18, "burst": True}]))

    def later(r):
        db = sqlite3.connect(os.path.join(r, "oss-bot/bot.db"))
        db.execute("INSERT INTO runs VALUES (2,'gatewayco','secrets',0,'AUDIT OK',3,?)", (ago(seconds=30),))
        db.executemany("INSERT INTO leads VALUES (?,?,?,?)", [(900 + i, "LEAD", None, "gatewayco") for i in range(3)])
        db.commit()
        db.close()
        with open(os.path.join(r, "hunt-loop/outcomes.jsonl"), "a") as fh:
            fh.write(json.dumps({"ts": ago(seconds=10), "lane": "auto", "target": "gatewayco", "vector": "token mint",
                                 "verdict": "LEAD", "probes": 26, "burst": True}) + "\n")
    return later, pm2_rows(cpu={"oss-bot": 40}), {"up": True, "n_reports": 7,
                                                  "states": {"duplicate": 5, "not-applicable": 2}, "events": []}


def sc_filed(root):
    base_state(root)
    write(root, "hunt-loop/outcomes.jsonl", jl([{"ts": ago(hours=1), "lane": "x", "target": "gatewayco",
                                                 "vector": "oauth mix-up", "verdict": "CRITICAL-CANDIDATE",
                                                 "probes": 140, "burst": True}]))
    write(root, "hunt-loop/ships.jsonl", jl([{"ts": ago(minutes=50), "kind": "draft", "program": "gatewayco",
                                              "title": "OAuth mix-up lets one tenant redeem another's code",
                                              "path": "reports/drafts/gatewayco/x/report.md"}]))

    def later(r):
        with open(os.path.join(r, "hunt-loop/ships.jsonl"), "a") as fh:
            fh.write(json.dumps({"ts": ago(seconds=15), "kind": "submission", "program": "gatewayco", "report_id": "4200001",
                                 "title": "OAuth mix-up lets one tenant redeem another's code"}) + "\n")
    return later, pm2_rows(cpu={"control-panel": 12}), {"up": True, "n_reports": 8,
                                                        "states": {"duplicate": 5, "not-applicable": 2, "new": 1}, "events": []}


def sc_bossout(root):
    base_state(root, boss_in=False)
    return None, pm2_rows(down=("split-llm",)), {"up": True, "n_reports": 7,
                                                 "states": {"duplicate": 5, "not-applicable": 2}, "events": []}


def sc_company(root):
    """COMPANY (bots-only floor): a running company with payroll, one probation bot, markets and two bounties."""
    base_state(root, stop=True)
    roster = [("lead", "lead analyst", 1180, 0.21, "working", "bounty B2 shopco: business-logic: coupon reuse"),
              ("worker", "lane worker", 960, 0.34, "working", "lane shopco/company-worker-b1-10230110"),
              ("reflector", "reflector", 1005, None, "idle", ""), ("brain", "brain", 1000, None, "idle", ""),
              ("phone-4b", "phone model, the manager's voice", 1040, 0.12, "working", "decided wait (ok)"),
              ("phone-1.7b", "phone model", 1000, None, "idle", ""),
              ("oss-bot", "scanner", 1000, None, "idle", "scheduled scans"),
              ("hunter", "hunter", 70, 0.61, "probation", ""), ("chat", "chat desk", 1000, None, "idle", ""),
              ("orch-bot", "manager", 1000, None, "working", "managing the company")]
    company = {"schema": 1, "updated": ago(seconds=20), "started": ago(hours=3), "paused": False, "stop": True,
               "auto_hunt": "target", "reserve": 98200, "escrow": 1260, "bot_of_day": "lead",
               "roster": [{"bot": b, "role": r, "wallet": w, "brier": br, "status": s, "assignment": a,
                           "run": 2 if s == "working" else 0, "morale": 72 if s != "probation" else 18,
                           "probation": s == "probation", "rc_per_probe": None} for b, r, w, br, s, a in roster],
               "bets": [{"ref": "mkt:shopco:H3", "program": "shopco", "hyp": "H3", "long": 40, "short": 10,
                            "budget": 80},
                           {"ref": "mkt:shopco:H5", "program": "shopco", "hyp": "H5", "long": 10, "short": 25,
                            "budget": 20}],
               "bounties": [{"id": "B1", "program": "shopco", "crown": "improper-auth: reset token reuse",
                             "amount": 600, "state": "open", "claimant": None, "poster": "orch-bot"},
                            {"id": "B2", "program": "shopco", "crown": "business-logic: coupon reuse", "amount": 300,
                             "state": "claimed", "claimant": "lead", "poster": "orch-bot"}],
               "pnl": {"minted_24h": 175, "burnt_24h": 412, "net_24h": -237, "drafts_24h": 1, "ready_24h": 0,
                       "rc_per_draft": 412.0, "rc_per_ready": None, "dupe_odds": 0.5},
               "bonus": {"day": "2026-10-22", "minted": 175, "pool": 3,
                         "paid": [{"bot": "lead", "amount": 1, "category": "best-brier"}]},
               "manager": {"bubble": "Two lanes on the board, one bot on probation, keep the floor honest.",
                           "voice": "template"}, "errors": {}, "results": {}, "last": {}}
    write(root, "economy/company.json", json.dumps(company))
    write(root, "economy/line.json", json.dumps({"updated": ago(seconds=40), "programs": {"shopco": [
        {"id": "202610230100-abcd", "station": 3, "name": "MARKET", "age_s": 5400, "rc_spent": 14, "budget_rc": 100,
         "class": "business-logic", "crown": "business-logic: coupon reuse", "items": {"H1": "PROBE"}},
        {"id": "202610230120-beef", "station": 0, "name": "SALES", "age_s": 600, "rc_spent": 0, "budget_rc": 200,
         "class": "unauth", "crown": "improper-auth: reset token reuse", "items": {}}]}}))
    write(root, "orch/brain.jsonl", jl([{"ts": ago(seconds=30), "action": "wait", "status": "wait",
                                          "reason": "STOP is set; the company keeps its books", "host": "phone",
                                          "model": "qwen3:8b"}]))
    return None, pm2_rows(), {"up": True, "n_reports": 7, "states": {"duplicate": 5, "not-applicable": 2}, "events": []}


def sc_floor(root):
    """THE FLOOR IS THE LINE: four plain rooms, seven open jobs in the hallway, one report waiting, a story. The
    kanban, staffing, boards and story sentences come from gnoc_company's own code (floor, screen, _ledger_story)."""
    sc_company(root)
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    import gnoc_company as C
    C.VOICE_OFF = True
    C.LINE_JSON = os.path.join(root, "economy/line.json")

    def wo(i, station, cls, items, age):
        return {"id": f"2026102301{i:02d}-{'abcd' if i == 0 else 'b%03d' % i}", "station": station, "name": "",
                "age_s": age, "rc_spent": 3 * i, "budget_rc": 100, "class": cls, "crown": f"{cls}: crown {i}",
                "items": items}
    views = [wo(0, 3, "business-logic", {"H1": "MARKET", "H2": "PROBE CANDIDATE", "H3": "PROBE DEAD"}, 5400),
             wo(1, 0, "unauth", {}, 600), wo(2, 3, "xss", {"H1": "MARKET", "H2": "MARKET"}, 3000),
             wo(3, 3, "ssrf", {"H1": "QA"}, 86400 + 4000), wo(4, 3, "idor", {"H1": "MARKET"}, 7200),
             wo(5, 1, "business-logic", {}, 1500), wo(6, 1, "unauth", {}, 900)]
    write(root, "economy/line.json", json.dumps({"updated": ago(seconds=30), "programs": {"shopco": views}}))
    c = json.load(open(os.path.join(root, "economy/company.json")))
    c["bounties"].append({"id": "B3", "program": "shopco", "crown": "business-logic: refund twice", "amount": 300,
                          "state": "open", "claimant": None, "poster": "orch-bot"})
    c["work_orders"] = {"B1": {"wo_id": views[1]["id"]}, "B2": {"wo_id": views[0]["id"]}}
    for r in c["roster"]:
        if r["bot"] == "worker":
            r["assignment"] = "lane shopco/company-worker-b2-wo202610230100abcd-10230110"
        if r["bot"] == "lead":
            r["assignment"] = "bounty B1 shopco: improper-auth: reset token reuse"
        if r["bot"] == "brain":
            r["rc_per_probe"], r["brier"] = 1.4, 0.18
    c["last"] = {"retro": time.time() - 3 * 86400}
    C.STORY = os.path.join(root, "economy/story.jsonl")
    C.STATUS_MD = os.path.join(root, "reports/STATUS.md")
    write(root, "reports/STATUS.md", "## 2. Ready for QA\n| hackerone | shopco | `coupon-applied-twice-at-checkout` | x |\n")
    led = [{"ts": ago(minutes=50), "seq": 1, "kind": "stake", "from": "orch-bot", "to": "escrow", "amount": 300,
            "ref": "bty:B3", "memo": json.dumps({"program": "shopco"})},
           {"ts": ago(minutes=40), "seq": 2, "kind": "stake", "from": "worker", "to": "escrow", "amount": 10,
            "ref": "mkt:shopco:H3", "memo": "long:post"},
           {"ts": ago(minutes=35), "seq": 3, "kind": "stake", "from": "phone-4b", "to": "escrow", "amount": 10,
            "ref": "mkt:shopco:H3", "memo": "short:bet"},
           {"ts": ago(minutes=5), "seq": 4, "kind": "mint", "from": "mint", "to": "worker", "amount": 50,
            "ref": "oracle:shopco:H3:o1", "memo": "oracle-pass prover"}]
    by_ref = {}
    for r in led:
        by_ref.setdefault(r["ref"], []).append(r)
    rows = [{"ts": r["ts"], "kind": k, "bot": b, "text": t} for r in led for k, b, t in [C._ledger_story(r, by_ref)]]
    rows.insert(1, {"ts": ago(minutes=45), "kind": "job", "bot": "worker",
                    "text": "The Manager sent Q to hunt logic bugs on shopco"})
    rows.append({"ts": ago(minutes=2), "kind": "report", "bot": None, "text": "Report ready for the user: shopco"})
    C._story_write(rows)
    C.floor(c, [], time.time())
    C.screen(c, led, time.time())
    write(root, "economy/company.json", json.dumps(c))
    return None, pm2_rows(), {"up": True, "n_reports": 7, "states": {"duplicate": 5, "not-applicable": 2}, "events": []}


SCENES = {"floor": sc_floor, "company": sc_company, "idle": sc_idle, "mid-hunt": sc_midhunt, "lead-in-triage": sc_triage, "report-filed": sc_filed,
          "boss-out": sc_bossout}


def load(path, root):
    os.environ.pop("GNOC_OFFICE_PUBLIC", None)
    # these fixtures are COMPANY-floor scenes; the office's default floor became UNITS on 2026-10-24
    os.environ.setdefault("GNOC_OFFICE_UNITS", "0")
    ld = importlib.machinery.SourceFileLoader("office_" + str(abs(hash((path, root)))), path)
    sp = importlib.util.spec_from_loader(ld.name, ld)
    m = importlib.util.module_from_spec(sp)
    ld.exec_module(m)
    real = m.STATE
    for k, v in list(vars(m).items()):  # re-point every state path at the fixture root
        if isinstance(v, str) and v.startswith(real):
            setattr(m, k, root + v[len(real):])
    m.jsave = lambda *a, **k: None
    return m


def poll(m, feed, pm2, h1):
    stub = {"pm2": lambda: (m.CPU_HIST.setdefault(pm2[0]["name"], m.deque(maxlen=48)), pm2)[1],
            "hosts": lambda: {}, "h1": lambda: h1, "website": lambda: {}, "lanes": lambda: [], "chat": lambda: {},
            "traffic": lambda: {"n": 0}}
    m.PM2_LAST = pm2
    for name, fn, _ in m.Feed.JOBS:
        try:
            feed.data[name] = stub[name]() if name in stub else fn()
        except Exception as e:  # report, never hide
            print(f"   job {name} failed: {e}")


def render_png(cv, path):
    from PIL import Image, ImageDraw, ImageFont
    font = ImageFont.truetype(FONT, 14)
    cw, chh = 8, 17
    img = Image.new("RGB", (cv.w * cw, cv.h * chh))
    d = ImageDraw.Draw(img)

    def rgb(c):
        if c is None:
            return (0, 0, 0)
        if c < 16:
            base = [(0, 0, 0), (128, 0, 0), (0, 128, 0), (128, 128, 0), (0, 0, 128), (128, 0, 128), (0, 128, 128),
                    (192, 192, 192), (128, 128, 128), (255, 0, 0), (0, 255, 0), (255, 255, 0), (0, 0, 255),
                    (255, 0, 255), (0, 255, 255), (255, 255, 255)]
            return base[c]
        if c < 232:
            c -= 16
            lv = [0, 95, 135, 175, 215, 255]
            return (lv[c // 36], lv[(c // 6) % 6], lv[c % 6])
        g = 8 + (c - 232) * 10
        return (g, g, g)
    for y in range(cv.h):
        for x in range(cv.w):
            bg = rgb(cv.bg[y][x])
            d.rectangle([x * cw, y * chh, x * cw + cw - 1, y * chh + chh - 1], fill=bg)
            ch = cv.ch[y][x]
            if ch != " ":
                d.text((x * cw, y * chh), ch, font=font, fill=rgb(cv.fg[y][x] if cv.fg[y][x] is not None else 252))
    img.save(path)


def run(path, outdir, names):
    os.makedirs(outdir, exist_ok=True)
    for name in names:
        root = tempfile.mkdtemp(prefix=f"office-{name}-")
        later, pm2, h1 = SCENES[name](root)
        m = load(path, root)
        feed = m.Feed()
        app = m.App(feed)
        poll(m, feed, pm2, h1)            # primes every "what changed" source silently
        if later:
            later(root)
            poll(m, feed, pm2, h1)        # the real change: events, bubbles, trips fire now
        cv = None
        for _ in range(60):               # 6 s of office time: walkers set off, bubbles appear
            cv = m.compose(app, W, H)
        with open(os.path.join(outdir, f"{name}.txt"), "w") as fh:
            fh.write("\n".join(cv.lines(color=False)) + "\n")
        render_png(cv, os.path.join(outdir, f"{name}.png"))
        print(f"{name}: wrote {outdir}/{name}.txt/.png")
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    if len(sys.argv) < 3:   # no arguments: the COMPANY fixture scene, this checkout's office, into ./screens/
        here = os.path.dirname(os.path.abspath(__file__))
        run(os.path.join(here, "..", "gnoc-office.py"), os.path.join(here, "screens"), ["company", "floor"])
    else:
        run(sys.argv[1], sys.argv[2], sys.argv[3:] or list(SCENES))
