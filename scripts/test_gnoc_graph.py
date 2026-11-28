#!/usr/bin/env python3
"""Tests for the ARTEX-style dual graph (scripts/gnoc_graph.py + its gnoc chat tools).

    python3 scripts/test_gnoc_graph.py [-v]

The contract: the asset graph deduplicates and associates assets with programs; the exploration
graph links goal/intent/fact/finding nodes, anchors them to assets and computes coverage from
fact/finding anchors; todos are durable and dependency-aware; traces are searchable across workers;
and the gnoc tools expose all of it without touching the real workspace database.
"""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_graph as GRAPH  # noqa: E402
import gnoc_agent as G  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-graph-test-")
        self.db = os.path.join(self.tmp, ".claude/state/graph/gnoc_graph.db")
        self.saved = (GRAPH.DB_PATH, GRAPH.WS, G.WS, list(G._ACTIVE_ROOT))
        GRAPH.DB_PATH = self.db
        GRAPH.WS = self.tmp
        G.WS = self.tmp
        os.makedirs(os.path.join(self.tmp, "targets"))
        G._ACTIVE_ROOT[0] = self.tmp

    def tearDown(self):
        GRAPH.DB_PATH, GRAPH.WS, G.WS = self.saved[0], self.saved[1], self.saved[2]
        G._ACTIVE_ROOT[:] = self.saved[3]
        shutil.rmtree(self.tmp, ignore_errors=True)


class AssetGraph(Base):
    def test_upsert_dedups_and_builds_the_hierarchy(self):
        root = GRAPH.upsert_asset("root_domain", "Acme.TEST", "prog")
        sub = GRAPH.upsert_asset("subdomain", "api.acme.test", "prog")
        again = GRAPH.upsert_asset("subdomain", "API.acme.test", "prog")
        endpoint = GRAPH.upsert_asset("endpoint", "https://api.acme.test/v1/users?id=1", "prog")
        self.assertEqual(root["identifier"], "acme.test")
        self.assertEqual(sub["id"], again["id"])
        self.assertEqual(sub["parent_id"], root["id"])
        self.assertEqual(endpoint["parent_id"], sub["id"])
        self.assertEqual(endpoint["identifier"], "https://api.acme.test/v1/users?id=1")

    def test_assets_are_shared_but_associated_per_program(self):
        a = GRAPH.upsert_asset("root_domain", "acme.test", "alpha")
        b = GRAPH.upsert_asset("root_domain", "acme.test", "beta")
        self.assertEqual(a["id"], b["id"])
        self.assertEqual([x["identifier"] for x in GRAPH.list_assets("alpha")], ["acme.test"])
        self.assertEqual([x["identifier"] for x in GRAPH.list_assets("beta")], ["acme.test"])
        self.assertEqual([x["identifier"] for x in GRAPH.list_assets(None)], ["acme.test"])

    def test_asset_detail_lists_parent_children_and_nodes(self):
        root = GRAPH.upsert_asset("root_domain", "acme.test", "prog")
        child = GRAPH.upsert_asset("subdomain", "api.acme.test", "prog")
        node = GRAPH.add_node("prog", "fact", "API exists", asset_ids=[child["id"]])
        detail = GRAPH.asset_detail(root["id"])
        self.assertEqual(detail["children"][0]["id"], child["id"])
        self.assertEqual(GRAPH.asset_detail(child["id"])["nodes"][0]["id"], node["id"])

    def test_bad_kind_and_identifier_are_refused(self):
        with self.assertRaises(ValueError):
            GRAPH.upsert_asset("nonsense", "acme.test", "prog")
        with self.assertRaises(ValueError):
            GRAPH.upsert_asset("root_domain", "", "prog")
        with self.assertRaises(ValueError):
            GRAPH.upsert_asset("url", "https://acme.test:notaport/x", "prog", db_path=self.db)

    def test_a_url_parent_is_reduced_to_its_host(self):
        child = GRAPH.upsert_asset("subdomain", "api.acme.test", "prog",
                                   parent="https://acme.test/login", db_path=self.db)
        parent = GRAPH.asset_detail(child["id"], db_path=self.db)["parent"]
        self.assertEqual((parent["kind"], parent["identifier"]), ("root_domain", "acme.test"))

    def test_import_scope_reads_in_scope_and_skips_exclusions(self):
        p = os.path.join(self.tmp, "targets", "prog")
        os.makedirs(p)
        with open(os.path.join(p, "SCOPE.txt"), "w") as fh:
            fh.write("# scope\n"
                     "WILDCARD *.acme.test  [bounty]\n"
                     "api.acme.test\n"
                     "https://portal.acme.test/login\n"
                     "# === OUT OF SCOPE ===\n"
                     "admin.acme.test\n")
        got = GRAPH.import_scope("prog")
        self.assertTrue(got["ok"], got)
        names = {a["identifier"] for a in GRAPH.list_assets("prog")}
        self.assertIn("*.acme.test", names)
        self.assertIn("api.acme.test", names)
        self.assertIn("https://portal.acme.test/login", names)
        self.assertNotIn("admin.acme.test", names)
        # idempotent
        GRAPH.import_scope("prog")
        self.assertEqual(len(GRAPH.list_assets("prog")), 3)


class ExplorationGraph(Base):
    def test_nodes_edges_and_anchors(self):
        asset = GRAPH.upsert_asset("subdomain", "api.acme.test", "prog")
        goal = GRAPH.add_node("prog", "goal", "Find a critical")
        intent = GRAPH.add_node("prog", "intent", "Probe the users endpoint",
                                asset_ids=[asset["id"]], parent_ids=[goal["id"]])
        fact = GRAPH.add_node("prog", "fact", "IDOR on /v1/users", body="B read A",
                              asset_ids=[asset["id"]], parent_ids=[intent["id"]])
        self.assertEqual(fact["parents"][0]["rel"], "yields")
        self.assertEqual(fact["anchors"][0]["id"], asset["id"])
        found = GRAPH.node_search("prog", kind="fact")
        self.assertEqual(found[0]["id"], fact["id"])
        self.assertEqual(found[0]["n_assets"], 1)

    def test_fact_without_parent_hangs_off_the_newest_intent(self):
        intent = GRAPH.add_node("prog", "intent", "probe login")
        fact = GRAPH.add_node("prog", "fact", "login leaks a token", asset_ids=[])
        self.assertEqual(fact["parents"][0]["id"], intent["id"])

    def test_update_and_link(self):
        a = GRAPH.add_node("prog", "hint", "try the staging host")
        b = GRAPH.add_node("prog", "intent", "probe staging")
        GRAPH.link_nodes("prog", a["id"], b["id"], "derived_from")
        updated = GRAPH.update_node("prog", b["id"], state="running", body="carrying the hint")
        self.assertEqual(updated["state"], "running")
        self.assertIn("carrying the hint", updated["body"])
        self.assertEqual(updated["parents"][0]["id"], a["id"])

    def test_coverage_counts_facts_not_only_probes(self):
        root = GRAPH.upsert_asset("root_domain", "acme.test", "prog")
        GRAPH.upsert_asset("subdomain", "api.acme.test", "prog")
        endpoint = GRAPH.upsert_asset("endpoint", "https://api.acme.test/v1/users", "prog")
        GRAPH.add_node("prog", "fact", "users endpoint exists", asset_ids=[endpoint["id"]])
        GRAPH.record_probe("prog", "https://api.acme.test/v1/users", "GET", 200, "raw/x", "")
        cov = GRAPH.coverage("prog")
        self.assertEqual(cov["in_scope"], 3)
        self.assertEqual(cov["covered"], 1)
        self.assertEqual(cov["touched"], 2)   # host + endpoint
        self.assertEqual([a["id"] for a in cov["untested_assets"]], [root["id"]])

    def test_bad_node_kind_or_state_is_refused(self):
        with self.assertRaises(ValueError):
            GRAPH.add_node("prog", "nonsense", "x")
        with self.assertRaises(ValueError):
            GRAPH.add_node("prog", "intent", "x", state="confirmed")


class TodosAndTraces(Base):
    def test_todos_respect_dependencies(self):
        one = GRAPH.todo_add("prog", "find an injection")
        two = GRAPH.todo_add("prog", "steal a token", depends_on=[one["id"]])
        self.assertEqual(GRAPH.todo_next("prog")["id"], one["id"])
        GRAPH.todo_update("prog", one["id"], state="completed")
        self.assertEqual(GRAPH.todo_next("prog")["id"], two["id"])
        self.assertEqual(GRAPH.todo_list("prog")[1]["depends_on"], [one["id"]])

    def test_todo_claim_heartbeat_release_complete(self):
        one = GRAPH.todo_add("prog", "find an injection")
        claimed = GRAPH.todo_claim("prog", worker="worker-1")
        self.assertEqual((claimed["state"], claimed["claimed_by"], claimed["attempts"]),
                         ("in_progress", "worker-1", 1))
        self.assertTrue(claimed["lease_live"])
        self.assertIsNone(GRAPH.todo_next("prog"))
        with self.assertRaises(ValueError):
            GRAPH.todo_claim("prog", todo_id=one["id"], worker="worker-2")
        first_until = claimed["lease_until"]
        hb = GRAPH.todo_heartbeat("prog", one["id"], worker="worker-1", lease_secs=3600)
        self.assertGreater(hb["lease_until"], first_until)
        released = GRAPH.todo_release("prog", one["id"], worker="worker-1", state="blocked", error="boom")
        self.assertEqual((released["state"], released["claimed_by"], released["last_error"]),
                         ("blocked", "", "boom"))
        self.assertIsNone(GRAPH.todo_next("prog"))
        with self.assertRaises(ValueError):
            GRAPH.todo_claim("prog", todo_id=one["id"], worker="worker-2")
        GRAPH.todo_update("prog", one["id"], state="pending")
        claimed2 = GRAPH.todo_claim("prog", worker="worker-2")
        self.assertEqual((claimed2["claimed_by"], claimed2["attempts"]), ("worker-2", 2))
        done = GRAPH.todo_update("prog", one["id"], state="completed")
        self.assertEqual((done["state"], done["claimed_by"], bool(done["completed_at"])),
                         ("completed", "", True))

    def test_an_expired_lease_is_reclaimable(self):
        one = GRAPH.todo_add("prog", "expire me")
        GRAPH.todo_claim("prog", worker="worker-1")
        conn = GRAPH.connect(self.db)
        conn.execute("UPDATE todos SET lease_until='2000-01-01T00:00:00+00:00' WHERE id=?", (one["id"],))
        conn.commit()
        conn.close()
        self.assertEqual(GRAPH.todo_next("prog")["id"], one["id"])
        claimed = GRAPH.todo_claim("prog", worker="worker-2")
        self.assertEqual((claimed["claimed_by"], claimed["attempts"]), ("worker-2", 2))

    def test_todo_claim_respects_dependencies(self):
        one = GRAPH.todo_add("prog", "first")
        two = GRAPH.todo_add("prog", "second", depends_on=[one["id"]])
        with self.assertRaises(ValueError):
            GRAPH.todo_claim("prog", todo_id=two["id"], worker="worker-1")
        self.assertEqual(GRAPH.todo_claim("prog", worker="worker-1")["id"], one["id"])

    def test_an_old_todos_table_migrates_the_lease_columns(self):
        import sqlite3
        old = os.path.join(self.tmp, "old-todos.db")
        conn = sqlite3.connect(old)
        conn.execute("CREATE TABLE todos (id INTEGER PRIMARY KEY AUTOINCREMENT, exploration_id INTEGER "
                     "NOT NULL, content TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending', depends_on TEXT "
                     "NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
        conn.commit()
        conn.close()
        conn = GRAPH.connect(old)
        conn.close()
        raw = sqlite3.connect(old)
        cols = {r[1] for r in raw.execute("PRAGMA table_info(todos)").fetchall()}
        raw.close()
        for name in ("claimed_by", "lease_until", "attempts", "last_error", "completed_at"):
            self.assertIn(name, cols)

    def test_trace_add_search_and_get(self):
        row = GRAPH.trace_add("prog", "bash", "curl api.acme.test", "HTTP 200 secret=xyz", worker="worker-1")
        self.assertIn("secret=xyz", GRAPH.trace_search("prog", "secret")[0]["result"])
        self.assertEqual(GRAPH.trace_get("prog", [row["id"]])[0]["args"], "curl api.acme.test")
        self.assertEqual(GRAPH.trace_search("prog", "no-such-byte"), [])

    def test_record_probe_upserts_assets_and_reuses_the_hypothesis_intent(self):
        first = GRAPH.record_probe("prog", "https://api.acme.test/v1/users?id=1", "GET", 200, "raw/1", "H7: idor")
        second = GRAPH.record_probe("prog", "https://api.acme.test/v1/users?id=2", "GET", 403, "raw/2", "H7")
        self.assertEqual(first["hypothesis"], "H7")
        self.assertEqual(first["node_id"], second["node_id"])
        self.assertEqual(first["assets"][0], second["assets"][0])      # one host asset
        self.assertNotEqual(first["assets"][1], second["assets"][1])   # different query = different endpoint
        self.assertEqual(GRAPH.node_search("prog", kind="intent")[0]["attrs"]["hypothesis"], "H7")
        self.assertEqual(len(GRAPH.trace_search("prog", "users")), 2)


class EvidenceAndFindings(Base):
    def _seed(self):
        a = GRAPH.upsert_asset("endpoint", "https://api.acme.test/v1/users?id=1", "prog", db_path=self.db)
        t = GRAPH.trace_add("prog", "http_request", "GET https://api.acme.test/v1/users?id=1",
                            "HTTP 200 len=42 raw=raw/1", asset_ids=[a["id"]], ok=True, db_path=self.db)
        return a, t

    def test_evidence_from_a_trace_dedups_and_links_the_endpoint(self):
        a, t = self._seed()
        ev = GRAPH.evidence_add("prog", trace_id=t["id"], db_path=self.db)
        self.assertEqual((ev["method"], ev["status"], ev["asset_id"]),
                         ("GET", 200, a["id"]))
        self.assertIn("users?id=1", ev["url"])
        again = GRAPH.evidence_add("prog", trace_id=t["id"], db_path=self.db)
        self.assertEqual(again["id"], ev["id"])
        self.assertEqual(again["seen_count"], 2)
        self.assertIn("users?id=1", GRAPH.evidence_text("prog", db_path=self.db))

    def test_evidence_hashes_the_raw_capture(self):
        import hashlib
        import json
        a = GRAPH.upsert_asset("endpoint", "https://api.acme.test/raw", "prog", db_path=self.db)
        raw = os.path.join(self.tmp, "capture.json")
        capture = {"request": {"method": "GET", "url": "https://api.acme.test/raw",
                               "headers": {"x-test": "1"}, "body": None},
                   "response": {"status": 200, "headers": {"content-type": "text/plain"},
                                "body": "secret=abc"}}
        payload = json.dumps(capture).encode()
        with open(raw, "wb") as fh:
            fh.write(payload)
        t = GRAPH.trace_add("prog", "http_request", "",
                            f"HTTP 200 len=10 raw={raw}", asset_ids=[a["id"]], ok=True, db_path=self.db)
        ev = GRAPH.evidence_add("prog", trace_id=t["id"], db_path=self.db)
        self.assertEqual(ev["raw_path"], raw)
        self.assertEqual(ev["raw_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual((ev["method"], ev["url"], ev["status"]),
                         ("GET", "https://api.acme.test/raw", 200))
        self.assertIn("x-test", ev["request"])
        self.assertIn("secret=abc", ev["response"])

    def test_finding_lifecycle_backs_confirmation_with_evidence(self):
        a, t = self._seed()
        ev = GRAPH.evidence_add("prog", trace_id=t["id"], db_path=self.db)
        f = GRAPH.finding_add("prog", "IDOR on users", asset_ids=[a["id"]],
                              evidence_ids=[ev["id"]], db_path=self.db)
        self.assertEqual(f["state"], "candidate")
        with self.assertRaises(ValueError):
            GRAPH.finding_update("prog", f["id"], state="confirmed", db_path=self.db)
        f = GRAPH.finding_update("prog", f["id"], state="triaged", severity="high",
                                 confidence="high", db_path=self.db)
        self.assertEqual((f["state"], f["severity"], f["confidence"]), ("triaged", "high", "high"))
        with self.assertRaises(ValueError):   # no body yet
            GRAPH.finding_update("prog", f["id"], state="confirmed", db_path=self.db)
        f = GRAPH.finding_update("prog", f["id"], state="confirmed", body="Change ?id=1 to ?id=2.",
                                 db_path=self.db)
        self.assertEqual(f["state"], "confirmed")
        with self.assertRaises(ValueError):   # cannot skip confirmed
            GRAPH.finding_add("prog", "skip", asset_ids=[a["id"]], evidence_ids=[ev["id"]],
                              state="reported", severity="high", confidence="high", body="x",
                              db_path=self.db)
        f = GRAPH.finding_update("prog", f["id"], state="reported", db_path=self.db)
        self.assertEqual(f["state"], "reported")
        c = GRAPH.coverage("prog", db_path=self.db)
        self.assertEqual(c["covered"], 1)
        self.assertEqual(c["findings"], {"reported": 1})
        self.assertEqual(c["evidence"], 1)

    def test_confirmed_needs_an_asset_and_evidence(self):
        a = GRAPH.upsert_asset("subdomain", "api.acme.test", "prog", db_path=self.db)
        f = GRAPH.finding_add("prog", "unbacked", asset_ids=[a["id"]], db_path=self.db)
        GRAPH.finding_update("prog", f["id"], state="triaged", severity="high",
                             confidence="high", body="x", db_path=self.db)
        with self.assertRaises(ValueError):   # triaged is allowed, confirmed without evidence is not
            GRAPH.finding_update("prog", f["id"], state="confirmed", db_path=self.db)
        with self.assertRaises(ValueError):
            GRAPH.finding_update("prog", f["id"], state="triaged", severity="high",
                                 confidence="high", body="x",
                                 evidence_ids=[999], db_path=self.db)

    def test_bad_evidence_kind_or_trace_is_refused(self):
        with self.assertRaises(ValueError):
            GRAPH.evidence_add("prog", url="https://api.acme.test/x", kind="nonsense", db_path=self.db)
        with self.assertRaises(ValueError):
            GRAPH.evidence_add("prog", trace_id=999, db_path=self.db)

    def test_cli_lists_evidence_and_findings(self):
        a, t = self._seed()
        ev = GRAPH.evidence_add("prog", trace_id=t["id"], db_path=self.db)
        GRAPH.finding_add("prog", "IDOR on users", asset_ids=[a["id"]],
                          evidence_ids=[ev["id"]], db_path=self.db)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(GRAPH._main(["evidence", "prog"]), 0)
        self.assertIn("EVIDENCE - prog", buf.getvalue())
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(GRAPH._main(["findings", "prog"]), 0)
        self.assertIn("IDOR on users", buf.getvalue())

    def test_an_old_evidence_table_migrates_the_raw_columns(self):
        import sqlite3
        old = os.path.join(self.tmp, "old.db")
        conn = sqlite3.connect(old)
        conn.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY AUTOINCREMENT, exploration_id INTEGER "
                     "NOT NULL, asset_id INTEGER, trace_id INTEGER, kind TEXT NOT NULL DEFAULT 'probe', "
                     "label TEXT NOT NULL DEFAULT '', method TEXT NOT NULL DEFAULT '', url TEXT NOT NULL "
                     "DEFAULT '', status INTEGER, request TEXT NOT NULL DEFAULT '', response TEXT NOT NULL "
                     "DEFAULT '', detail TEXT NOT NULL DEFAULT '', sha256 TEXT NOT NULL, seen_count INTEGER "
                     "NOT NULL DEFAULT 1, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, "
                     "UNIQUE(exploration_id, sha256))")
        conn.commit()
        conn.close()
        conn = GRAPH.connect(old)
        conn.close()
        raw = sqlite3.connect(old)   # reopen without the migration helper: the ALTER must have committed
        cols = {r[1] for r in raw.execute("PRAGMA table_info(evidence)").fetchall()}
        raw.close()
        self.assertIn("raw_path", cols)
        self.assertIn("raw_sha256", cols)


class Approvals(Base):
    def test_approval_queue_dedups_and_is_consumed_once(self):
        args = {"tool": "nuclei", "url": "https://api.acme.test/"}
        one = GRAPH.approval_request("prog", "scan", args, db_path=self.db)
        self.assertEqual(one["state"], "pending")
        again = GRAPH.approval_request("prog", "scan", args, db_path=self.db)
        self.assertEqual(again["id"], one["id"])
        self.assertIsNone(GRAPH.approval_check("prog", "scan", args, db_path=self.db))
        decided = GRAPH.approval_decide(one["id"], approve=True, program="prog", reason="ok", db_path=self.db)
        self.assertEqual(decided["state"], "approved")
        used = GRAPH.approval_check("prog", "scan", args, consume=True, db_path=self.db)
        self.assertEqual(used["id"], one["id"])
        self.assertTrue(used["used_at"])
        self.assertIsNone(GRAPH.approval_check("prog", "scan", args, consume=True, db_path=self.db))

    def test_denied_and_expired_requests_never_run(self):
        denied = GRAPH.approval_request("prog", "scan", {"url": "https://api.acme.test/a"}, db_path=self.db)
        GRAPH.approval_decide(denied["id"], approve=False, program="prog", reason="no", db_path=self.db)
        self.assertIsNone(GRAPH.approval_check("prog", "scan", {"url": "https://api.acme.test/a"},
                                               db_path=self.db))
        again = GRAPH.approval_request("prog", "scan", {"url": "https://api.acme.test/a"}, db_path=self.db)
        self.assertEqual((again["id"], again["state"]), (denied["id"], "denied"))
        expired = GRAPH.approval_request("prog", "scan", {"url": "https://api.acme.test/b"}, db_path=self.db)
        conn = GRAPH.connect(self.db)
        conn.execute("UPDATE approvals SET expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (expired["id"],))
        conn.commit()
        conn.close()
        row = GRAPH.approval_decide(expired["id"], approve=True, program="prog", db_path=self.db)
        self.assertEqual(row["state"], "expired")
        self.assertIsNone(GRAPH.approval_check("prog", "scan", {"url": "https://api.acme.test/b"},
                                               db_path=self.db))

    def test_payload_is_redacted_and_listing_shows_the_queue(self):
        row = GRAPH.approval_request("prog", "bash", {"command": "curl -H 'Authorization: Bearer ghp_abcdefghijklmnop1234'"},
                                     db_path=self.db)
        self.assertNotIn("ghp_abcdefghijklmnop1234", row["payload"])
        text = GRAPH.approvals_text("prog", db_path=self.db)
        self.assertIn(f"#{row['id']}", text)
        self.assertIn("pending", text)


class AgentTools(Base):
    def setUp(self):
        super().setUp()
        p = os.path.join(self.tmp, "targets", "prog")
        os.makedirs(p)
        with open(os.path.join(p, "SCOPE.txt"), "w") as fh:
            fh.write("acme.test\napi.acme.test\n")
        self.ctx = G.Ctx({"program": "prog", "sid": "graph-test"})

    def test_asset_tool_upsert_search_coverage_untested(self):
        G._graph_import_scope("prog")
        out = G.t_asset(self.ctx, action="upsert", kind="subdomain", identifier="deep.acme.test")
        self.assertIn("asset #", out)
        self.assertIn("deep.acme.test", G.t_asset(self.ctx, action="search", query="deep"))
        self.assertIn("in scope 3", G.t_asset(self.ctx, action="coverage"))
        self.assertIn("UNTESTED", G.t_asset(self.ctx, action="untested"))

    def test_set_program_imports_its_scope_into_the_graph(self):
        ctx = G.Ctx({"sid": "graph-test"})
        out = G.t_set_program(ctx, "prog")
        self.assertIn("active program -> prog", out)
        names = {a["identifier"] for a in GRAPH.list_assets("prog")}
        self.assertIn("acme.test", names)
        self.assertIn("api.acme.test", names)

    def test_node_todo_trace_tools(self):
        node = G.t_node(self.ctx, action="add", kind="fact", title="api is up",
                        asset_ids=["1"])
        self.assertIn("NODE #", node)
        self.assertIn("api is up", G.t_node(self.ctx, action="search", query="api"))
        self.assertIn("todo #", G.t_todo(self.ctx, action="add", content="probe login"))
        self.assertIn("PLANNING TODOS", G.t_todo(self.ctx, action="list"))
        self.assertIn("trace #", G.t_trace(self.ctx, action="add", tool="bash", args="echo hi", result="hi"))
        self.assertIn("echo hi", G.t_trace(self.ctx, action="search", query="echo"))
        # the same state layer through the node tool, so the model only needs one schema for it
        self.assertIn("todo #", G.t_node(self.ctx, action="todo_add", content="escalate idor"))
        self.assertIn("PLANNING TODOS", G.t_node(self.ctx, action="todo_list"))
        tid = GRAPH.todo_list("prog")[0]["id"]
        self.assertIn("claimed by w1", G.t_node(self.ctx, action="todo_claim", worker="w1"))
        self.assertIn("lease extended", G.t_node(self.ctx, action="todo_heartbeat", todo_id=tid,
                                                worker="w1", lease_secs=1200))
        self.assertIn("released to pending", G.t_node(self.ctx, action="todo_release", todo_id=tid,
                                                     worker="w1", state="pending"))
        self.assertIn("trace #", G.t_node(self.ctx, action="trace_add", tool="bash", args="id", result="uid=0"))
        self.assertIn("uid=0", G.t_node(self.ctx, action="trace_search", query="uid"))

    def test_node_evidence_and_finding_actions(self):
        out = G.t_asset(self.ctx, action="upsert", kind="endpoint",
                        identifier="https://api.acme.test/v1/users?id=1")
        self.assertIn("asset #", out)
        aid = GRAPH.list_assets("prog")[0]["id"]
        G.t_node(self.ctx, action="trace_add", tool="http_request",
                 args="GET https://api.acme.test/v1/users?id=1", result="HTTP 200 secret=abc")
        tid = GRAPH.trace_search("prog", "users")[0]["id"]
        ev_out = G.t_node(self.ctx, action="evidence_add", trace_id=tid)
        self.assertIn("evidence #", ev_out)
        eid = GRAPH.evidence_search("prog")[0]["id"]
        f_out = G.t_node(self.ctx, action="finding_add", title="IDOR on users",
                         asset_ids=[aid], evidence_ids=[eid])
        self.assertIn("FINDING #", f_out)
        fid = GRAPH.finding_search("prog")[0]["id"]
        self.assertIn("triaged", G.t_node(self.ctx, action="finding_update", finding_id=fid,
                                          state="triaged", severity="high", confidence="high",
                                          body="Change ?id=1 to ?id=2."))
        self.assertIn("confirmed", G.t_node(self.ctx, action="finding_update", finding_id=fid,
                                            state="confirmed"))
        self.assertIn("reported", G.t_node(self.ctx, action="finding_update", finding_id=fid,
                                           state="reported"))
        self.assertIn("IDOR on users", G.t_node(self.ctx, action="finding_list"))
        self.assertIn("FINDING #", G.t_node(self.ctx, action="finding_get", finding_id=fid))
        self.assertIn("users?id=1", G.t_node(self.ctx, action="evidence_get", evidence_ids=[eid]))

    def test_non_interactive_approval_is_queued_and_listed(self):
        ctx = G.Ctx({"program": "prog", "sid": "approval-test"})
        out = G.run_tools([{"function": {"name": "gnoc", "arguments": {"args": "resume"}}}], ctx, False)
        body = out[0]["content"]
        self.assertIn("Queued as approval #", body)
        rows = GRAPH.approval_list("prog")
        self.assertTrue(rows)
        listed = G.t_node(ctx, action="approval_list")
        self.assertIn(f"#{rows[0]['id']}", listed)
        self.assertIn("pending", listed)
        agent = type("A", (), {"ctx": ctx, "s": ctx.s, "save": lambda self: None})()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            G.handle_slash(agent, "/approvals", {})
        self.assertIn(f"#{rows[0]['id']}", buf.getvalue())
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            G.handle_slash(agent, f"/approve {rows[0]['id']}", {})
        self.assertIn("approved", buf.getvalue())
        self.assertEqual(GRAPH.approval_get(rows[0]["id"], program="prog")["state"], "approved")

    def test_graph_overview_and_prompt_block(self):
        G._graph_import_scope("prog")
        out = G.t_graph_overview(self.ctx)
        self.assertIn("DUAL GRAPH - prog", out)
        block = G._graph_block(self.ctx)
        self.assertIn("THE DUAL GRAPH IS YOUR SHARED STATE", block)
        self.assertIn("ASSET GRAPH", block)
        self.assertIn("asset action=untested", block)

    def test_graph_tools_are_in_the_hunt_and_worker_sets(self):
        for name in ("graph_overview", "asset", "node"):
            self.assertIn(name, G.HUNT_TOOLS)
            self.assertIn(name, G.TOOLS)
            self.assertIn(name, G.WORKER_TOOLS)
        # todo_* and trace_* are node actions, not separate schemas: the state layer costs three tools.
        self.assertNotIn("todo", G.TOOLS)
        self.assertNotIn("trace", G.TOOLS)

    def test_slash_graph_prints_the_overview(self):
        G._graph_import_scope("prog")
        agent = type("A", (), {"ctx": self.ctx, "s": self.ctx.s, "save": lambda self: None})()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            G.handle_slash(agent, "/graph", {})
        self.assertIn("DUAL GRAPH - prog", buf.getvalue())
        for view, expected in (("findings", "no findings in prog"), ("evidence", "no evidence in prog")):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                G.handle_slash(agent, f"/graph {view}", {})
            self.assertIn(expected, buf.getvalue())


class SnapshotsAndDiff(Base):
    """Attack-surface history: a snapshot freezes the in-scope set, a diff shows it moving."""

    def setUp(self):
        super().setUp()
        self.root = GRAPH.upsert_asset("root_domain", "acme.test", "prog")
        self.api = GRAPH.upsert_asset("subdomain", "api.acme.test", "prog")
        GRAPH.add_node("prog", "fact", "api is up", asset_ids=[self.api["id"]])

    def test_snapshot_freezes_the_in_scope_set(self):
        snap = GRAPH.take_snapshot("prog", "day1")
        self.assertEqual(snap["assets"], 2)
        self.assertEqual(len(snap["payload"]["assets"]), 2)
        self.assertEqual(len(snap["sha256"]), 64)
        self.assertIn("#1", GRAPH.snapshots_text("prog"))

    def test_diff_reports_added_removed_and_coverage_change(self):
        GRAPH.take_snapshot("prog", "day1")
        new = GRAPH.upsert_asset("endpoint", "https://api.acme.test/v1/users", "prog")
        d = GRAPH.asset_diff("prog")
        self.assertEqual([a["identifier"] for a in d["added"]], ["https://api.acme.test/v1/users"])
        GRAPH.add_node("prog", "fact", "root now covered", asset_ids=[self.root["id"]])
        d2 = GRAPH.asset_diff("prog")
        self.assertIn("acme.test", [a["identifier"] for a in d2["changed"]])
        GRAPH.take_snapshot("prog", "day2")   # the endpoint is in scope now; remove it and diff again
        with contextlib.closing(GRAPH.connect()) as conn:
            with conn:
                conn.execute("DELETE FROM asset_programs WHERE program='prog' AND asset_id=?",
                             (new["id"],))
        d3 = GRAPH.asset_diff("prog")
        self.assertEqual(d3["base"]["label"], "day2")
        self.assertIn("https://api.acme.test/v1/users", [a["identifier"] for a in d3["removed"]])
        text = GRAPH.diff_text("prog")
        self.assertIn("ATTACK-SURFACE DIFF - prog", text)
        self.assertIn("- endpoint https://api.acme.test/v1/users", text)

    def test_diff_without_a_snapshot_is_a_clear_error(self):
        with self.assertRaises(ValueError):
            GRAPH.asset_diff("prog")

    def test_snapshot_by_label_or_timestamp(self):
        first = GRAPH.take_snapshot("prog", "before")
        again = GRAPH.asset_diff("prog", since="before")
        self.assertEqual(again["base"]["id"], first["id"])
        by_ts = GRAPH.asset_diff("prog", since=first["taken_at"][:16])
        self.assertEqual(by_ts["base"]["id"], first["id"])


class GraphPaths(Base):
    """path = the shortest chain between two nodes; lineage = everything that led to one."""

    def setUp(self):
        super().setUp()
        self.asset = GRAPH.upsert_asset("endpoint", "https://acme.test/v1/orders", "prog")
        self.goal = GRAPH.add_node("prog", "goal", "prove the order read")
        self.intent = GRAPH.add_node("prog", "intent", "try the orders endpoint",
                                     asset_ids=[self.asset["id"]],
                                     parent_ids=[self.goal["id"]])
        self.fact = GRAPH.add_node("prog", "fact", "orders are not tenant-checked",
                                   asset_ids=[self.asset["id"]],
                                   parent_ids=[self.intent["id"]])
        self.finding = GRAPH.add_node("prog", "finding", "cross-tenant order read",
                                      asset_ids=[self.asset["id"]],
                                      parent_ids=[self.fact["id"]])
        GRAPH.link_nodes("prog", self.goal["id"], self.intent["id"], "spawns")
        GRAPH.link_nodes("prog", self.intent["id"], self.fact["id"], "yields")
        GRAPH.link_nodes("prog", self.fact["id"], self.finding["id"], "proves")

    def test_path_walks_the_chain_in_both_directions(self):
        r = GRAPH.node_path("prog", self.goal["id"], self.finding["id"])
        self.assertTrue(r["found"])
        self.assertEqual([n["id"] for n in r["path"]],
                         [self.goal["id"], self.intent["id"], self.fact["id"], self.finding["id"]])
        self.assertEqual(r["depth"], 3)
        back = GRAPH.node_path("prog", self.finding["id"], self.goal["id"])
        self.assertTrue(back["found"])
        self.assertEqual([n["id"] for n in back["path"]][0], self.finding["id"])
        text = GRAPH.path_text("prog", self.goal["id"], self.finding["id"])
        self.assertIn("PATH - prog", text)
        self.assertIn("-yields->", text)
        self.assertIn("<-spawns-", text.replace("-spawns->", "<-spawns-"))  # reverse arrow is used

    def test_no_path_is_reported_without_a_crash(self):
        lonely = GRAPH.add_node("prog", "goal", "an unrelated goal")
        r = GRAPH.node_path("prog", self.goal["id"], lonely["id"])
        self.assertFalse(r["found"])
        self.assertIn("no path", GRAPH.path_text("prog", self.goal["id"], lonely["id"]))

    def test_lineage_lists_ancestors_and_their_assets(self):
        lin = GRAPH.node_lineage("prog", self.finding["id"])
        ids = {a["id"] for a in lin["ancestors"]}
        self.assertEqual(ids, {self.goal["id"], self.intent["id"], self.fact["id"]})
        by_id = {a["id"]: a for a in lin["ancestors"]}
        self.assertEqual(by_id[self.intent["id"]]["depth"], 2)
        self.assertIn("https://acme.test/v1/orders", by_id[self.intent["id"]]["assets"])
        text = GRAPH.lineage_text("prog", self.finding["id"])
        self.assertIn("LINEAGE - prog", text)
        self.assertIn("<-proves-", text)

    def test_unknown_node_is_refused(self):
        with self.assertRaises(ValueError):
            GRAPH.node_path("prog", self.goal["id"], 99999)


class TrafficStore(Base):
    """Every exchange record_probe makes lands in the traffic store with its bytes."""

    def setUp(self):
        super().setUp()
        self.raw_rel = "targets/prog/raw/traffic-1.json"
        raw_abs = os.path.join(self.tmp, self.raw_rel)
        os.makedirs(os.path.dirname(raw_abs), exist_ok=True)
        self.capture = {
            "request": {"method": "GET", "url": "https://api.acme.test/v1/orders/2",
                        "headers": {"Authorization": "Bearer tenant-a"}, "body": None},
            "response": {"status": 200, "headers": {"content-type": "application/json"},
                         "body": '{"order_id": 2, "tenant": "b"}'}}
        with open(raw_abs, "w", encoding="utf-8") as fh:
            json.dump(self.capture, fh)
        os.makedirs(os.path.join(self.tmp, "targets", "prog"), exist_ok=True)
        self.probe = GRAPH.record_probe("prog", "https://api.acme.test/v1/orders/2", "GET", 200,
                                        raw=self.raw_rel, hypothesis="H1 order read")

    def test_a_probe_is_recorded_with_its_bytes(self):
        rows = GRAPH.traffic_search("prog")
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["method"], "GET")
        self.assertEqual(row["host"], "api.acme.test")
        self.assertEqual(row["status"], 200)
        self.assertIn("Authorization: Bearer tenant-a", row["request_headers"])
        self.assertIn('"tenant": "b"', row["response_body"])
        self.assertEqual(row["trace_id"], self.probe["trace_id"])
        self.assertEqual(row["seen_count"], 1)

    def test_the_same_exchange_dedups_and_counts_hits(self):
        again = GRAPH.record_probe("prog", "https://api.acme.test/v1/orders/2", "GET", 200,
                                   raw=self.raw_rel, hypothesis="H1 order read")
        self.assertEqual(again["traffic_id"], self.probe["traffic_id"])
        rows = GRAPH.traffic_search("prog")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["seen_count"], 2)

    def test_search_filters_and_host_summary(self):
        GRAPH.traffic_add("prog", "POST", "https://admin.acme.test/login", status=403,
                          response_body="forbidden")
        self.assertEqual(len(GRAPH.traffic_search("prog", method="POST")), 1)
        self.assertEqual(len(GRAPH.traffic_search("prog", host="admin")), 1)
        self.assertEqual(len(GRAPH.traffic_search("prog", status=403)), 1)
        self.assertEqual(len(GRAPH.traffic_search("prog", query="forbidden")), 1)
        hosts = {h["host"]: h for h in GRAPH.traffic_hosts("prog")}
        self.assertEqual(set(hosts), {"api.acme.test", "admin.acme.test"})
        self.assertIn("TRAFFIC HOSTS - prog", GRAPH.traffic_hosts_text("prog"))

    def test_detail_shows_the_request_and_response(self):
        text = GRAPH.traffic_detail_text("prog", self.probe["traffic_id"])
        self.assertIn("GET https://api.acme.test/v1/orders/2", text)
        self.assertIn("REQUEST", text)
        self.assertIn("Bearer tenant-a", text)
        self.assertIn("RESPONSE 200", text)
        self.assertIn('"order_id": 2', text)

    def test_purge_clears_by_host_or_all(self):
        GRAPH.traffic_add("prog", "POST", "https://admin.acme.test/login", status=403)
        self.assertEqual(GRAPH.traffic_purge("prog", host="admin"), 1)
        self.assertEqual(len(GRAPH.traffic_search("prog")), 1)
        self.assertEqual(GRAPH.traffic_purge("prog"), 1)
        self.assertEqual(GRAPH.traffic_search("prog"), [])

    def test_a_missing_capture_still_records_the_exchange(self):
        GRAPH.record_probe("prog", "https://api.acme.test/v1/other", "POST", 500,
                           raw="targets/prog/raw/does-not-exist.json")
        rows = [r for r in GRAPH.traffic_search("prog") if "v1/other" in r["url"]]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], 500)
        self.assertEqual(rows[0]["request_body"], "")


class Retests(Base):
    """A confirmed finding can be scheduled for a re-test and closed with an outcome."""

    def setUp(self):
        super().setUp()
        self.asset = GRAPH.upsert_asset("endpoint", "https://api.acme.test/v1/orders", "prog")
        self.ev = GRAPH.evidence_add("prog", kind="probe", label="probe", method="GET",
                                     url="https://api.acme.test/v1/orders", status=200,
                                     response="ok")
        f = GRAPH.finding_add("prog", "IDOR order read", body="Summary: x\n\nImpact: y",
                              severity="high", confidence="high",
                              asset_ids=[self.asset["id"]], evidence_ids=[self.ev["id"]],
                              state="triaged")
        self.finding = GRAPH.finding_update("prog", f["id"], state="confirmed")

    def test_a_confirmed_finding_can_be_scheduled_and_listed(self):
        r = GRAPH.retest_add("prog", self.finding["id"], due_in_days=7, note="after the fix window")
        self.assertEqual(r["state"], "pending")
        self.assertGreaterEqual(r["due_at"], r["created_at"])
        self.assertIn("#1", GRAPH.retests_text("prog"))

    def test_an_outcome_closes_the_active_list(self):
        r = GRAPH.retest_add("prog", self.finding["id"])
        self.assertIn("pending", GRAPH.retests_text("prog"))
        GRAPH.retest_update("prog", r["id"], "fixed", note="no longer reproduces")
        self.assertEqual(GRAPH.retests("prog", active_only=True), [])
        allrows = GRAPH.retests("prog")
        self.assertEqual(allrows[0]["state"], "fixed")
        self.assertEqual(allrows[0]["outcome"], "no longer reproduces")

    def test_a_candidate_is_refused(self):
        cand = GRAPH.finding_add("prog", "not proven", body="x")
        with self.assertRaises(ValueError):
            GRAPH.retest_add("prog", cand["id"])

    def test_an_overdue_retest_is_flagged(self):
        GRAPH.retest_add("prog", self.finding["id"], due_in_days=0)
        self.assertIn("OVERDUE", GRAPH.retests_text("prog"))

    def test_the_finding_carries_its_pending_retest(self):
        GRAPH.retest_add("prog", self.finding["id"])
        row = GRAPH.finding_get("prog", self.finding["id"])
        self.assertEqual(row["retest_count"], 1)
        self.assertEqual(len(row["retests"]), 1)
        self.assertIn("retest=1", GRAPH.findings_text("prog"))


class ApprovalRules(Base):
    """An operator rule stands in for the prompt once, for one exact action+args, and never for the
    always-ask tools."""

    def setUp(self):
        super().setUp()
        self.ctx = G.Ctx({"program": "prog", "sid": "rules-test"})
        self.args = {"path": "reports/x.md", "content": "hi"}
        self.pattern = '{"content": "hi", "path": "reports/x.md"}'

    def test_one_rule_authorises_exactly_one_matching_call(self):
        self.assertTrue(G._approval_required("write_file", dict(self.args), self.ctx))
        rule = GRAPH.rule_add("prog", "write_file", self.pattern)
        self.assertEqual(rule["uses_left"], 1)
        self.assertFalse(G._approval_required("write_file", dict(self.args), self.ctx))
        self.assertTrue(G._approval_required("write_file", dict(self.args), self.ctx))   # spent

    def test_a_different_call_does_not_match(self):
        GRAPH.rule_add("prog", "write_file", self.pattern)
        other = {"path": "reports/y.md", "content": "hi"}
        self.assertTrue(G._approval_required("write_file", other, self.ctx))
        self.assertEqual(GRAPH.rule_list("prog")[0]["uses_left"], 1)

    def test_the_use_budget_is_honoured(self):
        GRAPH.rule_add("prog", "write_file", self.pattern, uses=2)
        self.assertFalse(G._approval_required("write_file", dict(self.args), self.ctx))
        self.assertFalse(G._approval_required("write_file", dict(self.args), self.ctx))
        self.assertTrue(G._approval_required("write_file", dict(self.args), self.ctx))

    def test_a_rule_can_never_bypass_an_always_ask_tool(self):
        GRAPH.rule_add("prog", "scan", '{"target": "api.acme.test"}')
        self.assertTrue(G._approval_required("scan", {"target": "api.acme.test"}, self.ctx))
        self.assertEqual(GRAPH.rule_list("prog")[0]["uses_left"], 1)   # untouched

    def test_an_expired_rule_does_not_match(self):
        rule = GRAPH.rule_add("prog", "write_file", self.pattern)
        with contextlib.closing(GRAPH.connect()) as conn:
            with conn:
                conn.execute("UPDATE approval_rules SET expires_at='2000-01-01T00:00:00+00:00' WHERE id=?",
                             (rule["id"],))
        self.assertTrue(G._approval_required("write_file", dict(self.args), self.ctx))
        self.assertEqual(GRAPH.rule_list("prog"), [])

    def test_rule_listing_shows_and_remove_clears(self):
        rule = GRAPH.rule_add("prog", "write_file", self.pattern, note="bulk import")
        text = GRAPH.rules_text("prog")
        self.assertIn("APPROVAL RULES - prog", text)
        self.assertIn("bulk import", text)
        self.assertTrue(GRAPH.rule_remove("prog", rule["id"]))
        self.assertIn("no approval rules", GRAPH.rules_text("prog"))


class StatsAndFilters(Base):
    """The dashboard numbers and the asset filters."""

    def setUp(self):
        super().setUp()
        self.api = GRAPH.upsert_asset("endpoint", "https://api.acme.test/v1/orders", "prog")
        self.root = GRAPH.upsert_asset("root_domain", "acme.test", "prog")
        GRAPH.add_node("prog", "fact", "orders reachable", asset_ids=[self.api["id"]])
        GRAPH.traffic_add("prog", "GET", "https://api.acme.test/v1/orders", status=200)
        GRAPH.todo_add("prog", "write the report")

    def test_stats_counts_the_whole_program(self):
        st = GRAPH.program_stats("prog")
        self.assertEqual(st["assets"], 2)
        self.assertEqual(st["coverage"]["covered"], 1)
        self.assertEqual(st["coverage"]["untested"], 1)
        self.assertEqual(st["traffic"], 1)
        self.assertEqual(st["traffic_hosts"], 1)
        self.assertEqual(st["todos"].get("pending"), 1)
        text = GRAPH.stats_text("prog")
        self.assertIn("PROGRAM STATS - prog", text)
        self.assertIn("traffic 1 across 1 host", text)

    def test_asset_filters_by_kind_and_coverage(self):
        endpoints = GRAPH.assets_filter_text("prog", kind="endpoint")
        self.assertIn("https://api.acme.test/v1/orders", endpoints)
        self.assertNotIn(" acme.test", endpoints)
        covered = GRAPH.assets_filter_text("prog", coverage_state="covered")
        self.assertIn("https://api.acme.test/v1/orders", covered)
        self.assertNotIn("root_domain", covered)
        untested = GRAPH.assets_filter_text("prog", coverage_state="untested")
        self.assertIn("acme.test", untested)
        self.assertNotIn("endpoint", untested)
        self.assertIn("no assets match", GRAPH.assets_filter_text("prog", query="nothing-matches"))


class CockpitExport(Base):
    """The visual cockpit: one self-contained HTML page, no network, no way for a target-controlled
    title to break out of the embedded JSON."""

    def _seed(self):
        GRAPH.upsert_asset("root_domain", "acme.test", "prog")
        api = GRAPH.upsert_asset("endpoint", "https://api.acme.test/v1/orders", "prog")
        goal = GRAPH.add_node("prog", "goal", "Prove cross-tenant read")
        intent = GRAPH.add_node("prog", "intent", "Test the orders endpoint", asset_ids=[api["id"]])
        fact = GRAPH.add_node("prog", "fact", "Order ids are not tenant-checked",
                              asset_ids=[api["id"]])
        GRAPH.link_nodes("prog", goal["id"], intent["id"], "spawns")
        GRAPH.link_nodes("prog", intent["id"], fact["id"], "yields")
        tr = GRAPH.trace_add("prog", "http_request", "GET /v1/orders/2", "200 OK",
                             asset_ids=[api["id"]])
        ev = GRAPH.evidence_add("prog", trace_id=tr["id"], kind="probe", label="cross-tenant read")
        f = GRAPH.finding_add("prog", "Cross-tenant order read", body="repro",
                              severity="high", confidence="high",
                              asset_ids=[api["id"]], evidence_ids=[ev["id"]])
        GRAPH.finding_update("prog", f["id"], state="confirmed")
        GRAPH.todo_add("prog", "write the report")
        GRAPH.approval_request("prog", "bash", {"command": "nmap api.acme.test"})
        return api

    def _data_block(self, path):
        import json
        import re
        with open(path, encoding="utf-8") as fh:
            page = fh.read()
        m = re.search(r'<script id="graph-data" type="application/json">(.*?)</script>', page, re.S)
        self.assertIsNotNone(m, "the cockpit has no embedded data block")
        return page, json.loads(m.group(1))

    def test_export_data_carries_graph_coverage_and_ledger(self):
        self._seed()
        data = GRAPH.graph_export_data("prog")
        self.assertEqual(data["program"], "prog")
        self.assertEqual(data["counts"]["nodes"], 3)
        self.assertEqual(data["counts"]["edges"], 2)
        self.assertEqual(data["coverage"]["in_scope"], 2)   # the root domain + the endpoint
        self.assertEqual(data["coverage"]["covered"], 1)
        self.assertEqual(data["coverage"]["untested"], 1)
        self.assertTrue(any(n["anchors"] for n in data["nodes"]))
        self.assertEqual(data["findings"][0]["state"], "confirmed")
        self.assertEqual(data["todos"][0]["content"], "write the report")
        self.assertEqual(data["approvals"][0]["state"], "pending")
        self.assertEqual(data["traces"][0]["tool"], "http_request")

    def test_export_html_is_self_contained_and_parses(self):
        self._seed()
        got = GRAPH.export_html("prog")
        self.assertTrue(os.path.isfile(got["path"]))
        self.assertGreater(got["bytes"], 5000)
        page, parsed = self._data_block(got["path"])
        self.assertIn("<!DOCTYPE html>", page)
        self.assertIn('id="graph-data"', page)
        self.assertEqual(parsed["program"], "prog")
        self.assertEqual(parsed["counts"]["nodes"], 3)
        # no external fetch of any kind: the page must work from file:// with the network off
        for bad in ("<script src", "<link ", "@import", "url(http", "url(//", 'src="http'):
            self.assertNotIn(bad, page)
        self.assertIn("Cross-tenant order read", page)

    def test_a_target_controlled_title_cannot_break_the_data_block(self):
        self._seed()
        GRAPH.add_node("prog", "fact", "escapes",
                       body='x</script><img src=x onerror=alert(1)><!-- y')
        got = GRAPH.export_html("prog")
        page, parsed = self._data_block(got["path"])
        self.assertNotIn("</script><img", page)
        self.assertIn("<\\/script>", page)
        self.assertTrue(any("<img src=x" in n["body"] for n in parsed["nodes"]))
        self.assertNotIn("<!--", page)

    def test_empty_program_still_exports_a_page(self):
        got = GRAPH.export_html("nothing-here")
        page, parsed = self._data_block(got["path"])
        self.assertEqual(parsed["counts"]["nodes"], 0)
        self.assertEqual(parsed["coverage"]["in_scope"], 0)
        self.assertIn("no exploration nodes yet", page)

    def test_cli_export_writes_the_page_and_reports_it(self):
        self._seed()
        out = os.path.join(self.tmp, "cli-cockpit.html")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = GRAPH._main(["export", "prog", "--out", out])
        self.assertEqual(rc, 0)
        self.assertIn("cockpit written", buf.getvalue())
        self.assertTrue(os.path.isfile(out))
        page, parsed = self._data_block(out)
        self.assertEqual(parsed["counts"]["nodes"], 3)

    def test_slash_graph_export_writes_the_page(self):
        self._seed()
        ctx = G.Ctx({"program": "prog", "sid": "graph-test"})
        agent = type("A", (), {"ctx": ctx, "s": ctx.s, "save": lambda self: None})()
        out = os.path.join(self.tmp, "slash-cockpit.html")
        saved = (os.environ.pop("DISPLAY", None), os.environ.pop("WAYLAND_DISPLAY", None))
        try:  # a headless test must never spawn a browser
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                G.handle_slash(agent, f"/graph export {out}", {})
        finally:
            for key, val in zip(("DISPLAY", "WAYLAND_DISPLAY"), saved):
                if val is not None:
                    os.environ[key] = val
        self.assertIn("cockpit:", buf.getvalue())
        self.assertTrue(os.path.isfile(out))
        page, parsed = self._data_block(out)
        self.assertEqual(parsed["program"], "prog")

    def test_out_may_be_a_directory(self):
        self._seed()
        got = GRAPH.export_html("prog", out_path=self.tmp)
        self.assertEqual(os.path.dirname(got["path"]), os.path.abspath(self.tmp))
        self.assertEqual(os.path.basename(got["path"]), "cockpit-prog.html")
        self.assertTrue(os.path.isfile(got["path"]))


class FindingArtifacts(Base):
    """finding -> REPORT-FORMAT draft: the PoC quotes the captured bytes, the prose comes from
    labelled body lines, the draft is versioned and nothing is ever filed."""

    def setUp(self):
        super().setUp()
        os.makedirs(os.path.join(self.tmp, "targets", "prog"), exist_ok=True)
        self.asset = GRAPH.upsert_asset("endpoint", "https://api.acme.test/v1/orders/2", "prog")
        self.raw_rel = "targets/prog/raw/order-2.json"
        raw_abs = os.path.join(self.tmp, self.raw_rel)
        os.makedirs(os.path.dirname(raw_abs), exist_ok=True)
        self.capture = {
            "request": {"method": "GET", "url": "https://api.acme.test/v1/orders/2",
                        "headers": {"Authorization": "Bearer tenant-a"}, "body": None},
            "response": {"status": 200, "headers": {"content-type": "application/json"},
                         "body": '{"order_id": 2, "tenant": "b"}'}}
        with open(raw_abs, "w", encoding="utf-8") as fh:
            json.dump(self.capture, fh)
        tr = GRAPH.trace_add("prog", "http_request", "GET https://api.acme.test/v1/orders/2",
                             f"200 OK 42 bytes raw={self.raw_rel}", asset_ids=[self.asset["id"]])
        self.ev = GRAPH.evidence_add("prog", trace_id=tr["id"], kind="probe", label="tenant B order")
        self.body = ("Summary: Any tenant token reads another tenant's order by id.\n\n"
                     "Impact: A tenant reads every other tenant's order data.\n\n"
                     "CVSS: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 Medium\n\n"
                     "CWE: CWE-639 Authorization Bypass Through User-Controlled Key\n\n"
                     "Reproduction: send the request with tenant A's token.")
        f = GRAPH.finding_add("prog", "# IDOR: cross-tenant order read", body=self.body,
                              severity="high", confidence="high", asset_ids=[self.asset["id"]],
                              evidence_ids=[self.ev["id"]])
        GRAPH.finding_update("prog", f["id"], state="triaged")
        self.finding = GRAPH.finding_update("prog", f["id"], state="confirmed")

    def _report(self, got):
        with open(got["report_path"], encoding="utf-8") as fh:
            return fh.read()

    def test_draft_follows_report_format_and_quotes_the_capture(self):
        got = GRAPH.finding_artifact("prog", self.finding["id"])
        report = self._report(got)
        lines = report.splitlines()
        self.assertTrue(lines[0].startswith("CVSS: CVSS:3.1/AV:N/"), lines[0])
        self.assertEqual(lines[1], "Asset: https://api.acme.test/v1/orders/2")
        self.assertTrue(lines[2].startswith("CWE: CWE-639"), lines[2])
        self.assertIn("# IDOR: cross-tenant order read", lines)   # the body title's markdown is stripped
        self.assertEqual([ln for ln in lines if ln.startswith("## ")], ["## Summary", "## PoC", "## Impact"])
        self.assertIn("```bash", report)
        self.assertIn("```http", report)
        self.assertIn("Authorization: Bearer tenant-a", report)
        self.assertIn("HTTP 200", report)
        self.assertIn('"tenant": "b"', report)          # the captured response body, byte for byte
        self.assertIn("Any tenant token reads another tenant's order by id.", report)
        report.encode("ascii")                            # REPORT-FORMAT: ASCII only
        self.assertNotIn("\u2014", report)

    def test_draft_records_the_artifact_and_files_nothing(self):
        got = GRAPH.finding_artifact("prog", self.finding["id"])
        self.assertEqual(got["version"], 1)
        self.assertFalse(got["reused"])
        with open(got["gates_path"], encoding="utf-8") as fh:
            gates = fh.read()
        self.assertIn("DRAFT - NOT FILED", gates)
        self.assertIn(got["sha256"], gates)
        copied = os.path.join(os.path.dirname(got["report_path"]), "evidence", "evidence-1.json")
        self.assertTrue(os.path.isfile(copied))
        with open(copied, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), self.capture)
        row = GRAPH.finding_get("prog", self.finding["id"])
        self.assertEqual(row["state"], "confirmed")        # a draft is not a filing
        self.assertEqual(row["artifact_count"], 1)
        self.assertTrue(row["artifacts"][0]["path"].startswith("reports/drafts/prog/"),
                        row["artifacts"][0]["path"])
        self.assertIn("draft=1", GRAPH.findings_text("prog"))

    def test_candidate_finding_is_refused(self):
        cand = GRAPH.finding_add("prog", "not proven yet", body="x")
        with self.assertRaises(ValueError):
            GRAPH.finding_artifact("prog", cand["id"])

    def test_an_unchanged_draft_is_reused_not_rewritten(self):
        first = GRAPH.finding_artifact("prog", self.finding["id"])
        second = GRAPH.finding_artifact("prog", self.finding["id"])
        self.assertTrue(second["reused"])
        self.assertEqual(second["path"], first["path"])
        self.assertEqual(GRAPH.finding_get("prog", self.finding["id"])["artifact_count"], 1)

    def test_an_edited_draft_is_never_overwritten(self):
        first = GRAPH.finding_artifact("prog", self.finding["id"])
        with open(first["report_path"], "a", encoding="utf-8") as fh:
            fh.write("\nHUMAN EDIT\n")
        GRAPH.finding_update("prog", self.finding["id"], body=self.body.replace("Any tenant token", "Every tenant token"))
        second = GRAPH.finding_artifact("prog", self.finding["id"])
        self.assertEqual(second["version"], 2)
        self.assertNotEqual(second["path"], first["path"])
        with open(first["report_path"], encoding="utf-8") as fh:
            self.assertIn("HUMAN EDIT", fh.read())
        self.assertNotIn("HUMAN EDIT", self._report(second))
        self.assertIn("draft=2", GRAPH.findings_text("prog"))

    def test_a_capture_that_changed_on_disk_is_not_copied(self):
        GRAPH.finding_artifact("prog", self.finding["id"])
        raw_abs = os.path.join(self.tmp, self.raw_rel)
        with open(raw_abs, "w", encoding="utf-8") as fh:
            fh.write('{"request": {}, "response": {}}')
        GRAPH.finding_update("prog", self.finding["id"], body=self.body.replace("Any tenant token", "Every tenant token"))
        second = GRAPH.finding_artifact("prog", self.finding["id"])
        self.assertTrue(any("changed on disk" in w for w in second["warnings"]), second["warnings"])
        self.assertFalse(os.path.isdir(os.path.join(second["path"], "evidence")))

    def test_a_reused_draft_gains_a_capture_that_appeared_later(self):
        raw_abs = os.path.join(self.tmp, self.raw_rel)
        with open(raw_abs, "rb") as fh:
            saved = fh.read()
        os.remove(raw_abs)
        first = GRAPH.finding_artifact("prog", self.finding["id"])
        self.assertTrue(any("gone" in w for w in first["warnings"]), first["warnings"])
        self.assertFalse(os.path.isdir(os.path.join(first["path"], "evidence")))
        with open(raw_abs, "wb") as fh:
            fh.write(saved)
        second = GRAPH.finding_artifact("prog", self.finding["id"])
        self.assertTrue(second["reused"])
        self.assertTrue(os.path.isfile(os.path.join(second["path"], "evidence", "evidence-1.json")))
        self.assertTrue(any("copied missing capture" in w for w in second["warnings"]), second["warnings"])

    def test_operator_can_override_cvss_and_cwe(self):
        got = GRAPH.finding_artifact(
            "prog", self.finding["id"],
            cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical",
            cwe="CWE-284 Improper Access Control")
        lines = self._report(got).splitlines()
        self.assertEqual(lines[0], "CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical")
        self.assertEqual(lines[2], "CWE: CWE-284 Improper Access Control")

    def test_cli_draft_action(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = GRAPH._main(["draft", "prog", str(self.finding["id"])])
        self.assertEqual(rc, 0)
        self.assertIn("NOT FILED", out.getvalue())
        self.assertIn("report.md", out.getvalue())
        self.assertIn("house validator:", out.getvalue())

    def test_slash_graph_draft(self):
        ctx = G.Ctx({"program": "prog", "sid": "draft-test"})
        agent = type("A", (), {"ctx": ctx, "s": ctx.s, "save": lambda self: None})()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            G.handle_slash(agent, f"/graph draft {self.finding['id']}", {})
        self.assertIn("draft:", out.getvalue())
        self.assertIn("NOT FILED", out.getvalue())

    def test_draft_is_a_first_class_house_draft(self):
        import gnoc_finding
        got = GRAPH.finding_artifact("prog", self.finding["id"])
        record_path = os.path.join(got["path"], "finding.json")
        self.assertTrue(os.path.isfile(record_path), "no finding.json: gnoc_finding cannot validate it")
        with open(record_path, encoding="utf-8") as fh:
            record = json.load(fh)
        self.assertEqual(record["schema"], 1)
        self.assertEqual(record["program"], "prog")
        self.assertEqual(record["status"], "draft")
        self.assertIn("cross-tenant order read", record["title"])
        self.assertEqual(record["cwe"], "CWE-639")
        self.assertEqual(record["cvss"]["score"], 6.5)
        self.assertTrue(got["house"]["checked"])
        self.assertEqual(got["house_errors"], gnoc_finding.validate(got["path"]))
        with open(got["gates_path"], encoding="utf-8") as fh:
            self.assertIn("## House checks (gnoc_finding)", fh.read())

    def test_house_validator_flags_a_bugcrowd_draft_without_a_vrt(self):
        import gnoc_finding
        saved = gnoc_finding._venue
        gnoc_finding._venue = lambda program: "bugcrowd"
        try:
            got = GRAPH.finding_artifact("prog", self.finding["id"])
        finally:
            gnoc_finding._venue = saved
        self.assertTrue(any("VRT" in e for e in got["house_errors"]), got["house_errors"])
        with open(got["gates_path"], encoding="utf-8") as fh:
            self.assertIn("ERROR:", fh.read())


if __name__ == "__main__":
    unittest.main(verbosity=2)
