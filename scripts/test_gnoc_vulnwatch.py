"""Tests for gnoc_vulnwatch: no network, no dpkg database, no systemd. Every fetch is stubbed."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_defend as D  # noqa: E402
import gnoc_defender as G  # noqa: E402
import gnoc_vulnwatch as V  # noqa: E402


def _inv(**over):
    inv = {"bins": {"openssh-server": "1:10.3p1-1", "libc6": "2.41-12+deb13u4", "sudo": "1.9.16p2-3"},
           "srcs": {"openssh": "1:10.3p1-1", "glibc": "2.41-12+deb13u4", "sudo": "1.9.16p2-3"},
           "src_bins": {"openssh": ["openssh-server"], "glibc": ["libc6"], "sudo": ["sudo"]},
           "extra": {"google-chrome": "155.0.8059.79"}, "kernel": "7.1.13",
           "services": [{"port": 22, "proto": "tcp", "proc": "?", "pkg": "openssh-server"}],
           "notes": [], "apt": {"security": [], "other": 0, "lists_age_h": 2.0, "auto": True}}
    inv.update(over)
    return inv


def _chrome_cve(cid, hi="158.0.8127.36", cvss=8.8):
    return {"id": cid, "cvss": cvss, "desc": f"bug {cid} in Google Chrome prior to {hi}",
            "cpes": [{"vulnerable": True, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                      "versionEndExcluding": hi}]}


class Vulnwatch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = G.STATE
        G.STATE = self.tmp.name
        self.inv = _inv()
        self.kev = []
        self.nvd = []
        self.deb = {}            # cve -> {src: (fixed, urgency)}
        self.nvd_lookup = {}
        self.patches = [
            mock.patch.object(V, "inventory", lambda dest=None: self.inv),
            mock.patch.object(V, "fetch_kev", lambda st: (self.kev, f"{len(self.kev)} entries")),
            mock.patch.object(V, "fetch_nvd", lambda st: (list(self.nvd), f"{len(self.nvd)} new")),
            mock.patch.object(V, "http_json", self._http),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        G.STATE = self.saved
        self.tmp.cleanup()

    def _http(self, url, data=None, timeout=40, etag=None):
        if url.startswith(V.OSV_VULN + "DEBIAN-"):
            cve = url.rsplit("DEBIAN-", 1)[1]
            rec = self.deb.get(cve)
            if rec is None:
                return 404, None, "HTTP 404"
            aff = [{"package": {"name": src, "ecosystem": "Debian:13"},
                    "ranges": [{"events": [{"introduced": "0"}] + ([{"fixed": fx}] if fx else [])}],
                    "ecosystem_specific": {"urgency": urg}} for src, (fx, urg) in rec.items()]
            return 200, {"affected": aff}, None
        if "cveId=" in url:
            cid = url.rsplit("=", 1)[1]
            if cid not in self.nvd_lookup:
                return 0, None, "offline"
            return 200, {"vulnerabilities": [{"cve": {"configurations": [{"nodes": [
                {"cpeMatch": self.nvd_lookup[cid]}]}]}}]}, None
        return 0, None, "offline"

    def _ids(self):
        f, _n, s = V.run()
        return {x["id"]: x for x in f}, s

    def test_kev_match_patched_by_debian_is_silent(self):
        self.kev = [{"cveID": "CVE-2024-6387", "vendorProject": "OpenBSD", "product": "OpenSSH",
                     "vulnerabilityName": "regreSSHion"}]
        self.deb = {"CVE-2024-6387": {"openssh": ("1:9.7p1-7", "not yet assigned")}}
        ids, s = self._ids()
        self.assertFalse([i for i in ids if i.startswith("vuln:dpkg")])
        self.assertEqual(s["patched"], 1)

    def test_kev_match_with_fix_available_is_critical_and_says_how(self):
        self.kev = [{"cveID": "CVE-2026-1", "vendorProject": "Sudo", "product": "Sudo",
                     "vulnerabilityName": "chroot escalation"}]
        self.deb = {"CVE-2026-1": {"sudo": ("1.9.16p2-3+deb13u1", "high")}}
        ids, _ = self._ids()
        f = ids["vuln:dpkg:sudo:1.9.16p2-3"]
        self.assertEqual(f["sev"], "crit")
        self.assertIn("ACTIVELY EXPLOITED", f["fact"])
        self.assertIn("sudo apt install --only-upgrade sudo", f["fix"])

    def test_exposed_service_raises_severity(self):
        self.nvd = [{"id": "CVE-2026-2", "cvss": 8.1, "desc": "pre-auth bug in OpenSSH",
                     "cpes": [{"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                               "versionEndExcluding": "10.4"}]}]
        self.deb = {"CVE-2026-2": {"openssh": (None, "not yet assigned")}}
        ids, _ = self._ids()
        f = ids["vuln:dpkg:openssh:1:10.3p1-1"]
        self.assertEqual(f["sev"], "high")
        self.assertIn("network-facing service (port 22/tcp)", f["fact"])
        self.assertIn("ufw deny 22/tcp", f["fix"])

    def test_one_outdated_binary_is_one_finding_and_stays_until_fixed(self):
        self.nvd = [_chrome_cve(f"CVE-2026-13{i:04d}", cvss=9.6 if i == 0 else 8.8) for i in range(5)]
        ids, _ = self._ids()
        chrome = [i for i in ids if "google-chrome" in i]
        self.assertEqual(len(chrome), 1)
        f = ids[chrome[0]]
        self.assertIn("5 vulnerabilities", f["fact"])
        self.assertIn("fixed upstream in 158.0.8127.36", f["fact"])
        self.assertEqual(f["sev"], "high")
        self.nvd = []                                         # next hour: nothing NEW published
        ids, _ = self._ids()
        self.assertIn(chrome[0], ids, "an unpatched hit must not vanish when it stops being new")
        self.inv = _inv(extra={"google-chrome": "158.0.8127.40"})
        ids, _ = self._ids()
        self.assertFalse([i for i in ids if "google-chrome" in i], "updated: the finding clears")
        self.assertEqual(V._load("vulnwatch.json", {}).get("tracked"), {})

    def test_software_installed_after_the_announcement_is_still_checked(self):
        # measured 2026-11-18: the timer's first pass ran without ~/.local/bin on PATH, missed Chrome, and the
        # NVD cursor moved past its 35 CVEs for good. Recent announcements are re-matched every pass now.
        self.inv = _inv(extra={})
        self.nvd = [_chrome_cve("CVE-2026-1309999", cvss=9.6)]
        ids, _ = self._ids()
        self.assertFalse([i for i in ids if "google-chrome" in i])
        self.nvd = []
        self.inv = _inv()                                     # Chrome is visible now
        ids, _ = self._ids()
        self.assertIn("vuln:binary:google-chrome:155.0.8059.79", ids)

    def test_a_name_match_without_version_evidence_is_deferred_not_reported(self):
        self.kev = [{"cveID": "CVE-2026-3", "vendorProject": "Ollama", "product": "Ollama",
                     "vulnerabilityName": "x"}]
        self.inv = _inv(extra={"ollama": "0.40.3"})
        ids, s = self._ids()                                  # NVD lookup offline -> no evidence
        self.assertFalse([i for i in ids if "ollama" in i])
        self.assertEqual(s["deferred"], 1)
        self.nvd_lookup["CVE-2026-3"] = [{"vulnerable": True, "criteria": "cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*",
                                          "versionEndExcluding": "0.41.0"}]
        ids, _ = self._ids()
        self.assertEqual(ids["vuln:binary:ollama:0.40.3"]["sev"], "crit")   # KEV + outdated

    def test_generic_and_foreign_kernels_do_not_match(self):
        self.assertEqual(V.candidates("Kernel", "Android"), [])
        self.assertEqual(V.candidates("Windows", "Microsoft"), [])
        self.assertEqual(V.installed(V.candidates("Kernel", "Linux"), self.inv), [("kernel", "linux", "7.1.13", "linux")])

    def test_keeping_up_findings(self):
        self.inv = _inv(apt={"security": [{"pkg": "libc6", "from": "a", "to": "b"}], "other": 0,
                             "lists_age_h": 90.0, "auto": False})
        ids, _ = self._ids()
        self.assertEqual(ids["vuln:apt:security-updates"]["sev"], "high")
        self.assertIn("vuln:apt:stale-lists", ids)
        self.assertIn("vuln:apt:no-auto-security", ids)

    def test_new_cves_on_the_same_version_count_as_new(self):
        self.nvd = [_chrome_cve("CVE-2026-1300001")]
        _f, _n, s = V.run()
        self.assertTrue(s["new"])
        self.nvd = []
        _f, _n, s = V.run()
        self.assertFalse(s["new"], "nothing changed")
        self.nvd = [_chrome_cve("CVE-2026-1300002")]
        _f, _n, s = V.run()
        self.assertTrue(s["new"], "a new CVE against the same Chrome must notify again")

    def test_versions(self):
        self.assertEqual(V.upstream("1:10.3p1-1~bpo13+1"), "10.3p1")
        self.assertEqual(V.upstream("2.41-12+deb13u4"), "2.41")
        self.assertTrue(V.vcmp("155.0.8059.79", "lt", "158.0.8127.36"))


class Inventory(unittest.TestCase):
    def test_podman_shim_is_not_docker_and_port_fallback_only_for_hidden_owners(self):
        def run(argv, timeout=60):
            if argv[0] == "docker":
                return 0, "podman version 5.4.2"
            return 1, ""
        rows = [{"proto": "udp", "port": 5353, "bind": "all", "proc": "steam", "pid": 9},
                {"proto": "tcp", "port": 22, "bind": "all", "proc": "?", "pid": None}]
        with mock.patch.object(V.D, "_run", run), mock.patch.object(V.D, "listening", lambda: rows), \
                mock.patch.object(V.D, "_is_client_udp", lambda r: False), \
                mock.patch.object(V, "apt_state", lambda: {"security": [], "other": 0, "lists_age_h": None,
                                                           "auto": False}):
            inv = V.inventory()
        self.assertNotIn("docker", inv["extra"])
        self.assertEqual([s["pkg"] for s in inv["services"]], ["", "openssh"])


if __name__ == "__main__":
    unittest.main()


class OwnUnitsAreNotDrift(unittest.TestCase):
    """the user 2026-11-18: the sweep flagged the defender's own gnoc-vulnwatch.service and .timer as "new since the
    host baseline". gnoc vouches for exactly the bytes it wrote; anything else stays drift."""

    def setUp(self):
        import tempfile
        import gnoc_defender
        self.G = gnoc_defender
        self.tmp = tempfile.mkdtemp()
        self.base = os.path.join(self.tmp, "host.json")
        self._saved = (gnoc_defender._host_baseline_path, V._unit_dir)
        self.addCleanup(self._restore)   # runs even when setUp itself fails, so nothing leaks into later tests
        gnoc_defender._host_baseline_path = lambda dest=None: self.base
        V._unit_dir = lambda: self.tmp
        with open(self.base, "w") as fh:
            json.dump({"initialized": True, "files": {"/etc/x": "abc"}, "keys": {"k": "v"}, "ports": {},
                       "recorded": "2026-11-18 13:07:06"}, fh)

    def _restore(self):
        self.G._host_baseline_path, V._unit_dir = self._saved
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _drift(self, files):
        snap = self.G.host_snapshot(files, {"k": "v"}, [])
        found, _ = self.G.host_drift(snap, save=False)
        return [f for f in found if "drift:file" in str(f)]

    def test_an_installed_unit_is_vouched_and_a_tampered_one_is_not(self):
        svc, tmr = V._unit_files()
        with open(svc, "w") as fh:
            fh.write(V._service_text("/usr/bin:/bin"))      # installed from another shell: a different PATH
        with open(tmr, "w") as fh:
            fh.write(V._timer_text())
        self.assertEqual(V.vouch_own_units(), 2)
        files = {"/etc/x": None, svc: open(svc).read(), tmr: open(tmr).read()}
        b = json.load(open(self.base))
        self.assertEqual(b["files"]["/etc/x"], "abc", "nothing else in the baseline moves")
        self.assertEqual(b["keys"], {"k": "v"})
        swept = {p: D.parse_persist_dump(f"{D._PERSIST_MARK}{p}\n{t}")[p] for p, t in files.items() if t}
        self.assertEqual([f for f in self._drift(swept) if "gnoc-vulnwatch" in str(f)], [],
                         "the next sweep sees no drift on the units gnoc wrote")
        with open(svc, "a") as fh:
            fh.write("ExecStartPre=/tmp/evil\n")             # tampered: no longer what gnoc writes
        self.assertEqual(V.vouch_own_units(), 1, "only the untouched timer is vouched again")
        swept[svc] = D.parse_persist_dump(f"{D._PERSIST_MARK}{svc}\n{open(svc).read()}")[svc]
        self.assertTrue([f for f in self._drift(swept) if svc in str(f)], "the tampered unit is drift")

    def test_nothing_is_vouched_before_the_first_baseline(self):
        with open(self.base, "w") as fh:
            json.dump({"initialized": False}, fh)
        self.assertEqual(self.G.vouch_host_files({"/x": "y"}), 0)
        self.assertFalse(json.load(open(self.base)).get("initialized"))
