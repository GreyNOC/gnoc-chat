"""Phase 6: general scheduled tasks (/schedule).

The safety properties pinned here: a model or a tool cannot create, change or run a schedule (every shape a tool
call could use is refused, the vulnwatch timer included); /schedule add|rm|run take only a line typed at a
terminal; a scheduled run executes nothing that needs approval and lists each held call in its report; it runs
under the snapshot saved with it, not today's settings (except a deny rule added later, which still applies);
delivery to a file, the desktop and Telegram works, with the recipient fixed from the user's config and the bot
token never in what is sent. Nothing here touches the real crontab, systemd, network or home folder.
"""
import contextlib
import http.server
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import time
import types
import unittest
import unittest.mock as mock
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_agent as G  # noqa: E402
import gnoc_schedule as S  # noqa: E402

TOKEN = "123456789:AAH-fake-bot-token-for-tests-only"


class Done:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


class FakeRunner:
    """Records every command; crontab -l / crontab - act on an in-memory crontab."""

    def __init__(self, crontab="", fail=None):
        self.calls, self.crontab, self.fail = [], crontab, fail or set()

    def __call__(self, argv, input=None, timeout=30):
        self.calls.append((list(argv), input))
        key = " ".join(argv)
        if any(f in key for f in self.fail):
            return Done(1, "", "refused by the fake")
        if argv[:2] == ["crontab", "-l"]:
            return Done(0, self.crontab) if self.crontab else Done(1, "", "no crontab for user")
        if argv[:2] == ["crontab", "-"]:
            self.crontab = input
            return Done(0)
        return Done(0)


class Home(unittest.TestCase):
    """A throwaway HOME, GNOC_HOME and XDG_CONFIG_HOME for every test."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-p6-")
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(os.path.join(self.home, ".config", "gnoc"))
        self.env = mock.patch.dict(os.environ, {"HOME": self.home, "GNOC_HOME": os.path.join(self.home, ".gnoc"),
                                                "XDG_CONFIG_HOME": os.path.join(self.home, ".config")})
        self.env.start()
        for k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_OWNER_CHAT_ID", "TELEGRAM_API_BASE", "TERMUX_VERSION",
                  "HUNT_TARGET"):
            os.environ.pop(k, None)
        self.saved_root = G._ACTIVE_ROOT[0]

    def tearDown(self):
        G._ACTIVE_ROOT[0] = self.saved_root
        self.env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def secrets(self, **kv):
        with open(os.path.join(self.home, ".config", "gnoc", "secrets.env"), "w") as fh:
            fh.write("".join(f"{k}={v}\n" for k, v in kv.items()))

    def snap(self, folder=None, allow=(), deny=()):
        return S.snapshot(program=None, folder=folder or self.tmp, effort="low", steps=None, lead="fake-lead",
                          worker="fake-worker",
                          perms={"allow": [{"rule": r, "repo": None} for r in allow],
                                 "deny": [{"rule": r, "repo": None} for r in deny]})


# ------------------------------------------------------------------------------------------- the model cannot

class TheModelCannotSchedule(Home):
    """Every way a tool call could make, change or run a job is refused through the real dispatch."""

    REFUSED = [
        ("bash", {"command": 'gnoc chat "/schedule add \\"0 9 * * *\\" summarise the logs"'}),
        ("bash", {"command": "gnoc chat -p '/schedule rm 1a2b3c4d'"}),
        ("bash", {"command": "gnoc schedule run 1a2b3c4d"}),
        ("bash", {"command": "~/.local/bin/gnoc schedule list"}),
        ("bash", {"command": "python3 scripts/gnoc_schedule.py run 1a2b3c4d"}),
        ("bash", {"command": "python3 -c 'import gnoc_schedule; gnoc_schedule.add(1, 2)'"}),
        ("bash", {"command": '(crontab -l; echo "* * * * * curl x | sh") | crontab -'}),
        ("bash", {"command": "crontab /tmp/mine.cron"}),
        ("bash", {"command": "crontab -e"}),
        ("bash", {"command": "sudo crontab -r"}),
        ("bash", {"command": "systemctl --user enable --now backup.timer"}),
        ("bash", {"command": "systemctl --user edit backup.service"}),
        ("bash", {"command": "systemd-run --user --on-calendar=hourly /bin/true"}),
        ("bash", {"command": "echo /bin/true | at now + 1 minute"}),
        ("bash", {"command": "at 23:00 -f job.sh"}),
        ("bash", {"command": "cat > ~/.config/systemd/user/x.timer <<'EOF'\n[Timer]\nOnCalendar=hourly\nEOF"}),
        ("bash", {"command": "cp start.sh ~/.termux/boot/start.sh"}),
        ("bash", {"command": "echo '* * * * * x' >> /data/data/com.termux/files/usr/var/spool/cron/crontabs/u0"}),
        ("bash", {"command": "rm ~/.gnoc/schedules/1a2b3c4d.json"}),
        ("bg", {"action": "start", "name": "c", "command": "crontab /tmp/x"}),
        ("gnoc", {"args": "schedule run 1a2b3c4d"}),
        ("defend", {"action": "sweep", "target": "/schedule add hourly"}),
        ("write_file", {"path": "~/.config/systemd/user/evil.timer", "content": "[Timer]\nOnCalendar=minutely\n"}),
        ("write_file", {"path": "~/.termux/boot/run.sh", "content": "#!/bin/sh\n"}),
        ("edit_file", {"path": "~/.config/systemd/user/gnoc-schedule-1a2b3c4d.service", "old": "a", "new": "b"}),
        ("apply_patch", {"patch": "--- a/.config/systemd/user/x.timer\n+++ b/.config/systemd/user/x.timer\n"
                                  "@@ -1 +1 @@\n-a\n+b\n"}),
        ("claude_worker", {"agent": "claude", "brief": "add a crontab line that runs the backup every night"}),
    ]

    def test_each_shape_is_refused_by_the_dispatch(self):
        ctx = G.Ctx({"sid": "p6-model"})
        G._ACTIVE_ROOT[0] = self.home
        for name, args in self.REFUSED:
            # a tool the edition does not ship (gnoc, claude_worker in the public build) is refused as unknown
            # before any rule: its shape is checked against the rule itself
            pre = (G._plan_call(name, dict(args), ctx, False, None)[2] if name in G.TOOLS
                   else S.model_refusal(name, dict(args), root=self.home))
            self.assertIn("only the user sets a schedule", pre or "", (name, args, pre))
            self.assertIn("/schedule add", pre or "", name)

    def test_a_record_written_into_the_schedules_folder_is_refused(self):
        G._ACTIVE_ROOT[0] = self.home
        path = os.path.join(S.sched_dir(), "deadbeef.json")
        pre = G._plan_call("write_file", {"path": path, "content": "{}"}, G.Ctx({"sid": "p6"}), False, None)[2]
        self.assertIn("only the user sets a schedule", pre or "")

    def test_skip_perms_does_not_lift_it(self):
        saved = G.SKIP_PERMS[0]
        G.SKIP_PERMS[0] = True
        try:
            pre = G._plan_call("bash", {"command": "crontab /tmp/x"}, G.Ctx({"sid": "p6", "auto": True}), True,
                               None)[2]
        finally:
            G.SKIP_PERMS[0] = saved
        self.assertIn("only the user sets a schedule", pre or "")

    def test_the_vulnwatch_timer_is_the_users_too(self):
        """Phase 0 audit: the vulnwatch systemd timer escaped the user-only rule. defend(vulnwatch, op=on) fell
        through to a status read, but bash reached `gnoc_vulnwatch.py timer on` and a one-shot `gnoc chat
        "/defender vulnwatch on"` behind an ordinary approval (none under -s-p)."""
        ctx = G.Ctx({"sid": "p6-vw"})
        pre = G._plan_call("defend", {"action": "vulnwatch", "op": "on"}, ctx, False, None)[2]
        self.assertIn("only the user turns the hourly vulnerability watch on or off", pre or "")
        self.assertIn("/defender vulnwatch on", pre or "")
        for cmd in ("python3 scripts/gnoc_vulnwatch.py timer on", 'gnoc chat "/defender vulnwatch on"',
                    "python3 -c 'import gnoc_vulnwatch; gnoc_vulnwatch.timer(\"on\")'",
                    "systemctl --user enable --now gnoc-vulnwatch"):
            pre = G._plan_call("bash", {"command": cmd}, ctx, False, None)[2]
            self.assertIn("only the user sets a schedule", pre or "", cmd)
        # a direct caller of the tool gets the same answer, and the timer is never touched
        import gnoc_vulnwatch
        with mock.patch.object(gnoc_vulnwatch, "timer", side_effect=AssertionError("timer touched")):
            out = G.TOOLS["defend"][0](ctx, action="vulnwatch", op="on")
        self.assertTrue(out.startswith("refused: only the user"), out)

    def test_reads_and_unrelated_commands_are_not_refused(self):
        """Negative controls: looking is not scheduling, and the word 'schedule' is not a command."""
        root = self.home
        for name, args in [
                ("bash", {"command": "crontab -l"}), ("bash", {"command": "crontab -l | grep gnoc"}),
                ("bash", {"command": "crontab -l > /tmp/backup.cron"}),
                ("bash", {"command": "systemctl --user list-timers"}),
                ("bash", {"command": "systemctl --user status gnoc-schedule-1a2b3c4d.timer"}),
                ("bash", {"command": "cat ~/.config/systemd/user/x.timer"}),
                ("bash", {"command": "ls ~/.gnoc/schedules"}), ("bash", {"command": "cat scripts/gnoc_schedule.py"}),
                ("bash", {"command": "ls ~/projects/schedule"}), ("bash", {"command": "grep -rn schedule src/"}),
                ("bash", {"command": "cat now.txt"}), ("bash", {"command": "python3 at.py"}),
                ("gnoc", {"args": "status"}), ("defend", {"action": "vulnwatch", "op": "status"}),
                ("defend", {"action": "vulnwatch", "op": "run"}),
                ("write_file", {"path": "notes/schedule.md", "content": "crontab and systemd notes"}),
                ("claude_worker", {"brief": "fix the failing unit test in calc.py"})]:
            self.assertIsNone(S.model_refusal(name, args, root=root), (name, args))

    def test_the_old_defender_refusal_still_answers_first(self):
        pre = G._plan_call("bash", {"command": 'gnoc chat -s-p "/defender schedule hourly"'}, G.Ctx({"sid": "p6"}),
                           False, None)[2]
        self.assertIn("only the user sets a scheduled sweep", pre or "")

    def test_the_gnoc_tool_denies_schedule_without_the_dispatch_too(self):
        self.assertEqual(G._gnoc_class("schedule run 1a2b3c4d")[0], "deny")


# ------------------------------------------------------------------------------------------- typed only

class ScheduleIsTypedOnly(Home):
    """/schedule add|rm|run accept only the exact string object read from the keyboard, on a terminal."""

    def setUp(self):
        super().setUp()
        self.calls, self.out = [], []
        self.agent = G.Agent.__new__(G.Agent)
        self.agent.s = {"sid": "p6-typed", "history": []}
        self.agent.ctx = G.Ctx(self.agent.s)
        self.agent.interactive = True
        self.agent.interrupted = False
        self.agent.save = lambda: None
        self.cmd = mock.patch.object(S, "command", lambda rest, **k: self.calls.append(rest) or "ok")
        self.cmd.start()

    def tearDown(self):
        self.cmd.stop()
        super().tearDown()

    def _slash(self, line, tty=True):
        with contextlib.ExitStack() as st:
            st.enter_context(mock.patch.object(G, "say", lambda t: self.out.append(str(t))))
            st.enter_context(mock.patch.object(sys, "stdin", types.SimpleNamespace(isatty=lambda: tty)))
            return G.handle_slash(self.agent, line, {})

    def test_an_untyped_add_is_refused(self):
        self.agent._typed_line = None
        self._slash('/schedule add "0 9 * * *" hello')
        self.assertEqual(self.calls, [])
        self.assertTrue(any("refused, nothing changed" in o for o in self.out), self.out)

    def test_an_equal_but_different_string_is_refused(self):
        typed = "".join(["/schedule rm ", "1a2b3c4d"])
        echoed = "".join(["/schedule rm 1a2b", "3c4d"])
        self.assertEqual(typed, echoed)
        self.agent._typed_line = typed
        self._slash(echoed)
        self.assertEqual(self.calls, [])

    def test_the_typed_line_runs_once(self):
        typed = "".join(["/schedule run ", "1a2b3c4d"])
        self.agent._typed_line = typed
        self._slash(typed)
        self.assertEqual(self.calls, ["run 1a2b3c4d"])
        self._slash(typed)
        self.assertEqual(len(self.calls), 1)

    def test_a_typed_line_without_a_terminal_is_refused(self):
        """A model's bash runs `gnoc chat "/schedule add ..."` with stdin on /dev/null; that launcher marks its argv
        as typed, so the terminal is the second check."""
        typed = "".join(["/schedule add ", '"0 9 * * *" hi'])
        self.agent._typed_line = typed
        self._slash(typed, tty=False)
        self.assertEqual(self.calls, [])

    def test_list_needs_no_typed_line(self):
        self.agent._typed_line = None
        self._slash("/schedule list", tty=False)
        self.assertEqual(self.calls, ["list"])

    def test_defender_schedule_is_typed_only(self):
        import gnoc_defender
        self.agent._typed_line = None
        with mock.patch.object(gnoc_defender, "schedule", side_effect=AssertionError("crontab touched")):
            self._slash("/defender schedule hourly")
        self.assertTrue(any("refused, nothing changed" in o for o in self.out), self.out)

    def test_defender_vulnwatch_on_is_typed_only(self):
        import gnoc_vulnwatch
        self.agent._typed_line = None
        with mock.patch.object(gnoc_vulnwatch, "timer", side_effect=AssertionError("timer touched")):
            self._slash("/defender vulnwatch on")
        self.assertTrue(any("refused, nothing changed" in o for o in self.out), self.out)


# ------------------------------------------------------------------------------------------- cron -> systemd

class CronToOnCalendar(unittest.TestCase):
    def test_faithful_conversions(self):
        for cron, want in [("*/15 * * * *", "*-*-* *:0,15,30,45:00"),
                           ("0 9 * * 1-5", "Mon,Tue,Wed,Thu,Fri *-*-* 9:0:00"),
                           ("30 2 1 * *", "*-*-1 2:30:00"), ("@daily", "*-*-* 0:0:00"),
                           ("0 0 * * 7", "Sun *-*-* 0:0:00"), ("0 0 * * sun,sat", "Sun,Sat *-*-* 0:0:00"),
                           ("0 0 1 jan *", "*-1-1 0:0:00"), ("0 */6 * * *", "*-*-* 0,6,12,18:0:00"),
                           ("5 4 */10 * *", "*-*-1,11,21,31 4:5:00")]:
            self.assertEqual(S.cron_to_oncalendar(cron), (want, None), cron)

    def test_what_cannot_be_said_faithfully_is_refused(self):
        for cron, why in [("0 0 1 * 1", "EITHER"), ("@reboot", "no calendar time"), ("* * * *", "five fields"),
                          ("61 * * * *", "outside"), ("5-1 * * * *", "backwards"), ("*/0 * * * *", "bad step"),
                          ("a * * * *", "not a number"), ("0 0 * * * *", "five fields")]:
            got, err = S.cron_to_oncalendar(cron)
            self.assertIsNone(got, cron)
            self.assertIn(why, err, cron)


# ------------------------------------------------------------------------------------------- backends

class Backends(Home):
    def test_detection(self):
        run_ok, run_bad = FakeRunner(), FakeRunner(fail={"show-environment"})
        self.assertEqual(S.detect_backend({"TERMUX_VERSION": "0.118"}, lambda n: None, run_ok), "termux")
        termux_prefix = "/data/data/com.termux/files/usr"
        self.assertEqual(S.detect_backend({"PREFIX": termux_prefix}, lambda n: None, run_ok,
                                          exists=lambda p: p == termux_prefix + "/bin/crond"), "termux")
        self.assertEqual(S.detect_backend({}, lambda n: "/usr/bin/" + n, run_ok), "systemd")
        self.assertEqual(S.detect_backend({}, lambda n: "/usr/bin/" + n, run_bad), "cron")
        self.assertIsNone(S.detect_backend({}, lambda n: None, run_ok))

    def _rec(self, cron="0 9 * * 1-5"):
        return {"id": "1a2b3c4d", "cron": cron, "caps": {"wall_s": 900, "tokens": 1000}}

    def test_systemd_units_are_written_and_enabled(self):
        r = FakeRunner()
        rec = self._rec()
        ok, said = S.install(rec, "systemd", runner=r, which=lambda n: None, argv=["/opt/gnoc 1/gnoc"])
        self.assertTrue(ok, said)
        d = S.unit_dir()
        svc = open(os.path.join(d, "gnoc-schedule-1a2b3c4d.service")).read()
        tmr = open(os.path.join(d, "gnoc-schedule-1a2b3c4d.timer")).read()
        self.assertIn('ExecStart="/opt/gnoc 1/gnoc" "schedule" "run" "1a2b3c4d"', svc)
        self.assertIn("OnCalendar=Mon,Tue,Wed,Thu,Fri *-*-* 9:0:00", tmr)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(d, "gnoc-schedule-1a2b3c4d.timer")).st_mode), 0o600)
        self.assertIn(["systemctl", "--user", "enable", "--now", "gnoc-schedule-1a2b3c4d.timer"],
                      [c for c, _ in r.calls])
        S.uninstall(rec, runner=r)
        self.assertFalse(os.path.exists(os.path.join(d, "gnoc-schedule-1a2b3c4d.timer")))

    def test_a_refused_enable_leaves_nothing_behind(self):
        ok, said = S.install(self._rec(), "systemd", runner=FakeRunner(fail={"enable"}), which=lambda n: None,
                             argv=["gnoc"])
        self.assertFalse(ok)
        self.assertIn("refused", said)
        self.assertEqual([f for f in os.listdir(S.unit_dir()) if "1a2b3c4d" in f], [])

    def test_systemd_analyze_has_the_last_word_on_the_calendar(self):
        r = FakeRunner(fail={"systemd-analyze"})
        ok, said = S.install(self._rec(), "systemd", runner=r, which=lambda n: "/usr/bin/" + n, argv=["gnoc"])
        self.assertFalse(ok)
        self.assertIn("systemd does not accept", said)
        self.assertEqual([c for c, _ in r.calls], [["systemd-analyze", "calendar", "Mon,Tue,Wed,Thu,Fri *-*-* 9:0:00"]])

    def test_systemd_refuses_a_line_it_cannot_say(self):
        ok, said = S.install(self._rec("0 0 1 * 1"), "systemd", runner=FakeRunner(), which=lambda n: None,
                             argv=["gnoc"])
        self.assertFalse(ok)
        self.assertIn("EITHER", said)

    def test_crontab_keeps_every_other_line(self):
        mine = "15 3 * * * /usr/bin/backup\n*/30 * * * * gnoc chat \"/defender sweep\" # gnoc-defender-schedule\n"
        r = FakeRunner(crontab=mine)
        rec = self._rec()
        ok, said = S.install(rec, "cron", runner=r, which=lambda n: "/usr/bin/crontab", argv=["/usr/bin/gnoc"])
        self.assertTrue(ok, said)
        self.assertIn("/usr/bin/backup", r.crontab)
        self.assertIn("# gnoc-defender-schedule", r.crontab)
        line = [ln for ln in r.crontab.splitlines() if ln.endswith("# gnoc-schedule:1a2b3c4d")]
        self.assertEqual(len(line), 1)
        self.assertTrue(line[0].startswith("0 9 * * 1-5 GNOC_NO_UPDATE_CHECK=1 GNOC_SCHEDULED=1a2b3c4d "))
        self.assertIn("/usr/bin/gnoc schedule run 1a2b3c4d", line[0])
        S.uninstall(rec, runner=r)
        self.assertEqual(r.crontab, mine)

    def test_termux_gets_the_crond_note(self):
        ok, said = S.install(self._rec(), "termux", runner=FakeRunner(), which=lambda n: "/x/crontab", argv=["g"])
        self.assertTrue(ok)
        self.assertIn("termux-services", said)
        ok, said = S.install(self._rec(), "termux", runner=FakeRunner(), which=lambda n: None, argv=["g"])
        self.assertFalse(ok)
        self.assertIn("pkg install cronie", said)


# ------------------------------------------------------------------------------------------- add / list / rm

class AddListRemove(Home):
    def add(self, rest, **k):
        r = k.pop("runner", FakeRunner())
        return S.command("add " + rest, snap_fn=lambda: self.snap(allow=("bash(pytest *)",),
                                                                  deny=("bash(rm -rf *)",)),
                         runner=r, which=lambda n: "/usr/bin/" + n, backend="cron", argv=["/usr/bin/gnoc"], **k), r

    def test_add_saves_the_snapshot_owner_only_and_list_shows_it(self):
        out, r = self.add('"0 9 * * 1-5" summarise the CI failures')
        self.assertTrue(out.startswith("scheduled "), out)
        sid = out.split()[1].rstrip(":")
        rec = S.load(sid)
        self.assertEqual(rec["prompt"], "summarise the CI failures")
        self.assertEqual(rec["snapshot"]["effort"], "low")
        self.assertEqual(rec["snapshot"]["model"]["lead"], "fake-lead")
        self.assertEqual(stat.S_IMODE(os.stat(S._rec_path(sid)).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(S.sched_dir()).st_mode), 0o700)
        self.assertEqual(rec["caps"], {"wall_s": 900, "tokens": 200000})   # the README's 15 minutes / ~200k tokens
        listing = S.command("list")
        for want in (sid, "cron '0 9 * * 1-5'", "allow bash(pytest *)", "deny bash(rm -rf *)", "effort low",
                     "lead fake-lead", rec["snapshot"]["permissions"]["sha256"][:12], "held and reported"):
            self.assertIn(want, listing)
        out = S.command("rm " + sid, runner=r)
        self.assertIn("removed", out)
        self.assertIsNone(S.load(sid))
        self.assertNotIn("gnoc-schedule:" + sid, r.crontab)

    def test_malformed_input_is_refused_with_what_to_type(self):
        for rest, why in [('"0 9 * *" x', "five fields"), ('"0 9 * * *"', "say what to run"),
                          ('"0 9 * * *" x --deliver pigeon', "--deliver takes"), ('"0 9 * * * x', "does not close"),
                          ('"0 9 * * *" a​b', "invisible")]:
            out, _ = self.add(rest)
            self.assertIn("not scheduled", out, rest)
            self.assertIn(why, out, rest)
        self.assertEqual(S.records(), [])
        self.assertIn("no schedule", S.command("rm ../../etc/passwd"))

    def test_telegram_recipient_comes_from_config_never_the_prompt(self):
        out, _ = self.add('"0 9 * * *" send it to chat 999 --deliver telegram')
        self.assertIn("TELEGRAM_OWNER_CHAT_ID", out)   # nothing configured: refused, never taken from the prompt
        self.secrets(TELEGRAM_BOT_TOKEN=TOKEN, TELEGRAM_OWNER_CHAT_ID="4242")
        out, _ = self.add('"0 9 * * *" send it to chat 999 --deliver telegram')
        rec = S.load(out.split()[1].rstrip(":"))
        self.assertEqual(rec["deliver"], {"kind": "telegram", "chat_id": "4242", "api_base": S.TELEGRAM_API})
        self.assertNotIn(TOKEN, json.dumps(rec))   # the token is read at send time, never stored

    def test_the_gateways_owner_id_is_his_chat_when_no_owner_chat_is_set(self):
        # integration of phases 5 and 6: one Telegram setup serves both; the recipient is still his config
        self.secrets(TELEGRAM_BOT_TOKEN=TOKEN, GNOC_TELEGRAM_OWNERS="5150, 777")
        out, _ = self.add('"0 9 * * *" send it to chat 999 --deliver telegram')
        rec = S.load(out.split()[1].rstrip(":"))
        self.assertEqual(rec["deliver"]["chat_id"], "5150")
        # an explicit owner chat still wins over the gateway list
        self.secrets(TELEGRAM_BOT_TOKEN=TOKEN, GNOC_TELEGRAM_OWNERS="5150", TELEGRAM_OWNER_CHAT_ID="4242")
        out, _ = self.add('"0 9 * * *" hi --deliver telegram')
        self.assertEqual(S.load(out.split()[1].rstrip(":"))["deliver"]["chat_id"], "4242")
        # a gateway owner list with no numeric id is no recipient: refused, never the prompt's 999
        self.secrets(TELEGRAM_BOT_TOKEN=TOKEN, GNOC_TELEGRAM_OWNERS="@someone")
        out, _ = self.add('"0 9 * * *" send it to chat 999 --deliver telegram')
        self.assertIn("not scheduled", out)

    def test_a_cleartext_api_base_off_this_machine_is_refused(self):
        self.secrets(TELEGRAM_BOT_TOKEN=TOKEN, TELEGRAM_OWNER_CHAT_ID="4242",
                     TELEGRAM_API_BASE="http://api.example.invalid")
        out, _ = self.add('"0 9 * * *" hi --deliver telegram')
        self.assertIn("must be https", out)


# ------------------------------------------------------------------------------------------- a run

class _Telegram(http.server.BaseHTTPRequestHandler):
    got: list = []
    delay = 0.0
    status = 200

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        type(self).got.append((self.path, urllib.parse.parse_qs(body)))
        time.sleep(type(self).delay)
        data = json.dumps({"ok": self.status == 200}).encode()
        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


class ARun(Home):
    """Scheduled runs through the real Agent, dispatch and approval gate, with a scripted model."""

    def setUp(self):
        super().setUp()
        self.repo = os.path.join(self.tmp, "proj")
        os.makedirs(os.path.join(self.repo, "build"))
        self.saved_g = (G.SKIP_PERMS[0], G.resolve, G.llm_chat, G.say, G.AGENT_DIR)
        G.resolve = lambda role, quiet=False: ("smoke-model", "local")
        G.say = lambda *a, **k: None

    def tearDown(self):
        G.SKIP_PERMS[0], G.resolve, G.llm_chat, G.say, _agent_dir = self.saved_g
        self.assertEqual(G.AGENT_DIR, _agent_dir, "the run left its agent dir on the facade")
        super().tearDown()

    @staticmethod
    def call(name, **args):
        return {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": name, "arguments": args}}]}

    def script(self, steps):
        steps = list(steps)
        G.llm_chat = lambda model, host, msgs, *a, **k: (steps.pop(0) if steps else
                                                         {"role": "assistant", "content": "DONE (exhausted)"})

    def make(self, deliver=None, allow=(), deny=(), caps=None, prompt="tidy the build folder"):
        rec = {"id": "c0ffee01", "created_at": "2026-11-26T09:00:00", "cron": "0 9 * * *", "prompt": prompt,
               "deliver": deliver or {"kind": "file"}, "snapshot": self.snap(self.repo, allow, deny),
               "caps": caps or {"wall_s": 60, "tokens": 200000}, "backend": {"kind": "cron"}, "runs": []}
        S.save(rec)
        return rec

    def report(self, text):
        path = text.rsplit("report ", 1)[1].strip()
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with open(path) as fh:
            return fh.read()

    def test_a_held_action_is_reported_and_not_run(self):
        self.make()
        G.SKIP_PERMS[0] = True   # the chat had skip-perms on: a scheduled run never inherits it
        self.script([self.call("bash", command="rm -rf build"),
                     self.call("bash", command="crontab /tmp/mine.cron"),
                     {"role": "assistant", "content": "DONE: build is waiting for approval."}])
        code, text = S.run("c0ffee01")
        self.assertTrue(G.SKIP_PERMS[0], "the chat's own setting is put back")
        self.assertTrue(os.path.isdir(os.path.join(self.repo, "build")), "a held call ran")
        rep = self.report(text)
        self.assertIn("- status: finished", rep)
        self.assertIn("held for approval: bash rm -rf build", rep)
        self.assertIn("- held for approval, NOT run: 1", rep)
        self.assertIn("only the user sets a schedule", rep)   # the run cannot make a job either
        self.assertIn("DONE: build is waiting for approval.", rep)
        self.assertEqual(code, 0)
        self.assertEqual(S.load("c0ffee01")["runs"][-1]["held"], 1)

    def test_the_snapshot_rules_decide_not_todays(self):
        """allow: exactly the snapshot (one added later does not widen a run). deny: one added later still holds."""
        os.makedirs(S.home(), exist_ok=True)
        with open(os.path.join(S.home(), "permissions.json"), "w") as fh:
            json.dump({"allow": [{"rule": "bash(touch late.txt)", "repo": None}],
                       "deny": [{"rule": "bash(touch denied.txt)", "repo": None}]}, fh)
        self.make(allow=("bash(touch snap.txt)", "bash(touch denied.txt)"))
        self.script([self.call("bash", command="touch snap.txt"), self.call("bash", command="touch late.txt"),
                     self.call("bash", command="touch denied.txt"), {"role": "assistant", "content": "DONE"}])
        rep = self.report(S.run("c0ffee01")[1])
        self.assertTrue(os.path.exists(os.path.join(self.repo, "snap.txt")), rep)
        self.assertFalse(os.path.exists(os.path.join(self.repo, "late.txt")))
        self.assertFalse(os.path.exists(os.path.join(self.repo, "denied.txt")))
        self.assertIn("held for approval: bash touch late.txt", rep)
        self.assertIn("deny bash(touch denied.txt)", rep)

    def test_the_run_uses_the_saved_effort_model_and_folder_and_puts_them_back(self):
        self.make()
        seen = {}

        def llm(model, host, msgs, *a, **k):
            seen.update(effort=G.EFFORT[0], steps=G.STEPS_OVERRIDE[0], root=G._ACTIVE_ROOT[0],
                        lead=os.environ.get("GNOC_ROLE_LEAD"), worker=os.environ.get("GNOC_ROLE_WORKER"),
                        skip=G.SKIP_PERMS[0])
            return {"role": "assistant", "content": "DONE"}

        G.llm_chat = llm
        before = (G.EFFORT[0], G.STEPS_OVERRIDE[0], G._ACTIVE_ROOT[0], os.environ.get("GNOC_ROLE_LEAD"))
        S.run("c0ffee01")
        self.assertEqual(seen, {"effort": "low", "steps": G.EFFORTS["low"]["steps"], "root": self.repo,
                                "lead": "fake-lead", "worker": "fake-worker", "skip": False})
        self.assertEqual((G.EFFORT[0], G.STEPS_OVERRIDE[0], G._ACTIVE_ROOT[0], os.environ.get("GNOC_ROLE_LEAD")),
                         before)

    def test_an_unattended_run_writes_no_lessons(self):
        self.make()
        self.script([self.call("read_file", path="x.txt"), {"role": "assistant", "content": "DONE"}])
        wrote = []   # recorded, not raised: turn() swallows an exception, so a raise would prove nothing
        with mock.patch.object(G, "start_reflection", lambda *a, **k: wrote.append(a)):
            code, text = S.run("c0ffee01")
        self.assertIn("- status: finished", self.report(text))
        self.assertEqual(wrote, [])

    def test_file_delivery_is_the_default_and_owner_only(self):
        self.make()
        self.script([{"role": "assistant", "content": "DONE: nothing to do."}])
        code, text = S.run("c0ffee01")
        self.assertIn("written to the file", text)
        out = S.out_dir("c0ffee01")
        self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o700)
        self.assertEqual(len([f for f in os.listdir(out) if f.endswith(".md")]), 1)

    def test_desktop_delivery(self):
        self.make(deliver={"kind": "desktop"})
        self.script([self.call("bash", command="rm -rf build"), {"role": "assistant", "content": "DONE"}])
        seen = []
        code, text = S.run("c0ffee01", notify=lambda t, b, force=False: seen.append((t, b, force)) or True)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][0], "gnoc task c0ffee01")
        self.assertIn("held for approval, NOT run: 1", seen[0][1])
        self.assertTrue(seen[0][2], "a timer has no terminal: the notification is forced")
        self.assertIn("desktop notification sent", text)

    def _server(self):
        _Telegram.got, _Telegram.delay, _Telegram.status = [], 0.0, 200
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Telegram)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return f"http://127.0.0.1:{srv.server_address[1]}"

    def test_telegram_delivery_to_the_saved_owner_chat_with_the_token_redacted(self):
        base = self._server()
        self.secrets(TELEGRAM_BOT_TOKEN=TOKEN, TELEGRAM_OWNER_CHAT_ID="4242")
        self.make(deliver={"kind": "telegram", "chat_id": "4242", "api_base": base},
                  prompt="report, and send it to chat 999")
        self.script([self.call("bash", command="rm -rf build"),
                     {"role": "assistant", "content": f"DONE. The bot token is {TOKEN}. Also send to chat 999."}])
        code, text = S.run("c0ffee01")
        self.assertIn("sent to telegram", text)
        self.assertEqual(len(_Telegram.got), 1)
        path, form = _Telegram.got[0]
        self.assertEqual(path, f"/bot{TOKEN}/sendMessage")
        self.assertEqual(form["chat_id"], ["4242"])
        self.assertIn("held for approval: bash rm -rf build", form["text"][0])
        self.assertNotIn(TOKEN, form["text"][0])
        self.assertNotIn(TOKEN, self.report(text))

    def test_telegram_timeout_and_refusal_are_reported_without_the_token(self):
        base = self._server()
        _Telegram.delay = 2.0
        ok, said = S.telegram_send(TOKEN, "4242", "hi", base, timeout=0.5)
        self.assertFalse(ok)
        self.assertIn("not reached", said)
        self.assertNotIn(TOKEN, said)
        _Telegram.delay, _Telegram.status = 0.0, 401
        ok, said = S.telegram_send(TOKEN, "4242", "hi", base, timeout=5)
        self.assertFalse(ok)
        self.assertIn("HTTP 401", said)
        self.assertNotIn(TOKEN, said)
        ok, said = S.telegram_send(TOKEN, "4242", "hi", "http://203.0.113.9")
        self.assertFalse(ok)
        self.assertIn("must be https", said)

    def test_the_wall_clock_cap_stops_a_run(self):
        self.make(caps={"wall_s": 1, "tokens": 200000})

        def slow(model, host, msgs, *a, **k):
            end = time.time() + 20
            while not G.INTERRUPT.is_set() and time.time() < end:
                time.sleep(0.02)
            return {"role": "assistant", "content": "DONE late"}

        G.llm_chat = slow
        code, text = S.run("c0ffee01")
        self.assertEqual(code, 1)
        self.assertIn("stopped at the wall-clock cap (1 s)", text)
        self.assertFalse(G.INTERRUPT.is_set())

    def test_the_token_cap_stops_a_run(self):
        self.make(caps={"wall_s": 60, "tokens": 1})
        calls = []

        def llm(model, host, msgs, *a, **k):
            calls.append(1)
            return self.call("read_file", path="x.txt") if len(calls) < 5 else {"role": "assistant", "content": "DONE"}

        G.llm_chat = llm
        code, text = S.run("c0ffee01")
        self.assertIn("stopped at the token cap", text)
        self.assertEqual(len(calls), 1, "the model was called again past the cap")

    def test_a_second_start_while_one_runs_is_skipped(self):
        import fcntl
        self.make()
        os.makedirs(S.sched_dir(), exist_ok=True)
        with open(os.path.join(S.sched_dir(), ".c0ffee01.lock"), "a") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            code, text = S.run("c0ffee01")
        self.assertIn("still running", text)
        self.assertFalse(os.path.isdir(S.out_dir("c0ffee01")))

    def test_a_run_that_cannot_start_is_reported_not_raised(self):
        self.make()
        with mock.patch.object(G, "Agent", side_effect=RuntimeError("settings file unreadable")):
            code, text = S.run("c0ffee01")
        self.assertEqual(code, 1)
        self.assertIn("- status: failed: RuntimeError: settings file unreadable", self.report(text))

    def test_an_unknown_or_malformed_id_runs_nothing(self):
        self.assertEqual(S.run("../../x")[0], 2)
        self.assertEqual(S.main(["run", "../x"]), 2)
        self.assertEqual(S.main(["add", "x"]), 2)


if __name__ == "__main__":
    unittest.main()
