"""gnoc models: which machine a model is downloaded to when more than one is hooked up (machines, where, and the
question pull asks). No network: Hugging Face and the model servers are stand-ins."""
import contextlib
import importlib.util
import io
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_engine as E  # noqa: E402

_spec = importlib.util.spec_from_file_location("gnoc_models_cmd", os.path.join(HERE, "gnoc-models.py"))
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)

GB = 2 ** 30
QUANTS = [("Q4_K_M", int(9.0e9), "m-Q4_K_M.gguf"), ("Q8_0", int(15.7e9), "m-Q8_0.gguf"),
          ("Q3_K_M", int(7.3e9), "m-Q3_K_M.gguf")]


def row(name, kind="gnoc", vram=8, ram=32, free=100, have=()):
    return {"name": name, "addr": f"127.0.0.1:{11435 + len(name)}", "kind": kind, "gpu": "nvidia" if vram else "",
            "vram": vram * GB, "ram": ram * GB, "free": int(free * 1e9), "models": len(have), "have": list(have)}


class Base(unittest.TestCase):
    def setUp(self):
        self.pulled = []
        self.rows = [row("local"), row("desktop", "ollama", vram=16, ram=0, free=0), row("phone", "")]
        hosts = {r["name"]: r["addr"] for r in self.rows}
        for p in (mock.patch.object(M, "HOSTS", hosts), mock.patch.object(M, "quants", lambda repo: QUANTS),
                  mock.patch.object(M, "machines", lambda timeout=2: self.rows),
                  mock.patch.object(M.gnoc_engine, "remote_pull",
                                    lambda host, src, show=True: self.pulled.append((host, src))),
                  mock.patch.object(M.gnoc_engine, "remote_create", lambda *a, **k: None),
                  mock.patch.object(M, "ON", "local"), mock.patch.object(M, "HOST", hosts["local"])):
            p.start()
            self.addCleanup(p.stop)

    def pull(self, spec="o/m", on=None, said=None, tty=True):
        out = io.StringIO()
        asked = []

        def ask(prompt):
            asked.append(prompt)
            return said or ""
        with contextlib.redirect_stdout(out), mock.patch.object(sys.stdin, "isatty", lambda: tty), \
                mock.patch.object(sys.stdout, "isatty", lambda: tty, create=True):
            real = M.choose_machines
            with mock.patch.object(M, "choose_machines", lambda s, o=None, a=None: real(s, o, ask, tty)):
                M.cmd_pull(spec, on=on)
        return out.getvalue(), asked

    def where(self):
        return [(self.hostname(h), s) for h, s in self.pulled]

    def hostname(self, addr):
        return next(r["name"] for r in self.rows if r["addr"] == addr)


class Placement(Base):
    def by(self):
        return {q: (q, s) for q, s, _ in QUANTS}

    def test_the_bigger_gpu_is_the_best_fit_and_ties_go_to_this_computer(self):
        places = {r["name"]: M.placement(r, self.by(), None, "o/m") for r in self.rows}
        self.assertEqual(M.best_machine(self.rows, places), "desktop")
        self.assertEqual(places["phone"]["rank"], 9)
        self.rows[1] = row("desktop", vram=8)
        places = {r["name"]: M.placement(r, self.by(), None, "o/m") for r in self.rows}
        self.assertEqual(M.best_machine(self.rows, places), "local")

    def test_each_machine_gets_the_quantisation_that_fits_it(self):
        small = row("phone", vram=0, ram=11)
        self.assertEqual(M.placement(small, self.by(), None, "o/m")["quant"], "Q3_K_M")     # 6.6 GB runs well
        self.assertEqual(M.placement(self.rows[0], self.by(), None, "o/m")["quant"], "Q4_K_M")
        self.assertEqual(M.placement(small, self.by(), "Q8_0", "o/m")["rank"], 2)             # asked for: too big

    def test_a_full_disk_is_never_the_best_fit(self):
        self.rows[1] = row("desktop", vram=24, free=3)
        places = {r["name"]: M.placement(r, self.by(), None, "o/m") for r in self.rows}
        self.assertEqual(places["desktop"]["rank"], 8)
        self.assertIn("no room", places["desktop"]["word"])
        self.assertEqual(M.best_machine(self.rows, places), "local")

    def test_already_there_is_seen_and_needs_no_room(self):
        r = row("desktop", vram=24, free=3, have=["hf.co/o/m:Q4_K_M"])
        p = M.placement(r, self.by(), "Q4_K_M", "o/m")
        self.assertTrue(p["there"])
        self.assertEqual(p["rank"], 0)

    def test_an_ollama_with_no_recorded_gpu_is_not_known(self):
        r = row("desktop", "ollama", vram=0, ram=0, free=0)
        self.assertEqual(M.placement(r, self.by(), None, "o/m")["rank"], 3)


class PullChoosesAMachine(Base):
    def test_two_machines_and_a_terminal_is_a_question_and_enter_takes_the_best(self):
        out, asked = self.pull()
        self.assertEqual(len(asked), 1)
        self.assertIn("download to [desktop]", asked[0])
        self.assertIn("<- best fit", out)
        self.assertEqual(self.where(), [("desktop", "hf.co/o/m:Q4_K_M")])
        self.assertIn("ready: m-oc@desktop", out)
        self.assertIn("--on desktop", out)

    def test_the_answer_may_be_a_number_a_name_several_or_all(self):
        for said, want in (("1", ["local"]), ("local", ["local"]), ("2,1", ["desktop", "local"]),
                           ("all", ["local", "desktop"])):
            self.pulled.clear()
            self.pull(said=said)
            self.assertEqual([w for w, _ in self.where()], want, said)

    def test_q_downloads_nothing_and_so_does_a_machine_that_is_not_answering(self):
        for said in ("q", "phone", "3", "nonsense"):
            with self.assertRaises(SystemExit):
                self.pull(said=said)
        self.assertEqual(self.pulled, [])

    def test_no_terminal_downloads_here_and_says_the_others_exist(self):
        out, asked = self.pull(tty=False)
        self.assertEqual(asked, [])
        self.assertEqual([w for w, _ in self.where()], ["local"])
        self.assertIn("--on desktop", out)

    def test_one_machine_is_never_a_question(self):
        self.rows[1] = row("desktop", "")
        out, asked = self.pull()
        self.assertEqual(asked, [])
        self.assertEqual([w for w, _ in self.where()], ["local"])

    def test_on_names_the_machines_up_front(self):
        for on, want in (("desktop", ["desktop"]), ("local,desktop", ["local", "desktop"]),
                         ("all", ["local", "desktop"]), ("best", ["desktop"])):
            self.pulled.clear()
            out, asked = self.pull(on=on)
            self.assertEqual(asked, [], on)
            self.assertEqual([w for w, _ in self.where()], want, on)

    def test_on_a_machine_that_is_down_or_unknown_downloads_nothing(self):
        for on in ("phone", "laptop2", "desktop,phone"):
            with self.assertRaises(SystemExit):
                self.pull(on=on)
        self.assertEqual(self.pulled, [])

    def test_no_room_on_the_chosen_machine_downloads_nothing(self):
        self.rows[1] = row("desktop", vram=24, free=3)
        with self.assertRaises(SystemExit) as e:
            self.pull(on="desktop")
        self.assertIn("no room", str(e.exception))
        self.assertEqual(self.pulled, [])

    def test_one_machine_failing_does_not_stop_the_other(self):
        def pull(host, src, show=True):
            if self.hostname(host) == "desktop":
                raise E.EngineError("the model server did not finish")
            self.pulled.append((host, src))
        with mock.patch.object(M.gnoc_engine, "remote_pull", pull):
            with self.assertRaises(SystemExit) as e:
                self.pull(on="all")
        self.assertIn("1 of 2", str(e.exception))
        self.assertEqual([w for w, _ in self.where()], ["local"])

    def test_a_quantisation_the_repo_lacks_is_refused_before_any_question(self):
        with self.assertRaises(SystemExit) as e:
            self.pull("o/m:Q5_K_M")
        self.assertIn("has no Q5_K_M", str(e.exception))


class TheListNamesTheOtherMachines(Base):
    def test_the_list_ends_with_the_other_machines_and_the_commands(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.object(M.gnoc_engine, "who",
                                                                lambda addr, t=2: "ollama" if addr.endswith("42") else ""):
            M._other_machines_line()
        self.assertIn("desktop (answering)", out.getvalue())
        self.assertIn("phone (not answering)", out.getvalue())
        self.assertIn("gnoc models machines", out.getvalue())

    def test_one_machine_adds_no_line(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.object(M, "HOSTS", {"local": "127.0.0.1:1", "desktop": ""}):
            M._other_machines_line()
        self.assertEqual(out.getvalue(), "")


class TheEngineSaysWhatItCanHold(unittest.TestCase):
    def test_machine_reports_gpu_memory_and_disk(self):
        m = E.machine()
        self.assertEqual(m["engine"], "gnoc")
        for k in ("vram", "ram", "disk_free", "models"):
            self.assertIsInstance(m[k], int)
        self.assertGreater(m["disk_free"], 0)

    def test_budget_for_matches_fit_budget_on_this_computer(self):
        self.assertEqual(E.budget_for(E.gpu()[0], E.gpu()[1], E.ram_bytes()), E.fit_budget())


if __name__ == "__main__":
    unittest.main()
