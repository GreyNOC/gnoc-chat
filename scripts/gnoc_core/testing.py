"""Test discovery and invocation: find the tests that cover a change, and never run a Python test file bare."""
import json
import os
import re
import sys

from .util import _read


_TEST_DIRS = ("test", "tests", "__tests__", "spec")


_TEST_NAME = re.compile(r"(?:\.(?:test|spec)\.(?:mjs|cjs|jsx?|tsx?)|^test_.+\.py$|_test\.go$|"
                        r"(?:^|/)test_[^/]+\.py$|\.test\.py$|(?:^|/)[^/]+_test\.py$)", re.I)   # pytest collects foo_test.py


_STOPWORDS = frozenset(("test", "tests", "spec", "index", "src", "lib", "util", "utils",
                        "helper", "helpers", "common", "base", "mod", "js", "mjs", "cjs", "ts",
                        "py", "go", "new", "old", "tmp", "build", "dist", "public",
                        "scripts", "script", "integration", "unit"))


_KIND_TESTS = {".css": ("css",), ".scss": ("css",), ".html": ("dom", "xss", "html"),
               ".htm": ("dom", "xss", "html"), ".ejs": ("dom", "xss"), ".hbs": ("dom", "xss"),
               ".svg": ("icons", "asset"), ".json": ("manifest", "data")}


def _tokens(name):
    """Meaningful lowercase word-parts of a filename, longest first ('reel-capture' -> reel, capture)."""
    base = os.path.basename(name)
    base = re.sub(r"\.(test|spec)\.[a-z]+$", "", base, flags=re.I)
    base = re.sub(r"\.[A-Za-z0-9]+$", "", base)
    parts = [p.lower() for p in re.split(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])", base) if p]
    return sorted({p for p in parts if len(p) > 2 and p not in _STOPWORDS}, key=len, reverse=True)


def find_test_files(r, limit=4000):
    """Every test file in the repo's own test trees, skipping vendored ones. Bounded. The conventional folders
    (test/, tests/, __tests__/, spec/) at any depth, and test files sitting beside the code (scripts/test_*.py,
    pkg/foo_test.go): only top-level folders were walked, so most repos (this one included) found nothing for
    run_tests files=['auto'] (QAQC 2026-11-19)."""
    out = []
    skip = {"node_modules", "__pycache__", ".git", "fixtures", ".venv", "venv", "dist", "build", ".tox", "vendor",
            "target", ".next", "coverage"}
    base = r.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(r):
        dirnames[:] = sorted(x for x in dirnames if x not in skip and not x.startswith("."))
        if dirpath.count(os.sep) - base > 6:
            dirnames[:] = []
        for f in filenames:
            if _TEST_NAME.search(f):
                out.append(os.path.join(dirpath, f))
                if len(out) >= limit:
                    return out
    return out


def tests_for(r, changed, cap=6):
    """The test files that most likely COVER `changed`, narrowest first. [] when nothing matches.

    WHY THIS EXISTS (2026-10-27). detect_tests() answers with the repo's WHOLE-SUITE command, and on a
    real site that is unusable as a per-change check: the website's `npm test` chains about 200 node test
    files behind a 25-file `pretest`, so a one-line fix either times out or drowns in failures that have
    nothing to do with it - and T-269 says a change that was not RUN is a claim, not a change. Matching
    the changed file's name-parts against the test tree's turns that into seconds: `lib/censor.js` ->
    `test/censor.test.mjs`, `scripts/video/reel/*` -> `test/reel-lint.test.mjs` + `test/reel-capture.test.mjs`.
    Name-overlap is a heuristic, so this RANKS rather than decides, and the whole suite stays one call away.
    """
    changed = [changed] if isinstance(changed, str) else list(changed or [])
    pool = find_test_files(r)
    if not pool or not changed:
        return []
    scored = {}
    for f in changed:
        want = set(_tokens(f))
        if not want:
            continue
        stem = os.path.splitext(os.path.basename(f))[0].lower()
        for t in pool:
            have = set(_tokens(t))
            shared = want & have
            if not shared:
                continue
            # a longer shared word is stronger evidence ('greypath' beats 'data'); an exact stem match wins
            score = sum(len(w) for w in shared) + (20 if stem and stem in os.path.basename(t).lower() else 0)
            scored[t] = max(scored.get(t, 0), score)
    if not scored:
        # nothing shares a name: fall back to the FILE KIND, so a stylesheet still gets the css tests
        kinds = {k for f in changed for k in _KIND_TESTS.get(os.path.splitext(f)[1].lower(), ())}
        for t in pool:
            base = os.path.basename(t).lower()
            hit = [k for k in kinds if k in base]
            if hit:
                scored[t] = max(len(k) for k in hit)
    ranked = sorted(scored, key=lambda t: (-scored[t], len(t)))
    return [os.path.relpath(t, r) for t in ranked[:cap]]


def narrow_test_hint(r, changed):
    """One line naming the cheapest real check for `changed`, or '' - for the verify nudge."""
    picked = tests_for(r, changed)
    if not picked:
        return ""
    return ("the tests that look like they cover this: run_tests(files=" + json.dumps(picked[:4])
            + ") - far cheaper than the whole suite, and it is the change you need to see pass")


def detect_tests(r):
    """The repo's own full-suite test command, or None."""
    pj = os.path.join(r, "package.json")
    if os.path.isfile(pj):
        try:
            if (json.loads(_read(pj)).get("scripts") or {}).get("test"):
                return "npm test"
        except ValueError:
            pass
    for name in ("GNOC.md", "CLAUDE.md"):
        m = re.search(r"(?im)^\s*(?:-\s*)?tests?:\s*`([^`]+)`", _read(os.path.join(r, name)))
        if m:
            return m.group(1)
    if os.path.isfile(os.path.join(r, "pytest.ini")) or "[tool.pytest" in _read(os.path.join(r, "pyproject.toml")):
        return "python3 -m pytest -q"
    if re.search(r"(?m)^test:", _read(os.path.join(r, "Makefile"))):
        return "make test"
    if os.path.isfile(os.path.join(r, "go.mod")):
        return "go test ./..."
    if os.path.isfile(os.path.join(r, "Cargo.toml")):
        return "cargo test"
    # A plain Python repo with test_*.py and no runner config (the common small-project shape) used to answer
    # "no test command found" and the model gave up on verifying its fix (driven 2026-10-24). Look two levels
    # deep, skipping vendored trees, so a big repo costs a bounded walk.
    skip = {".git", "node_modules", ".venv", "venv", "__pycache__", "build", "dist", ".tox"}
    base = r.rstrip(os.sep).count(os.sep)
    for d, dirs, names in os.walk(r):
        dirs[:] = [x for x in dirs if x not in skip and not x.startswith(".")]
        if d.count(os.sep) - base >= 2:
            dirs[:] = []
        if any(re.match(r"(test_.*|.*_test)\.py$", n) for n in names):
            return "python3 -m pytest -q" if _have_pytest(r) else "python3 -m unittest discover -v"
    return None


_PY_TEST_SHIM = r"""
import importlib.util, inspect, os, sys, traceback, unittest
sys.path.insert(0, os.getcwd())
path = sys.argv[1]
spec = importlib.util.spec_from_file_location("_gnoc_testmod", path)
mod = importlib.util.module_from_spec(spec)
sys.modules["_gnoc_testmod"] = mod
try:
    spec.loader.exec_module(mod)
except SystemExit as e:
    # a script-style test file that chooses its own exit code (sys.exit(0) = pass, sys.exit(N) = fail):
    # honour it exactly, the way `python3 <file>` always did
    sys.exit(e.code if isinstance(e.code, int) else (0 if e.code is None else 1))
except BaseException:
    traceback.print_exc()
    print("COLLECT ERROR: the test module raised while importing")
    sys.exit(1)
fails, ran, skipped = [], 0, 0
suite = unittest.defaultTestLoader.loadTestsFromModule(mod)
if suite.countTestCases():
    res = unittest.TextTestRunner(verbosity=1).run(suite)
    ran += suite.countTestCases()
    if not res.wasSuccessful():
        fails.append("unittest: %d failure(s), %d error(s)" % (len(res.failures), len(res.errors)))
# pytest-style classes (class TestX: def test_y(self)) that are not unittest.TestCase: they passed as "no test
# functions" before (QAQC r2)
for cname in sorted(vars(mod)):
    cls = getattr(mod, cname)
    if cname.startswith("Test") and inspect.isclass(cls) and cls.__module__ == mod.__name__ \
            and not issubclass(cls, unittest.TestCase):
        for mname in sorted(vars(cls)):
            meth = getattr(cls, mname)
            if mname.startswith("test") and callable(meth):
                if len(inspect.signature(meth).parameters) > 1:
                    skipped += 1
                    continue
                ran += 1
                try:
                    inst = cls()
                    if hasattr(inst, "setup_method"):
                        inst.setup_method(meth)
                    getattr(inst, mname)()
                except BaseException as e:
                    fails.append("%s.%s: %s: %s" % (cname, mname, type(e).__name__, e))
                    traceback.print_exc()
for name in sorted(vars(mod)):
    fn = getattr(mod, name)
    if name.startswith("test") and inspect.isfunction(fn) and fn.__module__ == mod.__name__:
        if list(inspect.signature(fn).parameters):
            skipped += 1   # takes a fixture/param: only pytest can supply it, and pytest is absent
            continue
        ran += 1
        try:
            if inspect.iscoroutinefunction(fn):
                import asyncio
                asyncio.run(fn())   # calling it only built a coroutine: its asserts never ran (QAQC 2026-11-19)
            elif inspect.isgeneratorfunction(fn):
                for _ in fn():   # a generator test runs when iterated
                    pass
            else:
                fn()
        except BaseException as e:
            fails.append("%s: %s: %s" % (name, type(e).__name__, e))
            traceback.print_exc()
if fails:
    print("ran %d test(s), %d FAILING" % (ran, len(fails)))
    for f in fails:
        print("  FAIL", f)
    sys.exit(1)
if ran:
    print("ran %d test(s), all passing" % ran)
    sys.exit(0)
if skipped:
    print("CANNOT VERIFY: %d test(s) need pytest (fixtures/params) and pytest is not installed" % skipped)
    sys.exit(1)
print("ran as a script with no test functions; it imported cleanly")
sys.exit(0)
"""


def project_python(r=None):
    """The interpreter that runs THIS project's code: its own .venv / venv / env first, then the python3 on the
    user's PATH (gnoc's private environment taken off it), and gnoc's own interpreter only as a last resort. It used
    to be sys.executable always: in the public build that is gnoc's private venv, which has no pytest and none of
    the project's dependencies (2026-11-20 public-edition drive: "No module named pytest")."""
    import shutil
    win = os.name == "nt"
    for sub in (".venv", "venv", "env"):
        # a Windows venv keeps its interpreter in Scripts\python.exe, a POSIX one in bin/python
        cand = (os.path.join(r, sub, "Scripts", "python.exe") if win else os.path.join(r, sub, "bin", "python")) if r else ""
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    try:
        import gnoc_secrets
        path = gnoc_secrets.user_env().get("PATH")
    except Exception:  # noqa: BLE001
        path = None
    for name in ("python3", "python"):
        got = shutil.which(name, path=path)
        # the Microsoft Store "python" stub (WindowsApps) only opens the Store: never a project's interpreter
        if got and not (win and "windowsapps" in got.lower()):
            return got
    return sys.executable


_HAS_MOD = {}


def _py_has(py, mod):
    """Whether interpreter `py` can import `mod` (asked once per interpreter)."""
    key = (py, mod)
    if key not in _HAS_MOD:
        if os.path.realpath(py) == os.path.realpath(sys.executable):
            import importlib.util
            _HAS_MOD[key] = importlib.util.find_spec(mod) is not None
        else:
            import subprocess
            try:
                _HAS_MOD[key] = subprocess.run([py, "-c", f"import {mod}"], capture_output=True, timeout=30,
                                               stdin=subprocess.DEVNULL).returncode == 0
            except (OSError, subprocess.SubprocessError):
                _HAS_MOD[key] = False
    return _HAS_MOD[key]


def _have_pytest(r=None):
    return _py_has(project_python(r), "pytest")


def _py_test_argv(path, r=None):
    """How to actually RUN a Python test file: pytest when present, else the executing shim (never bare
    `python3 <file>`, which silently skips every pytest-style test and reports success)."""
    py = project_python(r)
    if _py_has(py, "pytest"):
        return [py, "-m", "pytest", "-q", path]
    return [py, "-c", _PY_TEST_SHIM, path]


def _js_runner(r):
    """'vitest' | 'jest' | None: the JS test runner the repo declares (package.json deps or scripts.test)."""
    try:
        pj = json.loads(_read(os.path.join(r, "package.json")) or "{}")
    except ValueError:
        return None
    deps = {**(pj.get("dependencies") or {}), **(pj.get("devDependencies") or {})}
    test = str((pj.get("scripts") or {}).get("test") or "")
    for name in ("vitest", "jest"):
        if name in deps or re.search(rf"\b{name}\b", test):
            return name
    return None


def _have_cov(r=None):
    return _py_has(project_python(r), "pytest_cov")


def test_argv(r, path, name=None, coverage=False):
    """(argv, note) to run ONE test file, optionally only the tests matching `name`; argv None + the reason when
    this file type cannot be run here. `name` is a substring / pattern in the runner's own syntax."""
    ext = os.path.splitext(path)[1].lower()
    rel = os.path.relpath(path, r)
    name = str(name or "").strip() or None
    note = ""
    if ext == ".py":
        py = project_python(r)
        if not _py_has(py, "pytest"):
            if name or coverage:
                note = "pytest is not installed, so name= / coverage= were ignored and the whole file ran"
            return [py, "-c", _PY_TEST_SHIM, path], note
        argv = [py, "-m", "pytest", "-q", path]
        if name:
            argv += ["-k", name]
        if coverage:
            if _have_cov(r):
                argv += ["--cov", "--cov-report=term-missing:skip-covered"]
            else:
                note = "coverage needs pytest-cov (pip install pytest-cov); ran without it"
        return argv, note
    if ext in (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"):
        runner = _js_runner(r)
        if runner:
            argv = ["npx", "--no-install", runner] + (["run"] if runner == "vitest" else []) + [rel]
            if name:
                argv += ["-t", name]
            if coverage:
                argv.append("--coverage")
            return argv, note
        if ext in (".ts", ".tsx", ".mts", ".cts"):
            tsx = os.path.join(r, "node_modules", ".bin", "tsx")
            if not os.path.isfile(tsx):
                return None, ("no runner for a TypeScript test here: the repo declares neither vitest nor jest and "
                              "has no tsx (npm i -D tsx), so name the suite instead (omit files)")
            argv = [tsx, "--test"]
        else:
            argv = ["node"] + (["--test"] if name or coverage else [])
        if name:
            argv.append(f"--test-name-pattern={name}")
        if coverage:
            argv.append("--experimental-test-coverage")
        return argv + [path], note
    if ext == ".go":
        pkg = "./" + (os.path.dirname(rel) or ".")
        argv = ["go", "test", pkg]
        if name:
            argv += ["-run", name]
        if coverage:
            argv.append("-cover")
        return argv, note
    if ext == ".rs":
        argv = ["cargo", "test"]
        parts = rel.split(os.sep)
        if parts[0] == "tests" and len(parts) == 2:
            argv += ["--test", os.path.splitext(parts[1])[0]]
        if name:
            argv.append(name)
        if coverage:
            note = "coverage for Rust needs cargo-llvm-cov or tarpaulin; ran without it"
        return argv, note
    if ext == ".sh":
        return ["bash", path], ("name= is ignored for a shell test" if name else "")
    return None, f"do not know how to run {rel} (python, js/ts, go, rust and bash test files; or omit files for the suite)"


def suite_with_name(cmd, name):
    """The whole-suite command narrowed to tests matching `name`, when the runner is recognisable."""
    if not name:
        return cmd, ""
    q = "'" + str(name).replace("'", "'\\''") + "'"
    if "pytest" in cmd:
        return f"{cmd} -k {q}", ""
    if cmd.startswith("go test"):
        return f"{cmd} -run {q}", ""
    if cmd.startswith("cargo test"):
        return f"{cmd} {q}", ""
    if cmd.startswith("npm test"):
        return f"{cmd} -- -t {q}", "name passed to the npm test script as -t (jest/vitest syntax)"
    return cmd, f"name= ignored: cannot narrow `{cmd}` to one test"
