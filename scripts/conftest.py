"""pytest setup for a release tree (`cd scripts && python3 -m pytest -q`).

1. Collection. The release ships the whole hunt harness, and some of its folders hold test INPUTS, not tests: a
   fixture that fails on purpose (learn/fixtures/failing, the soak's error-recovery batch), recorded tool output,
   self-test apps. pytest would collect them because they are named test_*.py, so they are left out by folder.

2. The workspace. A release tree run in place is its own workspace (scripts/.. , as in every module's WS default).
   An installed copy gets its folders and its hooks link from the launcher before the first chat; a test run never
   starts the launcher, so the same step (gnoc_setup.ensure_workspace) runs here first. The harness tests then meet
   the workspace a fresh install has, with the shipped scope-gate hook where the code looks for it. GNOC_WORKSPACE,
   when set, wins.

3. Tests that need the operator's own workspace. The harness's tests were written in that workspace, and a few read
   what never ships: the knowledge base (SPINE.md, Manual/, patterns/), real programs under targets/, the reports
   dashboard, his private machine addresses and his own wording, which the release rewrites. Each one is listed in
   release-test-denylist.txt with the reason, deselected here, and counted in the run's header, never skipped
   silently. A listed test that no longer exists is reported too.
"""
import os
import sys

collect_ignore_glob = ["*/fixtures/*", "*/selftest/*"]

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
_DENYLIST = os.path.join(_HERE, "release-test-denylist.txt")
_STATE = {"denied": {}, "deselected": 0, "unused": []}


def _read_denylist():
    out = {}
    try:
        with open(_DENYLIST, encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.rstrip("\n")
                if ln and not ln.startswith("#") and "\t" in ln:
                    node, why = ln.split("\t", 1)
                    out[node.strip()] = why.strip()
    except OSError:
        pass
    return out


def pytest_configure(config):
    import gnoc_setup
    ws = os.environ.get("GNOC_WORKSPACE") or os.path.dirname(_HERE)
    gnoc_setup.ensure_workspace(ws, os.path.dirname(_HERE))
    _STATE["denied"] = _read_denylist()


def pytest_collection_modifyitems(config, items):
    denied = _STATE["denied"]
    if not denied:
        return
    keep, drop, used = [], [], set()
    for item in items:
        hit = next((n for n in denied if item.nodeid == n or item.nodeid.startswith(n + "::")
                    or item.nodeid.startswith(n + "[")), None)
        if hit:
            drop.append(item)
            used.add(hit)
        else:
            keep.append(item)
    if drop:
        config.hook.pytest_deselected(items=drop)
        items[:] = keep
    _STATE["deselected"] = len(drop)
    # only meaningful when the whole suite was collected (a run of one file uses a few entries)
    _STATE["unused"] = sorted(n for n in denied if n not in used and n.split("::")[0] in {i.nodeid.split("::")[0]
                                                                                        for i in keep + drop})


def pytest_report_collectionfinish(config, start_path, items):
    n = _STATE["deselected"]
    lines = []
    if n:
        lines.append(f"release: {n} test(s) need the operator's own workspace and are deselected "
                     f"(scripts/release-test-denylist.txt says why for each)")
    if _STATE["unused"]:
        lines.append("release: denylist entries that match no test: " + ", ".join(_STATE["unused"][:10]))
    return lines
