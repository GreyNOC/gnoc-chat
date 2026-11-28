"""gnoc_testenv.py - point every piece of gnoc chat's live state at a throwaway directory for a test run.

The suites used to leave real files behind: nosid checkpoints, SAST output, and a rewrite of the live lesson book
(measured 2026-10-22 by snapshotting .claude/state before and after a full run). Call start() from setUpModule and
stop() from tearDownModule; a test that needs its own temp dir still makes one.
"""
import shutil
import tempfile

_SAVED = []


def start():
    import gnoc_agent as G
    import gnoc_learn as L
    import os
    d = tempfile.mkdtemp(prefix="gnoc-test-state-")
    agent = os.path.join(d, "agent")
    os.makedirs(agent)
    names = {"AGENT_DIR": agent, "SESSION": os.path.join(agent, "session.json"),
             "OUT_DIR": os.path.join(agent, "out"), "JOBS_DIR": os.path.join(agent, "jobs"),
             "SESSIONS_DIR": os.path.join(agent, "sessions"), "TASKS": os.path.join(d, "tasks.jsonl")}
    saved = {k: getattr(G, k) for k in names if hasattr(G, k)}
    for k, v in names.items():
        if k in saved:
            setattr(G, k, v)
    import llm_endpoints
    saved["__stock_disk"] = llm_endpoints.STOCK_DISK
    llm_endpoints.STOCK_DISK = os.path.join(d, "stock-verdicts.json")
    book = L.isolated(os.path.join(d, "lessons"))
    os.makedirs(os.path.join(d, "lessons"))
    book.__enter__()
    _SAVED.append((G, saved, book, d))
    return d


def stop():
    while _SAVED:
        G, saved, book, d = _SAVED.pop()
        import llm_endpoints
        llm_endpoints.STOCK_DISK = saved.pop("__stock_disk", llm_endpoints.STOCK_DISK)
        for k, v in saved.items():
            setattr(G, k, v)
        book.__exit__(None, None, None)
        shutil.rmtree(d, ignore_errors=True)
