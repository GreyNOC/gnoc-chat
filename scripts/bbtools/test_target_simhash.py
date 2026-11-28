#!/usr/bin/env python3
"""Offline tests for target_simhash (synthetic responses, no network)."""
import os, shutil, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import target_simhash as t

t.selfcheck()
# default_hosts reads recon/*hosts*, filters through program_allows, skips comments
root = tempfile.mkdtemp()
try:
    d = os.path.join(root, "targets", "px"); os.makedirs(os.path.join(d, "recon"))
    open(os.path.join(d, "SCOPE.txt"), "w").write("WILDCARD *.acme.example\n")
    open(os.path.join(d, "recon", "live-hosts.txt"), "w").write("# c\nhttps://a.acme.example/x 200\nb.acme.example\noffscope.example\n")
    assert t.default_hosts("px", root) == ["a.acme.example", "b.acme.example"]

    class R:
        def __init__(s, body): s.text, s.status_code, s.headers = body, 200, {"content-type": "text/html"}
    class S:
        def get(s, url, **kw):
            if "dead" in url: raise OSError("dns")
            return R("<title>App</title>" + "same page body words here " * 20)
    res = t.dedup("px", ["a.acme.example", "b.acme.example", "dead.acme.example"], root=root, session=S())
    assert [len(c["members"]) for c in res["clusters"]] == [2, 1], res["clusters"]
    assert os.path.exists(os.path.join(d, "recon", "simhash.json"))
finally:
    shutil.rmtree(root, ignore_errors=True)
print("test_target_simhash: ALL ASSERTIONS PASS")
