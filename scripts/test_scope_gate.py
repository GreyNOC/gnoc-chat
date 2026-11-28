"""Regression test for .claude/hooks/scope-gate.sh, replayed the way the harness calls it (JSON on stdin, T-152).

Pins both directions: false blocks that derailed agents (reserved RFC 2606 names, code identifiers in a command
that also runs curl) and true blocks (out-of-scope hosts, look-alikes, reserved-suffix bypass shapes). No network:
the hook only parses. No hunt target is set, so every real host must block.

    python3 scripts/test_scope_gate.py
"""
import json
import os
import subprocess
import unittest

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HOOK = os.path.join(WS, ".claude/hooks/scope-gate.sh")

CASES = [  # (label, command, expect_block)
    ("py attr d.get + json", "python3 -c \"import json;d=json.load(open('x'));print(d.get('a'))\"", False),
    ("py attr in heredoc", "python3 - <<'EOF'\nr = G._run_group(['bash','-c','echo out'])\nprint(r.returncode)\nEOF",
     False),
    ("reserved .test url in a local script", "python3 -c \"print(G.target_bytes('https://api.acme.test/n','x'))\"",
     False),
    ("reserved .example host curl", "curl -s https://foo.example/x", False),
    ("reserved .invalid", "curl -s https://a.b.invalid/", False),
    ("example.com", "curl -s https://www.example.com/", False),
    ("curl pipe into python d.get(",
     "curl -s 127.0.0.1:11434/api/show | python3 -c \"import json,sys;d=json.load(sys.stdin);print(d.get('x'))\"",
     False),
    ("grep -nc flag is not netcat", "sed -n 1p f | grep -nc x; python3 -c 'class S(unittest.TestCase): pass'", False),
    ("curl_cffi module name is not curl", "python3 -c 'import curl_cffi; print(self.subTest)'", False),
    ("netcat in a pipe still guesses hosts", "echo x | nc www.paypal.com 443", True),
    ("curl via abs path still guesses hosts", "/usr/bin/curl -s www.paypal.com", True),
    ("curl in subshell still guesses hosts", "x=$(curl -s www.paypal.com)", True),
    ("bypass: fragment .test", "curl -s https://umbrella.com#.test/", True),
    ("bypass: userinfo .test", "curl -s https://x.test@umbrella.com/", True),
    ("bypass: port-ish .test", "curl -s https://umbrella.com:443.test/", True),
    ("bare OOS host with path", "curl -s umbrella.com/x", True),
    ("real OOS host curl", "curl -s https://www.paypal.com/", True),
    ("real OOS bare host curl", "curl -s www.paypal.com", True),
    ("look-alike: test.paypal.com", "curl -s https://test.paypal.com/", True),
    ("look-alike suffix: umbrella.com.test.evil.io", "curl -s https://umbrella.com.test.evil.io/", True),
    # 2026-11-25 false blocks: a file name and a URL placeholder are not hosts (scope-gate.sh, FILE NAMES THAT LOOK
    # LIKE HOSTS and PLACEHOLDERS). The true-positive rows after them pin that the exclusions stay narrow.
    ("receipt: commit naming link-desktop.ps1",
     "git commit -m 'engine: the desktop link script link-desktop.ps1 can run gnoc engine, not curl'", False),
    ("receipt: prompt with the https://<name>/ placeholder", 'gnoc chat -x "fetch https://<name>/ with curl"', False),
    ("path to a .rs source file", "cat src/main.rs; curl --version", False),
    ("ts/tsx source files", "cat app/main.ts web/x.tsx && curl --version", False),
    ("prose host.example.com.md is a file name (.md always a file here)",
     "echo 'see host.example.com.md' && curl --version", False),
    ("still blocks: bare evil.com", "curl -s evil.com", True),
    ("still blocks: x.massive.com.evil.io", "curl -s https://x.massive.com.evil.io/", True),
    ("still blocks: scheme'd .md host", "curl -s https://evil.md/", True),
    ("still blocks: bare .rs host (real ccTLD, not in path position)", "curl -s evil.rs", True),
    ("still blocks: host before a placeholder", "curl -s https://evil.com<x>/", True),
    ("still blocks: host after a placeholder", "curl -s https://<x>evil.com/", True),
    ("still blocks: a ps1 file next to a real URL", "cat Build-It.ps1 && curl https://www.paypal.com/", True),
]


def run(cmd):
    payload = {"tool_name": "Bash", "tool_input": {"command": cmd}, "session_id": "scope-gate-test",
               "cwd": WS}
    env = {k: v for k, v in os.environ.items() if k != "HUNT_TARGET"}
    p = subprocess.run(["bash", HOOK], input=json.dumps(payload), capture_output=True, text=True, env=env, cwd=WS)
    return p.returncode, (p.stderr or p.stdout).strip()[:160]


class ScopeGate(unittest.TestCase):
    def test_cases(self):
        for label, cmd, expect in CASES:
            with self.subTest(label):
                rc, msg = run(cmd)
                self.assertEqual(rc == 2, expect, f"{label}: {msg}")


if __name__ == "__main__":
    unittest.main()
