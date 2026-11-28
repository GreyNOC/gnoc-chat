"""scope-gate.sh: the false positives fixed 2026-10-27, and proof the true positives still block.

Receipt. The gate fires on any dotted token in a Bash command when the command mentions curl/dig/etc.
That caught things that are not hosts at all: `outcomes.jsonl` and `trajectories.jsonl` (".jsonl" was
missing from the extension list), `2.0.alpha` (a version string), and `noreply@anthropic.com` (an email
address, whose domain part parses as a bare apex that is genuinely out of scope). Measured five times in
one session, and lane F reported it independently: "it currently makes writing an honest SSRF receipt
harder than firing the SSRF". That matters beyond friction - a safety gate that fires on prose teaches
agents to route around it, which is the one habit we must not train.

These tests are the reason the fix is safe to keep: the second class pins that a real out-of-scope host,
an IP literal, and an SSRF metadata address still BLOCK. If a future edit widens the exclusions far
enough to let one of those through, these fail.
"""
import os
import subprocess
import unittest

WS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(WS, ".claude", "hooks", "scope-gate.sh")


def gate(command, program="anthropic"):
    """(blocked, stderr) for a Bash tool call carrying `command`."""
    payload = ('{"tool_name":"Bash","tool_input":{"command":%s}}'
               % __import__("json").dumps(command))
    env = dict(os.environ, HUNT_TARGET=program)
    r = subprocess.run(["bash", GATE], input=payload, text=True, capture_output=True,
                       cwd=WS, env=env, timeout=60)
    return r.returncode != 0, (r.stderr or "")


class NotHosts(unittest.TestCase):
    """A token that is not a hostname must not block a non-probe command."""

    def test_a_jsonl_ledger_name_is_not_a_host(self):
        blocked, err = gate("curl -s localhost >/dev/null; wc -l .claude/state/hunt-loop/outcomes.jsonl")
        self.assertFalse(blocked, err)

    def test_a_trajectories_ledger_name_is_not_a_host(self):
        blocked, err = gate("echo 'see state/orch/agent/trajectories.jsonl' && curl --version")
        self.assertFalse(blocked, err)

    def test_a_version_string_is_not_a_host(self):
        blocked, err = gate("echo 'api version 2.0.alpha and 1.0.rc1' && curl --version")
        self.assertFalse(blocked, err)

    def test_an_email_address_is_not_a_host(self):
        """A commit message or report body naming an address must not be refused."""
        blocked, err = gate("git commit -m 'fix. Co-Authored-By: x <noreply@anthropic.com>' && curl --version")
        self.assertFalse(blocked, err)


OOS_HOST = "oos-host-not-in-any-scope.com"
NESTED_HOST = "umbrella.com.test.evil-oos-host.com"


class TrailingPunctuationIsNotPartOfTheHost(unittest.TestCase):
    """QAQC 2026-11-03. The scheme'd extractor stops only at / space quote backtick, so a URL with NO
    PATH kept whatever prose punctuation followed it: `https://app.example.com,` parsed as the host
    `app.example.com,`. That token missed the RFC 2606 reserved-name drop (which requires the WHOLE token to
    be a hostname) and could never match a scope row, so the gate hard blocked `app.example.com,` as out of
    scope against program-63's OWN SCOPE.txt - it blocked the programme's primary in-scope asset, and it
    blocked the reserved-name forms the drop exists to allow. With a path (`https://app.example.com/casino,`)
    every case already passed, because / ends the match, which is why this went unseen. The last test
    is the other half: stripping to the last alphanumeric makes a token MORE canonical, so nothing out
    of scope gets through."""

    def test_an_in_scope_host_followed_by_a_comma_passes(self):
        blocked, err = gate("curl https://app.example.com,", program="program-63")
        self.assertFalse(blocked, err)

    def test_an_in_scope_host_followed_by_a_full_stop_passes(self):
        blocked, err = gate("curl https://app.example.com.", program="program-63")
        self.assertFalse(blocked, err)

    def test_an_in_scope_host_in_parentheses_passes(self):
        blocked, err = gate("curl (https://app.example.com)", program="program-63")
        self.assertFalse(blocked, err)

    def test_a_reserved_name_followed_by_punctuation_passes(self):
        for cmd in ("curl https://evil.example, then the control",
                    "curl https://attacker.invalid)",
                    "curl https://api.acme.test;",
                    "curl https://thing.localhost."):
            blocked, err = gate(cmd, program="program-63")
            self.assertFalse(blocked, f"{cmd}: {err}")

    def test_a_port_survives_the_strip(self):
        """:8080 ends in a digit, so nothing is stripped and the port logic still sees it."""
        blocked, err = gate("curl https://app.example.com:8080/casino", program="program-63")
        self.assertFalse(blocked, err)

    def test_punctuation_does_not_smuggle_an_out_of_scope_host_through(self):
        for cmd in ("curl https://%s," % OOS_HOST,
                    "curl https://%s)" % OOS_HOST,
                    "curl https://%s," % NESTED_HOST):
            blocked, err = gate(cmd, program="program-63")
            self.assertTrue(blocked, f"{cmd} must still block")


class RegexEscapedDots(unittest.TestCase):
    """2026-11-10: the scheme'd extractor keeps everything up to / space quote backtick, so a Python
    regex over a URL (`re.search(r"https://scrm-x\\.brand\\.com\\.cn/api", raw)`) reached the scope
    match as `scrm-x\\.brand\\.com\\.cn`, matched no row, and a LOCAL grep over the lane's own raw
    captures was hard blocked as an out-of-scope probe on program-50, whose SCOPE.txt carries the
    `*.app.example.com` wildcard. A backslash is never part of a hostname, so stripping it makes
    the token MORE canonical: the in-scope forms pass, and the last test pins that an out-of-scope host
    in the same shapes still blocks."""

    IN = "app.example.com"
    OOS = "evil-not-in-scope.io"

    @staticmethod
    def raw(h):
        return h.replace(".", "\\.")

    @staticmethod
    def nonraw(h):
        return h.replace(".", "\\\\.")

    def test_a_raw_string_regex_over_an_in_scope_host_passes(self):
        cmd = "python3 - <<'EOF'\nimport re\nre.search(r\"https://%s/api\", open('raw.json').read())\nEOF" % self.raw(self.IN)
        blocked, err = gate(cmd, program="program-50")
        self.assertFalse(blocked, err)

    def test_a_non_raw_string_regex_over_an_in_scope_host_passes(self):
        cmd = "python3 - <<'EOF'\nimport re\nre.search(\"https://%s/api\", open('raw.json').read())\nEOF" % self.nonraw(self.IN)
        blocked, err = gate(cmd, program="program-50")
        self.assertFalse(blocked, err)

    def test_an_escaped_out_of_scope_host_still_blocks(self):
        for cmd in ("python3 - <<'EOF'\nimport re\nre.search(r\"https://%s/\", 'x')\nEOF" % self.raw(self.OOS),
                    "python3 - <<'EOF'\nimport re\nre.search(\"https://%s/\", 'x')\nEOF" % self.nonraw(self.OOS),
                    "curl -s https://%s/" % self.raw(self.OOS)):
            blocked, err = gate(cmd, program="program-50")
            self.assertTrue(blocked, f"{cmd!r} must still block")
            self.assertIn(self.OOS, err, "the refusal names the canonical host, no backslashes")


class FileNamesAndPlaceholders20261125(unittest.TestCase):
    """2026-11-25 receipts. (1) A commit message naming `link-desktop.ps1` was refused as "OOS host
    link-desktop.ps": the TLD class stopped before the digit and kept a prefix of the word. (2) A prompt naming
    the template `https://<name>/` was refused as "OOS host <name". Decision, documented in the gate: a token
    whose last label holds a digit or "_" is no hostname; .ps/.rs (real ccTLDs) are files only in path position;
    .md/.sh/.py stay always-a-file in the scheme-less branch as before, while a scheme'd URL on such a host is
    always checked; < and > are cut out and the fixed parts on each side are still checked."""

    def test_the_two_receipts_pass(self):
        for cmd in ("git commit -m 'engine: CUDA build on Windows; the desktop link script link-desktop.ps1 can "
                    "run gnoc engine, not curl'",
                    'gnoc chat -s-p -x "fetch https://<name>/ and report with curl"'):
            blocked, err = gate(cmd)
            self.assertFalse(blocked, f"{cmd!r}: {err}")

    def test_a_dotted_prose_file_name_passes(self):
        blocked, err = gate("echo 'see host.example.com.md and src/lib.rs' && curl --version")
        self.assertFalse(blocked, err)

    def test_real_hosts_still_block(self):
        for cmd, host in (("curl -s evil.com", "evil.com"),
                          ("curl -s https://x.massive.com.evil.io/", "x.massive.com.evil.io"),
                          ("curl -s https://evil.md/", "evil.md"),
                          ("curl -s evil.rs", "evil.rs"),
                          ("curl -s https://evil.com<x>/", "evil.com"),
                          ("curl -s https://<x>evil.com/", "evil.com")):
            blocked, err = gate(cmd)
            self.assertTrue(blocked, f"{cmd!r} must still block")
            self.assertIn(host, err)


class StillBlocks(unittest.TestCase):
    """The reason the exclusions above are safe. Do not let these start passing."""

    def test_a_real_out_of_scope_host_blocks(self):
        blocked, _ = gate("curl -s https://evil-not-in-scope.io/")
        self.assertTrue(blocked, "an out-of-scope host must be refused")

    def test_a_scheme_less_out_of_scope_host_blocks(self):
        blocked, _ = gate("curl -s evil-not-in-scope.io/path")
        self.assertTrue(blocked, "a bare out-of-scope host must be refused")

    def test_another_programs_host_blocks(self):
        blocked, _ = gate("curl -s https://www.otherprog-shop.com/")
        self.assertTrue(blocked, "a host from a different program must be refused")

    def test_the_imds_metadata_address_blocks(self):
        blocked, _ = gate("curl -s http://169.254.169.254/latest/meta-data/")
        self.assertTrue(blocked, "the cloud metadata address must be refused")

    def test_an_in_scope_host_passes(self):
        blocked, err = gate("curl -s https://api.program-0.example/v1/x")
        self.assertFalse(blocked, err)

    def test_an_operator_approved_successor_host_passes(self):
        """Added by the user's 2026-10-27 ruling; if SCOPE.txt loses the row this fails loudly."""
        blocked, err = gate("curl -s https://platform.claude.com/")
        self.assertFalse(blocked, err)

    def test_a_referenced_but_unapproved_host_blocks(self):
        """admin.claude.com was only named in a config blob, never a redirect target: still out."""
        blocked, _ = gate("curl -s https://admin.claude.com/")
        self.assertTrue(blocked, "an unapproved host must stay refused")


if __name__ == "__main__":
    unittest.main()
