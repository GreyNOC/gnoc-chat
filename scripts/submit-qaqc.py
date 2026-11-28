#!/usr/bin/env python3
"""Pre-submission QAQC gate. The user 2026-10-10.

Run this on a report BEFORE any submission. It is a BLOCKER, not advice.
  scripts/submit-qaqc.py reports/drafts/<program>/<slug>/report.md

Checks three things the user named plus the format caps:
  1. INTERNAL NOTES - workspace artifacts that must never reach a triager
  2. AI SLOP - tells that make a report read as machine-written
  3. SEVERITY - authorization is HIGH or CRITICAL only (CVSS >= 7.0)
Exit 0 = clean. Exit 1 = BLOCKED, do not submit.
"""
import re, sys, os, unicodedata

# --- 1. INTERNAL NOTES: workspace leakage. Each has cost us a report or nearly did.
INTERNAL = [
    (r'(?m)^\s*Gate:', 'Gate: stamp (internal gate state)'),
    (r'(?m)^\s*Dedup:', 'Dedup: stamp (internal dedup state)'),
    (r'ESCALATION TARGET:', 'escalation target line'),
    (r'\*\*Unlock:', 'HELD unlock line'),
    (r'NOT-YET-RUN', 'gate NOT-YET-RUN marker'),
    # CASE-SENSITIVE on purpose: every other row here is matched with re.I, but a real HELD marker is the
    # uppercase status word, while "held" is ordinary English that a PoC says constantly ("the gate held").
    # Matched case-insensitively this fired on four honest drafts and taught the writer to avoid a normal verb.
    (r'(?-i:\bHELD\b)', 'HELD status marker'),
    (r'~/', 'absolute workspace path'),
    (r'(?<![\w/])(targets|reports|patterns|salvage)/', 'workspace directory path'),
    (r'\b(GATES|STATUS|HELD-REASON|KILL-PASS|REPRO-CHECK|DEDUP)\.md\b', 'internal sidecar filename'),
    (r'\bprobeLog\b|\bprobe count\b|\bfloor=met\b', 'probe-log bookkeeping'),
    (r'(?m)^\s*digest\s*$', 'worker digest header'),
    (r'\b(report-killer|report-writer|dedup-scout|triage-validator|reviewer-agent|'
     r'cvss-scorer|recon-scout|target-modeler|hypothesis-generator|repro-checker)\b', 'agent name'),
    (r'\bsub-?agent\b|\borchestrator\b|\bthis lane\b|\bthe lane\b|\bmy brief\b', 'internal process language'),
    (r'(?m)^\s*/(persist|pivot|report|slim|trim|dig|hyp)\b', 'slash command'),
    (r'SPINE|CLAUDE\.md|do-not-rehunt|hunt-loop', 'internal doctrine reference'),
    (r'OVERRIDE-DRAFT-GATE', 'draft-gate override sentinel'),
]

# --- 2. AI SLOP: register tells. GreyNOC: nobody should be able to tell this is AI.
SLOP = [
    (r'\u2014', 'em dash'),
    (r'\bdelve\b|\bdelving\b', '"delve"'),
    (r"\bit'?s worth noting\b|\bit is worth noting\b", '"worth noting" filler'),
    (r'\bit is important to note\b|\bimportantly,', '"important to note" filler'),
    (r'\bin conclusion\b|\bto summarize\b|\bin summary,', 'essay-style closer'),
    (r'\bfurthermore\b|\bmoreover\b', 'formal connective filler'),
    (r'\badditionally,', '"Additionally," opener'),
    (r'\brobust\b|\bseamless\b|\bleverage[ds]?\b|\butilize[ds]?\b', 'corporate filler word'),
    (r'\bcomprehensive\b|\bholistic\b|\bmultifaceted\b', 'padding adjective'),
    (r'\bas an AI\b|\bI hope this helps\b|\bI apologize\b', 'assistant voice'),
    (r'\bcrucial\b|\bvital\b|\bparamount\b', 'inflated stakes word'),
    (r'\bnovel\b', '"novel" (never claim novelty)'),
    (r'\bsignificantly\b|\bdramatically\b|\bsubstantially\b', 'unmeasured intensifier'),
    (r'\bbad actor\b|\bthreat actor\b|\bmalicious actor\b', 'vague actor phrasing'),
    (r'\beasy to miss\b|\bunlikely to notice\b|\bwould not notice\b', 'unmeasured human-behaviour claim'),
]
# Hedging is forbidden in OUR prose but legitimate inside a quoted capture or a vendor quote.
HEDGE = r'\b(could|may|might|would|potentially|possibly|likely|probably|presumably)\b'

def strip_fences(t):
    """Remove fenced blocks and indented captures so we only lint OUR prose."""
    t = re.sub(r'```.*?```', '', t, flags=re.S)
    t = re.sub(r'(?m)^(?: {4}|\t).*$', '', t)
    t = re.sub(r'`[^`\n]+`', '', t)          # inline code
    t = re.sub(r'(?m)^\s*>.*$', '', t)       # block quotes (vendor quotes)
    return t

def words(s):
    return len([w for w in re.split(r'\s+', s.strip()) if w])

def section(text, name):
    m = re.search(rf'(?mis)^#+\s*{name}\s*$(.*?)(?=^#+\s|\Z)', text)
    return m.group(1) if m else None

def main(path):
    raw = open(path, encoding='utf-8').read()
    prose = strip_fences(raw)
    fails, warns = [], []

    # 1. internal notes - checked against the WHOLE file, these must not appear anywhere
    for pat, label in INTERNAL:
        for m in re.finditer(pat, raw, re.I):
            ln = raw[:m.start()].count('\n') + 1
            fails.append(f'INTERNAL  line {ln}: {label} -> {m.group(0)[:48]!r}')

    # 2. ai slop - OUR prose only
    for pat, label in SLOP:
        for m in re.finditer(pat, prose, re.I):
            fails.append(f'SLOP      {label} -> {m.group(0)[:48]!r}')
    for m in re.finditer(HEDGE, prose, re.I):
        fails.append(f'HEDGE     theoretical language in prose -> {m.group(0)!r}')

    # non-ascii / emoji anywhere
    for i, ch in enumerate(raw):
        if ord(ch) > 126 and ch not in '\n\r\t':
            cat = unicodedata.category(ch)
            if cat.startswith('So') or ord(ch) > 0x2000:
                ln = raw[:i].count('\n') + 1
                fails.append(f'NONASCII  line {ln}: U+{ord(ch):04X} {unicodedata.name(ch,"?")}')

    # 3. SEVERITY GATE - High or Critical only
    # The '=' is optional: gnoc_report.build writes "CVSS: <vector> = <score> <Sev>" and hand-written
    # drafts write "CVSS: <vector> <score> <Sev>". Demanding only the second spelling failed the
    # harness's own output on its own pre-submit gate (an OSS repo draft, 2026-10-28).
    cv = re.search(r'CVSS:\s*(CVSS:(?:3\.[01]|4\.0)/[A-Z:/]+)\s*=?\s+([0-9.]+)', raw)
    if not cv:
        fails.append('SEVERITY  no parseable "CVSS: <vector> <score>" header line')
    else:
        score = float(cv.group(2))
        # The 7.0 authorization floor was SUPERSEDED on 2026-10-19 by GreyNOC, verbatim: "we want to file
        # anything medium, high, crit wit impact to CIA". That revision is carried in CLAUDE.md's hard rules
        # and SPINE section 4; this gate was still enforcing the dead 2026-10-06 rule and refused a Medium
        # with captured impact. What the floor parks now is a true Low or an informational finding.
        if score < 4.0:
            fails.append(f'SEVERITY  score {score} is below Medium (4.0). A Low or informational finding is '
                         'parked as a LEAD, not filed (SPINE 4 severity floor).')
        elif score < 7.0:
            warns.append(f'SEVERITY  score {score} is Medium. Filable since 2026-10-19 ONLY with a captured '
                         'confidentiality, integrity or availability impact. Confirm the PoC captures one.')
        else:
            warns.append(f'severity {score} ({cv.group(1)}) - verify the vector against captured bytes')

    # 4. format caps
    for nm, cap in (('Summary', 35), ('Impact', 35)):
        sec = section(raw, nm)
        if sec is None:
            fails.append(f'FORMAT    no "{nm}" section')
        else:
            w = words(strip_fences(sec))
            if w > cap:
                fails.append(f'FORMAT    {nm} is {w} words, cap is {cap}')
            else:
                warns.append(f'{nm} {w}/{cap} words')
    t = re.search(r'(?m)^#\s+(.+)$', raw)
    if not t:
        fails.append('FORMAT    no "# title" line')
    elif len(t.group(1)) > 120:
        fails.append(f'FORMAT    title is {len(t.group(1))} chars, cap is 120')
    # Strip fenced blocks first: a captured log or script comment that begins with '##' is not a report
    # heading. program-62/recaptcha-client-supplied-sitekey was refused for a '## gate=1 means ...' line
    # that was inside its own quoted capture.
    unfenced = re.sub(r'```.*?```', '', raw, flags=re.S)
    heads = re.findall(r'(?m)^##\s+(.+)$', unfenced)
    extra = [h for h in heads if h.strip().rstrip('.').lower()
             not in ('summary', 'poc', 'impact', 'attachments')]
    for h in extra:
        fails.append(f'FORMAT    non-canonical heading: {h!r} (a labelled extra section gets bot-closed)')
    pw = words(prose)
    if pw > 1000:
        fails.append(f'FORMAT    {pw} words of prose, cap is 1000')
    else:
        warns.append(f'prose {pw}/1000 words')

    print(f'=== SUBMIT QAQC: {os.path.basename(os.path.dirname(path))} ===')
    for w in warns:
        print(f'  ok   {w}')
    if fails:
        print()
        for f in dict.fromkeys(fails):
            print(f'  FAIL {f}')
        print(f'\nBLOCKED: {len(set(fails))} issue(s). DO NOT SUBMIT.')
        return 1
    # Do not restate the severity rule here: it was wrong for every Medium after the 2026-10-19 revision.
    print('\nCLEAN. No internal notes, no slop tells. Severity is reported above, not asserted here.')
    print('Still required by hand: diff the staged bundle against this file, and')
    print('re-verify eligible_for_submission PER ASSET at filing time.')
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
