#!/usr/bin/env bash
#
# scope-gate.sh - PreToolUse hook for Bash | WebFetch | Burp MCP send_http1/2.
#
# Enforces the SCOPE GATE hard block (CLAUDE.md / RTK.md): before any probe,
# the target host must appear in targets/<program>/SCOPE.txt for the active
# program (derived from the working directory). An out-of-scope (OOS) probe
# is FORBIDDEN regardless of bug attractiveness (Bursa Malaysia 2026-05-15
# RTFS lesson, -5 reputation).
#
# Mechanism:
#   - Bash:     extract host(s) from any URL in tool_input.command.
#   - WebFetch: take host from tool_input.url.
#   - Burp MCP: take host from tool_input.targetHostname (send_http1/2, any
#               mcp server alias: burp / caveman-shrink).
#   - Program:  resolve the run-bound HUNT_TARGET/session LOCK first, then cwd.
#   - If targets/<prog>/SCOPE.txt exists, build the IN-SCOPE allowlist (only
#     host lines BEFORE any out-of-scope section marker; see scope_inscope_hosts)
#     and if the probe host matches no allowlist entry -> stderr + exit 2 (block).
#
# OOS-section awareness (2026-06-10 fix): SCOPE.txt files carry an explicit
# out-of-scope carve-out section (## OUT OF SCOPE / # === OUT OF SCOPE === /
# # OUT OF SCOPE (Ineligible) / etc). The previous substring match treated a
# host listed ONLY in that carve-out as in-scope (e.g. avevaresource.com,
# www.decathlon.com). The allowlist now stops at the first genuine OOS section
# divider, so carve-out hosts are correctly blocked.
#
# FAIL-OPEN (exit 0, never block) when:
#   - no jq, no payload, any parse/jq error
#   - no SCOPE.txt for the active program
#   - no host could be parsed from the command/url
#   - host is localhost / 127.0.0.1 / RFC1918 (10. / 172.16-31. / 192.168.)
#   - host is a known bug-bounty platform or infra (allowlist below)
#
# Design rule: a buggy gate that halts the live session is worse than a
# missed OOS catch. Every uncertain path exits 0.

set -u  # no -e / no pipefail: must exit 0 on any internal failure path that
        # is not an explicit block.

# --- Shared in-scope extraction (identical logic in scope-inject.sh) --------
# Print the IN-SCOPE host tokens of a SCOPE.txt: every first-token host on a
# non-comment, non-blank line that appears BEFORE the first genuine OUT-OF-SCOPE
# section divider. A divider is a comment/text line whose stripped text (leading
# '#', whitespace and '='/'-' decoration removed) STARTS with an OOS phrase AND
# does NOT itself name a bare host on the same line (the latter guard keeps an
# inline note like "# OUT OF SCOPE: vinda.com ..." from nuking the whole file,
# as in targets/essity/SCOPE.txt where the note precedes the in-scope list).
# A SCOPE.txt with no divider yields all host lines (legacy behavior).
scope_inscope_hosts() {
  awk '
    function strip_decor(s) {
      gsub(/^[[:space:]]*#+[[:space:]]*/, "", s)
      gsub(/^[-=[:space:]]+/, "", s)
      return s
    }
    BEGIN { IGNORECASE = 1 }
    {
      raw = $0
      is_comment = (raw ~ /^[[:space:]]*#/)
      line = strip_decor(raw)
      if (line ~ /^(out.?of.?scope|oos([^a-z0-9]|$)|exclud|ineligib|not[[:space:]]+in[[:space:]]+scope|do[[:space:]]+not[[:space:]]+test|forbidden)/) {
        # inline OOS note that references a host -> not a divider, skip as comment
        if (line ~ /[a-z0-9]([a-z0-9-]*[a-z0-9])?\.[a-z]{2,}/) { next }
        exit   # genuine section divider -> ignore everything to EOF
      }
      if (is_comment) next
      if (raw ~ /^[[:space:]]*$/) next
      sub(/[[:space:]]*#.*$/, "", raw)   # strip trailing inline comment
      sub(/^[[:space:]]+/, "", raw)
      sub(/[[:space:]]+$/, "", raw)
      if (raw == "") next
      n = split(raw, a, /[[:space:]]+/)
      tok = a[1]
      # H1 TABULAR FORMAT (fix 2026-10-02). Platform scope exports prefix each row with the
      # asset TYPE: "WILDCARD  *.foo.com\t[bounty; max=critical]". Printing a[1] yielded the
      # keyword, which has no dot and is refused by host_in_scope, so a tabular SCOPE.txt
      # matched NOTHING and this gate blocked even in-scope hosts (verified end-to-end).
      # A bare-host file has one token per line (n==1) and is untouched.
      # ASSET TYPE CARRIES THE SEMANTICS: only WILDCARD authorises subdomains. A bare domain on
      # a URL/DOMAIN/API row is exact-only on HackerOne, so it is marked "=" - treating it as an
      # apex would silently widen scope to every subdomain of a bare-domain asset.
      if (n > 1 && tok !~ /\./ && tok ~ /^[A-Za-z][A-Za-z0-9_]*$/) {
        atype = toupper(tok)
        tok = a[2]
        sub(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "", tok)   # URL-form asset -> host
        sub(/\/.*$/, "", tok)
        sub(/^[^@]*@/, "", tok)
        sub(/:[0-9]+$/, "", tok)
        if (atype != "WILDCARD" && tok !~ /^\*/) tok = "=" tok
      }
      if (tok != "") print tok
    }
  ' "$1" 2>/dev/null
}

# host_in_scope <host> <scopefile> : exit 0 if host matches an in-scope entry.
# Entry E matches host H when (case-insensitive, with any leading "*." / "*"
# wildcard stripped to its suffix): H == E, H ends with ".E", or H ends with E
# for a wildcard suffix entry. Non-host tokens (app ids, "Braintree SDK") never
# match a parsed URL host, which is the safe direction.
host_in_scope() {
  local h="$1" sf="$2" e ne lh exact
  lh=$(printf '%s' "$h" | tr '[:upper:]' '[:lower:]')
  while IFS= read -r e; do
    [ -z "$e" ] && continue
    e=$(printf '%s' "$e" | tr '[:upper:]' '[:lower:]')
    # Exact-only marker (2026-06-10 backlog #22): a leading '=' matches THIS
    # host only, never its subdomains, for URL-asset programs (acmefoods,
    # nintendo) whose subdomains are explicitly out of scope.
    exact=0
    case "$e" in
      =*) exact=1; e=${e#=} ;;
    esac
    # normalize leading wildcard:  *.foo.com -> foo.com ;  *foo.com -> foo.com
    ne=$(printf '%s' "$e" | sed -E 's/^\*\.//; s/^\*//')
    [ -z "$ne" ] && continue
    # Data-hygiene guard: refuse a scope entry that is ONLY a public suffix or a
    # bare TLD. Without this, its subdomain rule (*".$ne") fail-OPENs every domain
    # under that suffix (random.co.uk, evil.com.mx). Skipping only removes ALLOW
    # paths, so the failure direction is safe (block, not leak).
    case "$ne" in
      app.example.com|com.au|com.co|com.mx|co.jp|co.nz|com.br|co.in|com.sg|com.hk|co.za|com.tr|gov.uk|org.uk|net.au|org.au|co.kr|com.cn|co.id|com.ph|com.my|co.th|com.tw|ne.jp|or.jp) continue ;;
    esac
    case "$ne" in
      *.*) ;;             # at least two labels: a registrable host, proceed
      *) continue ;;      # single label (bare TLD like "com"): refuse
    esac
    case "$lh" in
      "$ne") return 0 ;;          # exact (always honored)
    esac
    # exact-only entry stops here: never match a subdomain or wildcard form.
    [ "$exact" = 1 ] && continue
    case "$lh" in
      *".$ne") return 0 ;;        # subdomain of an in-scope apex/suffix
    esac
    # WILDCARD FORM MATTERS (2026-09-30). This branch used to fire for ANY '*' entry,
    # so '*.target.example' also matched 'eviltarget.example' / 'nottarget.example' -
    # a DIFFERENT registrable domain, possibly a third party's. Since '*.foo.com' is the
    # most common scope line on every platform, that silently widened scope off-program.
    # '*.foo.com' is now dot-bounded (the exact + *".$ne" cases above already cover it).
    # A bare '*foo.com' (no dot) keeps the loose suffix match - that form is a deliberate
    # glob. Kept byte-for-byte in step with bbtools/lib_scope.py.
    case "$e" in
      \*.*) ;;                                      # '*.foo.com' -> dot-bounded only
      \**) case "$lh" in *"$ne") return 0 ;; esac ;; # '*foo.com'  -> loose suffix (intended)
    esac
    # mid-string wildcard entry (e.g. www.paypal-*.com): * is a glob, not literal.
    # ne is matched UNQUOTED so the star expands; covers the host and its subdomains.
    case "$ne" in
      *'*'*)
        case "$lh" in
          $ne) return 0 ;;        # unquoted: www.paypal-*.com matches www.paypal-status.com
          *.$ne) return 0 ;;      # subdomain of the wildcard host
        esac
        ;;
    esac
  done <<EOH
$(scope_inscope_hosts "$sf")
EOH
  return 1
}

PAYLOAD=$(cat 2>/dev/null || true)
[ -z "$PAYLOAD" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

TOOL=$(printf '%s' "$PAYLOAD" | jq -r '.tool_name // empty' 2>/dev/null) || exit 0
case "$TOOL" in
  Bash|WebFetch) ;;
  mcp__*send_http1_request|mcp__*send_http2_request) ;;
  *) exit 0 ;;
esac

CWD=$(printf '%s' "$PAYLOAD" | jq -r '.cwd // empty' 2>/dev/null) || exit 0
[ -z "$CWD" ] && CWD=$(pwd 2>/dev/null || echo "")

# Locate the workspace root (the path component up to and including the workspace).
ROOT=$(printf '%s' "$CWD" | sed -n 's#\(.*/.gnoc\)/.*#\1#p' 2>/dev/null)
if [ -z "$ROOT" ]; then
  ROOT=$(printf '%s' "$CWD" | sed -n 's#\(.*/.gnoc\)$#\1#p' 2>/dev/null)
fi
[ -z "$ROOT" ] && ROOT="${GNOC_WORKSPACE:-$HOME/.gnoc}"

# Resolve the ONE active program.  A root-run hunt must never inherit the union
# of every program's authorization.  The per-session lock is the authoritative
# context used by the selector/fleet; cwd remains a compatibility fallback.
SID=$(printf '%s' "$PAYLOAD" | jq -r '.session_id // empty' 2>/dev/null || echo "")
PROG=""
# 2026-10-19 (platform mode, parallel lanes on DIFFERENT programs in ONE session): an explicit
# per-command pin written as a leading `HUNT_TARGET=<handle>` assignment in the Bash command text
# wins over the session LOCK, exactly as the fleet's HUNT_TARGET env wins. Workers share the
# orchestrator's session id, so a shared LOCK cannot express N programs at once; the command-text
# pin can. Honoured ONLY when targets/<handle>/SCOPE.txt exists, so it never widens scope beyond
# one real program. A worker must never run lock.sh to pass the gate.
_CMDPIN=$(printf '%s' "$PAYLOAD" | jq -r '.tool_input.command // empty' 2>/dev/null | sed -nE 's/^[[:space:]]*(cd[^;&|]*[;&|]+[[:space:]]*)?(export[[:space:]]+)?HUNT_TARGET=([A-Za-z0-9._-]+).*/\3/p' | head -1)
if [ -n "$_CMDPIN" ] && [ -s "$ROOT/targets/$_CMDPIN/SCOPE.txt" ]; then
  PROG="$_CMDPIN"
fi
if [ -z "$PROG" ] && [ -r "$ROOT/scripts/hunt-loop/lock-lib.sh" ]; then
  PROG=$(. "$ROOT/scripts/hunt-loop/lock-lib.sh" 2>/dev/null; hl_lock_target "$SID" 2>/dev/null | awk 'NF{print $1; exit}')
fi
if [ -z "$PROG" ]; then
  PROG=$(printf '%s' "$CWD" | sed -n 's#.*/targets/\([^/]*\)/.*#\1#p' 2>/dev/null)
  [ -z "$PROG" ] && PROG=$(printf '%s' "$CWD" | sed -n 's#.*/targets/\([^/]*\)$#\1#p' 2>/dev/null)
fi
case "$PROG" in *[!A-Za-z0-9._-]* ) PROG="" ;; esac

# Build only the active program's scope.  With no run context SCOPES stays
# empty and any actual target request is blocked below (platform/toolchain and
# loopback traffic are still allowed).  This is deliberate fail-closed behavior.
SCOPES=""
if [ -n "$PROG" ] && [ -f "$ROOT/targets/$PROG/SCOPE.txt" ]; then
  SCOPES="$ROOT/targets/$PROG/SCOPE.txt"
fi

# --- Explicit DENY list (2026-09-30) ---------------------------------------
# Some programs publish hosts that sit UNDER an in-scope parent but are
# explicitly INELIGIBLE (Meta lists app.example.com in scope while naming
# app.example.com and app.example.com ineligible, and app.example.com in scope
# while naming app.example.com ineligible). The allowlist cannot express this:
# the parent's subdomain rule matches them, and an OUT-OF-SCOPE carve-out
# written inside SCOPE.txt is inert because scope_inscope_hosts() stops reading
# at the divider. targets/<prog>/NOSCOPE.txt is the deny list. It is evaluated
# BEFORE any allowlist and overrides every one of them, including a match from
# another program's SCOPE.txt. Failure direction is safe: a deny entry can only
# ADD a block, never grant access, so a wrong entry costs a loud halt, not a leak.
DENIES=""
if [ -n "$PROG" ] && [ -f "$ROOT/targets/$PROG/NOSCOPE.txt" ]; then
  DENIES="$ROOT/targets/$PROG/NOSCOPE.txt"
fi

# --- Extract host(s) -------------------------------------------------------
HOSTS=""
case "$TOOL" in
  WebFetch)
    URL=$(printf '%s' "$PAYLOAD" | jq -r '.tool_input.url // empty' 2>/dev/null) || exit 0
    [ -z "$URL" ] && exit 0
    HOSTS=$(printf '%s' "$URL" | grep -oiE 'https?://[^/ "'"'"'`]+' 2>/dev/null \
            | sed -E 's#^https?://##I' 2>/dev/null)
    ;;
  Bash)
    CMD=$(printf '%s' "$PAYLOAD" | jq -r '.tool_input.command // empty' 2>/dev/null) || exit 0
    [ -z "$CMD" ] && exit 0
    # Strip request-body / header / form / referer / cookie flag VALUES before host extraction:
    # a URL inside a -d/--data*/--json/-F/--form/-H/-e/-b value is NOT the fetch target, so it
    # must not scope-block a legit in-scope probe whose body or header carries an external
    # callback / redirect_uri / Referer (the SSRF/OAuth/cache chained probes). Safe direction:
    # the real target is a positional arg or --url (never stripped), so this removes only FALSE
    # blocks and can never let a real OOS target through.
    # a flag only at the START of a word: without the boundary, "/tmp/x-e https://evil" lost its URL to "-e" (QAQC r2)
    CMD=$(printf '%s' "$CMD" | sed -E "s/(^|[[:space:]])(--data[a-z-]*|-d|--json|--form|-F|--header|-H|--referer|-e|--cookie|-b|--user-agent|-A)([[:space:]]+|=)('[^']*'|\"[^\"]*\"|[^[:space:]]+)/\1 /gI" 2>/dev/null)
    HOSTS=$(printf '%s' "$CMD" | grep -oiE 'https?://[^/ "'"'"'`]+' 2>/dev/null \
            | sed -E 's#^https?://##I' 2>/dev/null)
    # SCHEME-LESS fallback (2026-07-19): curl/nuclei/httpx/ffuf commonly take a BARE host (no
    # https://). If the scheme'd scan found nothing AND a network client is invoked, extract
    # host-shaped tokens (label.label.tld) so an OOS bare host cannot silently pass; filenames
    # (known extensions) are excluded and a non-host command finds nothing -> stays FAIL-OPEN.
    # An in-scope bare host clears the SAME allowlist test a scheme'd host does, so this adds
    # ONLY real OOS catches, never a new false-block on an in-scope host.
    # CODE-IDENTIFIER false blocks (2026-09-30): this fallback fires whenever a network-client
    # word appears ANYWHERE in the command - including inside a quoted regex or string - and then
    # treats any label.label token as a host. Observed real false blocks: a python attribute
    # access `s.count(...)` inside a LOCAL file-edit script was read as the host 's.count', and a
    # Go module path in a local write was blocked with no network request involved. A hard block
    # derails an agent mid-task, so a second filter below drops common code identifiers. Every
    # name in it was checked NOT to be a real TLD, so it removes only false blocks and can never
    # cause a genuine out-of-scope host to slip through.
    # Word boundaries exclude "-", "_" and "." (2026-10-22): `grep -nc` read as netcat and the
    # module name `curl_cffi` read as curl, switching this host guessing on for plain local scripts.
    # dig/host/nslookup/whois/ping resolve an attacker-chosen name, which is a working exfil channel and was
    # not gated at all: they are classed read-only so they also skip the approval prompt (audit A-02, 2026-10-22).
    # 2026-10-28: the AMBIGUOUS tool names are also ordinary English, and matching them ANYWHERE in the
    # command text turned this fallback on for plain prose. The literal word "host" in a sentence switched
    # on scheme-less host guessing over the whole command, which then read a Go method name, a source
    # filename and a URL quoted inside a report body as probe targets: four documentation writes were
    # HARD-BLOCKED in one session. Lane F already warned this "makes writing an honest receipt harder than
    # firing the probe", which pushes agents to route around a SAFETY gate - the worst outcome.
    # Split the list: unambiguous tool names still match anywhere, because they are never prose. The
    # ambiguous ones must be in COMMAND POSITION: at the start, or after | ; & ( or $( . A real
    # `host somewhere` invocation still matches, so enforcement is unchanged; only prose stops triggering
    # it. Explicit scheme URLs are extracted by the branch above and are unaffected.
    _TOOLS_ANY='curl|wget|httpx|nuclei|ffuf|wfuzz|gobuster|feroxbuster|nikto|dirsearch|websocat|wscat|ncat|nslookup|traceroute|kdig|doggo|openssl'
    _TOOLS_CMDPOS='nc|dig|host|whois|ping|ping6|dog'
    if [ -z "$HOSTS" ] && { printf '%s' "$CMD" | grep -qiE "(^|[^a-z_.-])($_TOOLS_ANY)([^a-z_]|$)" \
         || printf '%s' "$CMD" | grep -qiE "(^|[|;&()]|\\\$\\()[[:space:]]*($_TOOLS_CMDPOS)[[:space:]]"; }; then
      # A token directly followed by "(" is a call (`d.get(`, `json.load(`), never a bare host
      # (2026-10-22: a `curl ... | python3 -c "...d.get(...)"` pipeline was blocked on host "d.get").
      # An EMAIL ADDRESS is not a host. "noreply@anthropic.com" parses as the bare apex, which is
      # genuinely out of scope, so a commit message or report body merely NAMING an address was
      # hard-blocked (measured 5x in one session, 2026-10-27, plus lane F independently). The
      # lookbehind drops a token with "@" immediately before it; a userinfo URL
      # (http://user@host/) is handled by the scheme branch above, never here. -P is GNU grep; if
      # this build lacks it the || falls back to the original -E extraction, so the gate still fires.
      # Capability-probe -P ONCE. It cannot be done with `grep -P ... || grep -E ...`: grep exits 1 on
      # NO MATCH, which is exactly the success case here (the only candidate sat after an "@"), so the
      # fallback fired and re-extracted without the lookbehind. Probe, then pick.
      if printf 'a.bc' | grep -qoP 'a\.bc' 2>/dev/null; then
        HOST_RE_MODE=P
      else
        HOST_RE_MODE=E
      fi
      # FILE NAMES THAT LOOK LIKE HOSTS (2026-11-25). Two false blocks, both from text that names a file:
      # a commit message naming "link-desktop.ps1" was refused as "OOS host link-desktop.ps" - the TLD
      # class [a-z]{2,} stopped before the digit and kept a PREFIX of the word - and "main.rs" in a path
      # was refused as a host. (1) The match now runs to the end of the word ([a-z0-9_]* after the TLD)
      # and a token whose LAST LABEL holds a digit or "_" is dropped below: no TLD has either, so
      # "x.ps1" is a file and "evil.com2" is no resolvable name, while every real host is unaffected.
      # (2) .rs (Serbia) and .ps (Palestine) ARE real ccTLDs, so they are NOT in the always-a-file list;
      # a token ending in them is dropped only in PATH position (right after a "/", e.g. src/main.rs).
      # A bare `curl evil.rs` still blocks. (.md .sh .py were already in the always-a-file list before
      # this change and stay there: setup.py / README.md / run.sh in a command are files far more often
      # than hosts, and a scheme'd URL on a .md or .sh host never reaches this branch - it is always
      # extracted and checked by the scheme'd branch above.)
      CMD_HL=$(printf '%s' "$CMD" | sed -E 's#/[A-Za-z0-9_.-]+\.(rs|ps)([^A-Za-z0-9_.-]|$)#/\2#gI' 2>/dev/null || printf '%s' "$CMD")
      if [ "$HOST_RE_MODE" = P ]; then
        HOSTS=$(printf '%s' "$CMD_HL" \
                | grep -oiP '(?<![@A-Za-z0-9._-])([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}[a-z0-9_]*\(?' 2>/dev/null || true)
      else
        HOSTS=$(printf '%s' "$CMD_HL" \
                | grep -oiE '([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}[a-z0-9_]*\(?' 2>/dev/null || true)
      fi
      HOSTS=$(printf '%s\n' "$HOSTS" \
              | grep -v '($' \
              | grep -viE '\.[a-z]*[0-9_][a-z0-9_]*$' \
              `# FILE NAMES and VERSION STRINGS are not hosts. ".jsonl" was missing from this list, so` \
              `# "outcomes.jsonl" and "trajectories.jsonl" were read as hostnames; "2.0.alpha" likewise.` \
              `# Lane F's note (2026-10-27): the gate "makes writing an honest SSRF receipt harder than` \
              `# firing the SSRF", which pushes agents to route around a SAFETY gate - the worst outcome.` \
              | grep -viE '\.(py|js|mjs|cjs|ts|tsx|jsx|css|scss|vue|ps1|psm1|psd1|bat|cmd|json|jsonl|ndjson|jsonc|md|txt|sh|bash|html?|log|csv|tsv|xml|ya?ml|png|jpe?g|gif|svg|pdf|conf|ini|env|cfg|toml|lock|bak|zip|tar|gz|tgz|db|sql|har|pem|crt|key|p12|diff|patch|sig|hdr|body|resp|out|tmp|orig|rej|cast|mp4|webm|gguf|bin|pyc|ipynb|go|rb|php|java|cpp|hpp|kt|swift|scala|lua|proto|tf|tfvars|mod|sum|gemspec|rake)$' 2>/dev/null \
              | grep -viE '\.(alpha|beta|rc[0-9]*|dev|final|old|new|prev|next|latest|sample|template)$' 2>/dev/null \
              | grep -viE '\.(count|append|split|splitlines|join|strip|rstrip|lstrip|replace|format|items|keys|values|exists|lower|upper|casefold|encode|decode|groups|findall|finditer|loads|dumps|environ|argv|stdout|stderr|stdin|isoformat|timedelta|communicate|startswith|endswith|insert|reverse|extend|basename|dirname|realpath|abspath|isfile|isdir|getcwd|listdir|makedirs|hexdigest|digest|compile|escape|readlines|writelines|setdefault|popitem|fromkeys|rfind|rindex|partition|rpartition|zfill|ljust|rjust|expandtabs|isalpha|isdigit|isalnum|isspace|check_output|check_call|Popen|getenv|unlink|rmtree|copyfile|copytree|removeall|readlink|mkdirall|writefile|readfile|lstat|symlink|marshal|unmarshal|sprintf|errorf|fatalf|hasprefix|hassuffix|trimspace|atoi|itoa|readdir|openfile|truncate|chmod|chown|rename|tempdir)$' 2>/dev/null \
              | sort -u)
    fi
    ;;
  mcp__*send_http1_request|mcp__*send_http2_request)
    HOSTS=$(printf '%s' "$PAYLOAD" | jq -r '.tool_input.targetHostname // empty' 2>/dev/null) || exit 0
    [ -z "$HOSTS" ] && exit 0
    ;;
esac

# TRAILING PUNCTUATION (2026-11-03). The scheme'd extractor stops only at / space quote backtick,
# so a URL with NO PATH followed by prose punctuation keeps it: `https://app.example.com,` parsed as the
# host `app.example.com,`. That token then (a) misses the RFC 2606 drop below, which requires the whole
# token to be a hostname, and (b) is scope-matched malformed, so it NEVER matches - the gate hard
# blocked `app.example.com,` as out of scope against program-63's OWN SCOPE.txt, and blocked `evil.example,`
# and `attacker.invalid)` that the reserved drop exists to allow. Measured 2026-11-03: with a path
# (`https://app.example.com/casino,`) every case already passed, because / ends the match - only the
# no-path form was affected. Stripping to the last hostname character makes the token MORE
# canonical, so a real out-of-scope host still reaches every check below: `oos-host.com,` and
# `oos-host.com` both block, verified. Everything after the LAST ALPHANUMERIC goes, which also takes
# the FQDN root dot: `app.example.com.` is the same host as `app.example.com`, and in a command it is far more
# often the end of a sentence. A :port is untouched because it ends in a digit.
# PLACEHOLDERS (2026-11-25). "<" and ">" are never hostname bytes. A prompt or doc naming a URL
# template (scheme, then <name>, then a slash) was hard blocked as "OOS host <name". A token holding
# < or > is replaced by its two fixed parts: the text BEFORE the first < or >, and the text AFTER the
# last one, each kept only when it still has a dot. So <name> alone is dropped (a template, not a
# host), while evil.com<x> is checked as evil.com, <x>evil.com as evil.com, and a.<n>.app.example.com as
# app.example.com. Each part is a substring of the original, so this can only drop the placeholder bytes,
# never let a named out-of-scope host through.
HOSTS=$(printf '%s\n' "$HOSTS" | awk '{
  if ($0 ~ /[<>]/) {
    a = $0; sub(/[<>].*$/, "", a); sub(/[^A-Za-z0-9]+$/, "", a)
    b = $0; sub(/^.*[<>]/, "", b); sub(/^[^A-Za-z0-9]+/, "", b); sub(/[^A-Za-z0-9]+$/, "", b)
    if (a ~ /\./) print a
    if (b ~ /\./) print b
  } else print
}' 2>/dev/null || true)

HOSTS=$(printf '%s\n' "$HOSTS" | sed -E 's#[^A-Za-z0-9]+$##' 2>/dev/null || true)

# REGEX-ESCAPED DOTS (2026-11-10). A command that carries a regex over a URL, such as a Python
# `re.search(r"https?://scrm-x\.brand\.com\.cn/...")` over the lane's OWN raw captures, reaches the
# scheme'd extractor as `scrm-x\.brand\.com\.cn`: the backslashes survive (the extractor stops only
# at / space quote backtick), so the token can match NO scope row and a LOCAL file grep was hard
# blocked as an out-of-scope probe on a host whose wildcard apex sat in SCOPE.txt (program-50,
# 2026-11-10 03:15Z). A backslash is never part of a hostname; `\.` names the same byte as `.`, so
# unescaping makes the token MORE canonical and a genuinely out-of-scope host still blocks after it.
# Every backslash goes, not only the one before a dot: a non-raw Python string carries `\\.` and a
# JSON body carries `https:\/\/host\/`, and neither byte can belong to a hostname.
HOSTS=$(printf '%s\n' "$HOSTS" | tr -d '\\' 2>/dev/null || true)

# RESERVED NAMES (RFC 2606 / RFC 6761, 2026-10-22): .test .example .invalid .localhost and
# example.com/.net/.org can never be a bounty asset, yet bench fixtures and unit tests that name
# api.acme.test were hard-blocked. Only a token that is ENTIRELY a plain hostname (letters, digits,
# dots, hyphens, optional :port) under a reserved name is dropped, so `umbrella.com#.test`,
# `x.test@umbrella.com` or `umbrella.com.test.evil.io` still reach the checks below.
HOSTS=$(printf '%s\n' "$HOSTS" \
        | grep -viE '^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*((test|example|invalid|localhost)|example\.(com|net|org))\.?(:[0-9]+)?$' \
        || true)

[ -z "$HOSTS" ] && exit 0   # FAIL-OPEN: no URL/host parsed.

# Known platform / infra allowlist (substring match against host).
# OWN INFRASTRUCTURE (2026-10-20): your-site.example is GreyNOC's own site (your-site.example,
# GreyIQ behind the Cloudflare tunnel), same category as the VPS entry. Never a bounty asset.
# SELF-HOSTED PROGRAM POLICY HOSTS (2026-09-30): a program that runs its own bounty
# portal has no hackerone.com/bugcrowd.com entry to ride on, so reading its scope and
# payout pages -- which the rules of engagement REQUIRE before the first packet -- was
# hard-blocked. bugbounty.meta.com is Meta's portal, the same category as the platform
# hosts below: a policy-documentation host, never a bounty asset. Meta's in-scope
# ASSETS stay gated by targets/program-64/SCOPE.txt and are unaffected by this entry.
# CVE / security-documentation research hosts (read-only advisory + vendor-doc
# sources, same category as nvd.nist.gov / cve.org; used for static CVE research,
# never live-target probes): kubernetes.io, cloud.google.com + docs mirror,
# bugzilla.redhat.com / access.redhat.com, lwkd.info, osv.dev, tenable.com,
# cisecurity.org, mitre.org, first.org, learn.microsoft.com, suse.com,
# groups.google.com.
PLATFORM_RE='bugbounty\.meta\.com|your-site\.example|api\.stripe\.com|mullvad\.net|registry\.ollama\.ai|ollama\.com|203\.0\.113\.10|203-0-113-10\.sslip\.io|203-0-113-10\.nip\.io|webhook\.site|immunefi\.com|docs\.parallel\.best|parallel\.best|hackerone\.com|bugcrowd\.com|intigriti\.com|yeswehack\.com|huntr\.com|hackenproof\.com|github\.com|githubusercontent\.com|nvd\.nist\.gov|cve\.org|kubernetes\.io|cloud\.google\.com|docs\.cloud\.google\.com|bugzilla\.redhat\.com|access\.redhat\.com|lwkd\.info|osv\.dev|tenable\.com|cisecurity\.org|mitre\.org|cwe\.mitre\.org|first\.org|learn\.microsoft\.com|suse\.com|groups\.google\.com|crt\.sh|hackertarget\.com|rapiddns\.io|jldc\.me|otx\.alienvault\.com|urlscan\.io|certspotter\.com|api\.certspotter\.com|web\.archive\.org|dns\.google|cloudflare-dns\.com|api\.cloudflare\.com|apkpure\.com|apkpure\.net|apkmirror\.com|aptoide\.com|uptodown\.com|f-droid\.org|d\.apkpure\.com|apkcombo\.com|apkcombo\.app|uptodown\.com|uptodown\.net|androidapksfree\.com|r2\.cloudflarestorage\.com|apkflash\.com|apkcombo\.org|mail\.tm|mail\.gw|1secmail\.com|guerrillamail\.com|api\.guerrillamail\.com|guerrillamailblock\.com|sharklasers\.com|grr\.la|quackr\.io|receive-sms\.com|receive-smss\.com|receivesmss\.com|mytempsms\.com|receivesmsfast\.com|freereceivesms\.com|smss\.biz|onlinesim\.io|smspva\.com|receivesms\.org|receivesms\.co|receivesms\.in|sms24\.me|anonymsms\.com|temp-number\.com|receive-sms-online\.info|getfreesmsnumber\.com|smsreceivefree\.com|freephonenum\.com|textverified\.com|5sim\.net|sms-activate\.org|sms-activate\.io|temporary-phone-number\.com|mobilesms\.io|receive-sms-free\.cc|temp-sms\.org|sms-receive\.net|receivesmsonline\.net|sms-online\.co|quackr\.io|oastify\.com|burpcollaborator\.net|interact\.sh|oast\.fun|oast\.online|oast\.pro|oast\.live|oast\.site|oast\.me|2captcha\.com|rucaptcha\.com|api\.capmonster\.cloud|api\.vercel\.com|globex\.com|repo1\.maven\.org|repo\.maven\.apache\.org|search\.maven\.org|central\.sonatype\.com|oss\.sonatype\.org|maven\.org|mvnrepository\.com|sourcegraph\.com|grep\.app|searchcode\.com|publicwww\.com|api\.postman\.com|www\.postman\.com|postman\.com|go\.postman\.co|app\.swaggerhub\.com|api\.swaggerhub\.com|swaggerhub\.com|gitlab\.com|bitbucket\.org|api\.bitbucket\.org|registry\.npmjs\.org|www\.npmjs\.com|npmjs\.com|pypi\.org|files\.pythonhosted\.org|hub\.docker\.com|registry\.hub\.docker\.com|registry-1\.docker\.io|auth\.docker\.io|index\.docker\.io|gallery\.ecr\.aws|public\.ecr\.aws|api\.ecr-public\.aws|registry\.terraform\.io|api\.github\.com|gist\.github\.com|gist\.githubusercontent\.com|raw\.githubusercontent\.com|bgp\.he\.net|viewdns\.info|dnsdumpster\.com|columbus\.elmasy\.com|subdomain\.center|api\.subdomain\.center|index\.commoncrawl\.org|c99\.nl|dns\.bufferover\.run|tls\.bufferover\.run|api\.hackertarget\.com|crt\.sh|www\.dnsdb\.info|riddler\.io|api\.threatminer\.org|threatminer\.org|www\.virustotal\.com|otx\.alienvault\.com|sonar\.omnisint\.io|api\.certspotter\.com'

# Toolchain / package-registry hosts (see the FAIL-OPEN note below). Never bounty assets.
TOOLCHAIN_RE='hf\.co|huggingface\.co|cdn-lfs\.hf\.co|cas-bridge\.xethub\.hf\.co|github\.io|golang\.org|go\.dev|proxy\.golang\.org|sum\.golang\.org|googlesource\.com|storage\.googleapis\.com|dl\.google\.com|edgedl\.me\.gvt1\.com|nodejs\.org|unpkg\.com|cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|jsdelivr\.net|crates\.io|static\.crates\.io|rubygems\.org|packagist\.org|nuget\.org|deb\.debian\.org|security\.debian\.org|archive\.parrotsec\.org|deb\.parrot\.sh|ftp\.debian\.org|snapcraft\.io|api\.snapcraft\.io|launchpad\.net|sh\.rustup\.rs|static\.rust-lang\.org|rust-lang\.org|pkg\.go\.dev|deepseek\.com'

# Evaluate each parsed host. First OOS host blocks.
while IFS= read -r HOSTPORT; do
  [ -z "$HOSTPORT" ] && continue
  # strip any user@ prefix and :port suffix for matching, but keep full for msg
  H=$(printf '%s' "$HOSTPORT" | sed -E 's#^[^@/]*@##; s#:[0-9]+$##' 2>/dev/null | tr '[:upper:]' '[:lower:]')
  [ -z "$H" ] && continue

  # EXPLICIT DENY first: an ineligible host is blocked even when an allowlist
  # (this program's or another's) would match it. Checked before the fail-open
  # cases below so a deny cannot be short-circuited.
  if [ -n "$DENIES" ]; then
    while IFS= read -r DF; do
      [ -z "$DF" ] && continue
      if host_in_scope "$H" "$DF"; then
        printf 'BLOCKED: %s is on the explicit DENY list (%s) - the program names it INELIGIBLE even though it sits under an in-scope parent domain.\n' "$H" "$DF" >&2
        exit 2
      fi
    done <<EODENY
$DENIES
EODENY
  fi

  # FAIL-OPEN: localhost / loopback / RFC1918.
  # QAQC 2026-11-19: the prefix cases below must only ever see an IP LITERAL - as hostname patterns,
  # 127.evil.com and 10.attacker.net passed as "loopback".
  case "$H" in
    localhost|localhost.localdomain|0.0.0.0|::1|\[::1\]) continue ;;
  esac
  if printf '%s' "$H" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
    case "$H" in
      127.*|10.*|192.168.*) continue ;;
      172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) continue ;;
    esac
  fi

  # FAIL-OPEN: known platform / infra host.
  if printf '%s' "$H" | grep -qiE "(^|\.)($PLATFORM_RE)\$" 2>/dev/null; then
    continue
  fi
  # FAIL-OPEN: toolchain / package-registry host (2026-09-30). These are never bounty
  # assets; they are how this workspace installs and updates its own tooling. Two real
  # false positives motivated this: a Go module path in a LOCAL file-write command was
  # blocked (no network request at all), and the Chrome-for-Testing download URL on
  # googlechromelabs.github.io was blocked because PLATFORM_RE covers github.com and
  # githubusercontent.com but not github.io. A hard block here derails an agent mid-task,
  # and blocking a package fetch protects nothing.
  if printf '%s' "$H" | grep -qiE "(^|\.)($TOOLCHAIN_RE)\$" 2>/dev/null; then
    continue
  fi

  # INTEL allowlist (GreyNOC 2026-10-23: "yes"): the knowledge-intake sources in scripts/intel/sources.json
  # (public blogs, disclosed reports, advisories) are reachable ONLY when the command or URL is the intel
  # pipeline itself; a hunt lane naming the same host without a target is still blocked. Keep in sync with
  # sources.json (regenerate: python3 scripts/intel/intake.py allowlist).
  INTEL_RE='api\.github\.com|blog\.orange\.tw|feeds\.transistor\.fm|github\.com|googleprojectzero\.blogspot\.com|hackerone\.com|pentester\.land|portswigger\.net|projectdiscovery\.io|samcurry\.net|www\.assetnote\.io|www\.bugcrowd\.com|www\.intigriti\.com|www\.skeletonscribe\.net|www\.yeswehack\.com'
  if printf '%s%s' "${CMD:-}" "${URL:-}" | grep -qE 'scripts/intel/|gnoc intel|intel/intake' 2>/dev/null \
     && printf '%s' "$H" | grep -qiE "(^|\.)($INTEL_RE)\$" 2>/dev/null; then
    continue
  fi

  # A real remote target requires one explicit program context and one readable
  # scope file.  Never authorize it by finding a match in another program.
  #
  # WEBFETCH CARVE-OUT (2026-10-21 fix, HANDOFF-CURRENT.md section 6b): WebFetch has no
  # tool_input.command text to carry a per-call HUNT_TARGET= pin the way Bash does (the
  # _CMDPIN extraction above only ever reads .tool_input.command), so in a multi-program
  # session it has only the session-wide LOCK to fall back on. That LOCK names ONE program
  # for the whole session, so a WebFetch read ABOUT a different program - a brand-new
  # pre-intake candidate's own policy page, a CVE advisory, an OSS source file - resolves
  # PROG to whatever is locked and then fails the OOS-host check below, even though the
  # read has nothing to do with that locked program (observed live: cloudflare, program-90,
  # program-39 policy reads blocked while the session was locked to program-60). WebFetch is
  # a passive GET + summarize - it cannot submit an exploit payload, run a scan, or mutate
  # target state - so it is not the kind of activity this gate exists to forbid; Bash and
  # the MCP send_http path (where curl/nuclei/sqlmap actually run) are UNCHANGED below and
  # remain fully gated. The explicit NOSCOPE.txt deny check above still applies to WebFetch.
  if [ "$TOOL" = "WebFetch" ] && { [ -z "$PROG" ] || [ -z "$SCOPES" ]; }; then
    printf 'scope-gate NOTE: %s read with no scope file resolved for the active target (%s); WebFetch is read-only so this fails OPEN, unlike Bash/MCP probes.\n' "$H" "${PROG:-no target}" >&2
    continue
  fi
  if [ -z "$PROG" ]; then
    printf 'BLOCKED: %s has no active hunt target. Set HUNT_TARGET, a session LOCK, or run under targets/<program>/ before probing.\n' "$H" >&2
    exit 2
  fi
  if [ -z "$SCOPES" ]; then
    printf 'BLOCKED: %s has no readable scope file for active target %s.\n' "$H" "$PROG" >&2
    exit 2
  fi

  # In-scope test: host must match an IN-SCOPE allowlist entry in AT LEAST ONE
  # program's SCOPE.txt (host lines before the first OOS section divider). A host
  # listed only in an OOS carve-out does not pass.
  MATCHED=""
  ANYLIST=""
  READABLE=""
  HASCONTENT=""
  while IFS= read -r SF; do
    [ -z "$SF" ] && continue
    [ -r "$SF" ] && READABLE="yes"
    # a genuine content line = not blank, not a comment
    grep -qE '^[[:space:]]*[^#[:space:]]' "$SF" 2>/dev/null && HASCONTENT="yes"
    [ -n "$(scope_inscope_hosts "$SF")" ] && ANYLIST="yes"
    if host_in_scope "$H" "$SF"; then MATCHED="yes"; break; fi
  done <<EOSC
$SCOPES
EOSC
  [ -n "$MATCHED" ] && continue

  # WEBFETCH CARVE-OUT, continued: the host did not match the RESOLVED program's SCOPE.txt.
  # For WebFetch that resolved program is frequently just "whatever the session LOCK says"
  # (see the carve-out above, same root cause), so a mismatch here commonly means "this read
  # is about some OTHER, possibly not-yet-intaked program," not "this is an OOS probe target."
  # Already screened above: the explicit NOSCOPE.txt deny list (still enforced, unconditional)
  # and the platform/toolchain allowlists. Bash and MCP send_http are untouched below.
  if [ "$TOOL" = "WebFetch" ]; then
    printf 'scope-gate NOTE: %s not in resolved target %s SCOPE.txt; WebFetch is read-only so this fails OPEN (the read may be about a different/pre-intake program).\n' "$H" "${PROG:-<none>}" >&2
    continue
  fi

  # EMPTY-SCOPE FAIL-CLOSED (2026-09-30). The previous guard was a bare
  # `[ -z "$ANYLIST" ] && continue`, which conflated two very different states and so
  # turned an EMPTY scope file into allow-all. Verified before the fix: a 0-byte
  # targets/<prog>/SCOPE.txt let `totally-arbitrary-evil-host.example` through with exit 0.
  # That is reachable in normal operation, not a corner case: h1-scope.sh and ywh-scope.sh
  # can both exit 0 having written a comments-only SCOPE.txt (API returned no eligible
  # assets), and immunefi-scope.sh's fallback skeleton is entirely commented out by design.
  # Any of those silently disabled the gate for that target.
  # The three states are now separated, and the file's design rule ("a buggy gate that halts
  # the session is worse than a missed catch") is preserved for the two states it was written for:
  #   1. no scope file readable at all      -> FAIL-OPEN (unchanged)
  #   2. file has content but parsed to zero -> possible PARSER BUG -> FAIL-OPEN, but warn loudly
  #   3. file readable and genuinely empty   -> FAIL-CLOSED (this is the fix)
  if [ -z "$ANYLIST" ]; then
    if [ -z "$READABLE" ]; then
      continue
    fi
    if [ -n "$HASCONTENT" ]; then
      printf 'scope-gate WARNING: SCOPE.txt has content but parsed to ZERO in-scope entries (possible parser bug). Failing OPEN per design rule; host %s NOT verified in scope. Check targets/*/SCOPE.txt formatting.\n' "$H" >&2
      continue
    fi
    printf 'BLOCKED: scope file present but contains ZERO in-scope entries; refusing to treat an empty scope as allow-all (host %s). Populate targets/%s/SCOPE.txt, then verify with: scripts/intake.sh verify %s\n' "$H" "${PROG:-<program>}" "${PROG:-<program>}" >&2
    exit 2
  fi

  # Reached here -> OOS host (in-scope for no program). BLOCK.
  if [ -n "$PROG" ]; then
    printf 'OOS host %s not in targets/%s/SCOPE.txt (allowlist stops at the OUT-OF-SCOPE section)\n' "$H" "$PROG" >&2
  else
    printf 'OOS host %s not in-scope for ANY program under targets/*/SCOPE.txt\n' "$H" >&2
  fi
  exit 2
done <<EOF
$HOSTS
EOF

exit 0
