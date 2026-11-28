#!/usr/bin/env bash
#
# pattern-auto-suggest.sh - UserPromptSubmit hook
#
# Scans the user's prompt against patterns/INDEX.md trigger words and surfaces
# the top matching vulnerability patterns inline as additional context. This is
# the "Claude detects a pattern, knows to pull everything related in seconds"
# capability GreyNOC asked for.
#
# Output behavior:
#   - Silent when 0 matches (no noise on chats unrelated to hunting)
#   - Up to 8 top matches when triggered, ranked by number of distinct trigger words hit
#   - Format: class/id | severity | bounty | matched-triggers | 1-line fingerprint
#
# Hard rules:
#   - Trigger words must be >= 4 chars (skip noise: "race", "auth", etc. would
#     match too broadly; we still include them in INDEX but require length filter
#     to prevent false positives at suggest time).
#   - Skip very common english words that appear in trigger lists ("user", "data",
#     "file", "code", "test") via stopword filter.
#   - Cap output at 8 patterns to keep injection lightweight (~600 tokens max).
#   - Workspace-cwd-only: only fires for the specific bb workspace (parity with
#     contextual-memory-injector.sh) so it never injects on unrelated projects.
#   - FAIL-OPEN: exit 0 on any error (a non-zero + empty stderr surfaces as
#     user-visible noise in Claude Code); every branch below stays silent-exit-0.
#
# Exit codes:
#   0 = always (silent or with stdout context)

set -u  # NOT pipefail/-e: hook MUST exit 0 silently on any internal failure.

# FAIL-OPEN backstop: any unexpected error (a set -u unbound, an awk crash, a
# broken pipe) traps here and exits 0 so the hook can never emit a non-zero +
# empty-stderr that Claude Code would render as noise.
trap 'exit 0' ERR

INDEX="${GNOC_WORKSPACE:-$HOME/.gnoc}/patterns/INDEX.md"
[ -r "$INDEX" ] || exit 0

# Required tools (parity with contextual-memory-injector.sh); missing -> silent.
command -v jq  >/dev/null 2>&1 || exit 0
command -v awk >/dev/null 2>&1 || exit 0

# Read prompt from stdin JSON.
input=$(cat 2>/dev/null) || exit 0
[ -n "$input" ] || exit 0

# WORKSPACE-CWD-ONLY GATE (parity with contextual-memory-injector.sh). Only fire
# for the specific bb workspace so a shared global settings never injects pattern
# cards on an unrelated project. Missing/foreign cwd -> stay silent.
cwd=$(printf '%s' "$input" | jq -r '.cwd // empty' 2>/dev/null) || exit 0
case "$cwd" in
  ${GNOC_WORKSPACE:-$HOME/.gnoc}*) ;;
  *) exit 0 ;;
esac

prompt=$(printf '%s' "$input" | jq -r '.prompt // empty' 2>/dev/null) || exit 0
[ -n "$prompt" ] || exit 0

# Normalize prompt: lowercase + replace non-alnum with spaces.
norm=$(printf '%s' "$prompt" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9' ' ' | tr -s ' ')

# ---------------------------------------------------------------------------
# INTENT GATE (2026-06-10 retrieval-engine, context-budget lean pass).
# Anthropic context-engineering: suppress injection on clearly NON-hunting
# prompts (meta / token-cost / billing / status / file-mgmt / training) so the
# pattern budget stays lean and high-signal. The gate only fires when the prompt
# is BOTH (a) short-ish chatter AND (b) has no STRONG security signal, so a real
# hunting prompt that merely mentions "cost" or "status" is never suppressed.
#
# Why a gate and not just the >=2 score: tokens like "token"/"session"/"cost"
# legitimately appear in pattern trigger rows, so a meta prompt ("what is my
# token cost this session") scores >=2 and wrongly injects 3 crypto/session
# cards. The gate short-circuits that whole class before scoring.
#
# Fail-open: a STRONG security token (a CLASS_SHORT acronym, a spelled-out class
# already expanded above, or an explicit hunt verb) DISARMS the gate so we never
# suppress a genuine probe. Keep this list tight to avoid silencing real work.
META_RE='(token cost|token budget|token usage|token spend|rtk gain|how much.*(cost|token|paid|spend|owe|bill)|billing|invoice|my (cost|spend|usage|budget|bill)|git (status|add|commit|push|pull|log|diff|stash|branch|checkout)|^[[:space:]]*(ls|cd|cat|mkdir|rm|mv|cp|pwd|du|df)([[:space:]]|$)|list (the )?(files|dirs|directories|contents)|move (the )?file|rename (the )?file|delete (the )?file|trainer (cron|run)|run the trainer|what (skills|commands|hooks) |whats my|what is my (status|cost|budget|usage))'
STRONG_RE='\b(ssrf|xss|csrf|idor|xxe|sqli|ssti|rce|lfi|rfi|jwt|sso|mfa|oauth|saml|graphql|smuggl|deserial|clickjack|upload|prototype pollution|open redirect|hunt|probe|exploit|payload|bypass|takeover|injection|traversal|escalat|recon|vuln|cve-)'
if printf '%s' "$norm" | grep -Eq "$META_RE"; then
  if ! printf '%s' "$norm" | grep -Eq "$STRONG_RE"; then
    exit 0   # clearly non-hunting + no strong security signal -> stay silent
  fi
fi

# WORKSPACE-META SUPPRESSOR (2026-07-19). A prompt ABOUT our own tooling (the hook,
# the pattern library, build-index, settings.json, the hunt-loop, the doctrine) is
# meta-development, not a hunt - even when it names a vuln class ("the injection
# hook", "improve the ssrf detection in the scorer"). The STRONG_RE disarm above is
# WRONG here (a class word is the false positive), so this runs as its OWN gate and
# is deliberately NOT disarmed by STRONG_RE. Tokens are unambiguous references to
# THIS workspace's machinery; bare \bhook\b is boundary-safe vs "webhook" (no word
# boundary inside "webhook", so a webhook-SSRF hunt still fires). Fail-silent.
# The trailing alternatives (added 2026-07-19 root-fix regression guard) catch the
# meta-dev VERB+OBJECT shapes that survive the generic-content stopword strip because
# their sole remaining content token is a legit trigger word ("index"/"scoring"):
# "rebuild/regenerate/reindex the index", "the scoring", "the pattern scoring". Anchored
# on the meta verb or "the scoring" so a real hunt ("IDOR on the index endpoint",
# "reward flywheel user index") is untouched - no hunt says "regenerate the index".
WSMETA_RE='\b(hook|pattern[- ]?(auto[- ]?)?suggest|auto[- ]?suggest|patterns? (library|cards?|index|corpus|match|scoring)|build[- ]?index|pat\.?sh|idf\.?tsv|settings\.?json|reasoning doctrine|spine\.?md|claude\.?md|hunt[- ]?(loop|cycle)|the (scorer|indexer|linter|retrieval|scoring)|inject(ion|ed)? hook|(rebuild|regenerate|regenerating|rebuilding|reindex|refactor|optimi[sz]e) (the |all )?(index|scoring|scorer))\b'
if printf '%s' "$norm" | grep -Eq "$WSMETA_RE"; then
  exit 0   # meta-conversation about the hunt system itself -> no card injection
fi

# Spanish to English alias map (2026-05-24 trainer extension). Phase 1 real-prompt
# measurement showed ~40% of misses were on Spanish-language hunting prompts where
# none of the keywords cleared the INDEX-trigger filter. We pre-translate common
# Spanish security vocabulary so the same prompt scores against the same patterns.
# This is additive: we APPEND the English form to the prompt (so the English token
# also contributes a score hit if the original Spanish word remains).
norm=$(printf '%s' "$norm" | sed -E '
  s/\bmovil\b/movil mobile/g
  s/\baplicacion\b/aplicacion application/g
  s/\bregistrada\b/registrada registered/g
  s/\binstalada\b/instalada installed/g
  s/\bsuperficie\b/superficie surface/g
  s/\bbuscar\b/buscar hunt/g
  s/\bencontrar\b/encontrar find/g
  s/\bprueba\b/prueba test probe/g
  s/\bpruebas\b/pruebas tests probes/g
  s/\bdocumento\b/documento document/g
  s/\barchivo\b/archivo file/g
  s/\busuario\b/usuario user/g
  s/\bcontrasena\b/contrasena password/g
  s/\binyeccion\b/inyeccion injection/g
  s/\bdesbordamiento\b/desbordamiento overflow/g
  s/\bvulnerabilidad\b/vulnerabilidad vulnerability/g
  s/\bataque\b/ataque attack/g
  s/\bcuenta\b/cuenta account/g
  s/\bautenticacion\b/autenticacion authentication/g
  s/\bautorizacion\b/autorizacion authorization/g
  s/\bsesion\b/sesion session/g
  s/\bcorreo\b/correo email/g
  s/\bgestor\b/gestor manager/g
  s/\bgestion\b/gestion management/g
  s/\bservidor\b/servidor server/g
  s/\bcliente\b/cliente client/g
  s/\bpagina\b/pagina page/g
  s/\bllaves\b/llaves keys/g
  s/\btoken\b/token token/g
  s/\bbarrida\b/barrida sweep/g
  s/\bsuperficies\b/superficies surfaces/g
  s/\brevision\b/revision review/g
  s/\bxss\b/xss xss/g
  s/\bxxs\b/xxs xss/g
  s/\binyecciones\b/inyecciones injections/g
' | tr -s ' ')

# EN spelled-out -> acronym expansion (2026-06-08 archmax recall fix, held-out P10).
# Hunters often spell out the class ("server side request forgery"); INDEX triggers
# store the acronym ("ssrf"). After tr -c the prose never yields the acronym token,
# so the precise card never scores. Additive: append the acronym so it also scores.
# Acronyms (ssrf/xss/csrf/idor/...) are in CLASS_SHORT, so they bypass the >=4 filter.
norm=$(printf '%s' "$norm" | sed -E '
  s/server side request forgery/server side request forgery ssrf/g
  s/server side request/server side request ssrf/g
  s/cross site scripting/cross site scripting xss/g
  s/cross site request forgery/cross site request forgery csrf/g
  s/insecure direct object references/insecure direct object references idor/g
  s/insecure direct object reference/insecure direct object reference idor/g
  s/insecure direct object/insecure direct object idor/g
  s/server side template injection/server side template injection ssti/g
  s/remote code execution/remote code execution rce/g
  s/local file inclusion/local file inclusion lfi/g
  s/remote file inclusion/remote file inclusion rfi/g
  s/xml external entity/xml external entity xxe/g
  s/sql injection/sql injection sqli/g
  s/single sign on/single sign on sso/g
  s/multi factor authentication/multi factor authentication mfa/g
  s/two factor authentication/two factor authentication mfa/g
' | tr -s ' ')

# Contracted multi-word trigger phrases (2026-06-08 archmax recall fix, held-out P8).
# A few high-value INDEX triggers are stored as single contracted tokens
# ("mapskey", "keyrestriction") that prose ("maps api key", "no application
# restriction") never reproduces after tr -c. Additive phrase -> contracted-token
# expansion so the precise card gets its hits and clears the >=3 primary gate.
norm=$(printf '%s' "$norm" | sed -E '
  s/maps api key/maps api key mapskey/g
  s/google maps key/google maps key mapskey/g
  s/key restriction/key restriction keyrestriction/g
  s/api key restriction/api key restriction keyrestriction/g
  s/application restriction/application restriction keyrestriction/g
  s/no restriction/no restriction keyrestriction/g
  s/gift card/gift card giftcard/g
  s/double credit/double credit doublecredit/g
  s/double spend/double spend doublespend/g
  s/tool call/tool call toolcall/g
  s/model context protocol/model context protocol mcp/g
  s/rate limit/rate limit ratelimit/g
  s/open redirect/open redirect openredirect/g
  s/brute force/brute force bruteforce/g
  s/cross tenant/cross tenant crosstenant/g
  s/session cookie/session cookie sessioncookie/g
  s/reset token/reset token resettoken/g
  s/host header/host header hostheader/g
  s/privilege escalation/privilege escalation privesc/g
  s/read only/read only readonly/g
' | tr -s ' ')

# Verb -> noun stem expansion (2026-06-10 audit fix, backlog #23). INDEX triggers
# store the noun ("injection", "escalation", "deserialization", "traversal") but
# prose uses the verb ("injects", "escalate", "deserializes"). Additive: append
# the noun form so the precise card scores. Whole-word, never removes a token.
norm=$(printf '%s' "$norm" | sed -E '
  s/\binject(s|ed|ing)?\b/& injection/g
  s/\bescalat(e|es|ed|ing)\b/& escalation/g
  s/\bdeserializ(e|es|ed|ing|ation)?\b/& deserialization/g
  s/\btravers(e|es|ed|ing|al)?\b/& traversal/g
' | tr -s ' ')

# Stopwords (overlap with common english that bloat trigger matches).
# 2026-05-24 trainer extension: numeric and bounty-formatting tokens added so
# "$500", "1000", "3000" stop biasing scores toward bounty-mentioning patterns.
# 2026-07-19 generic-content root-fix: the generic-content / instruction / time /
# Spanish-autonomy words moved to the SHARED patterns/_meta/stopwords-generic.txt
# (single source of truth, also consumed by build-index.sh at IDF-emit time). The
# inline STOP_BASE below keeps only QUERY-ONLY tokens that are NOT corpus terms:
# numeric/bounty-format tokens, bounty/severity words, and hunt-verb chatter that
# must not drive scoring but has no place in the index-time term list. The shared
# file's terms are appended so the query-time stop set == corpus-drop set for every
# generic word. FAIL-OPEN: a missing shared file leaves STOP == STOP_BASE (never errors).
STOP_BASE="user data file code test http https json html with from when this that into more less than user info type rule used uses make made date time line item list each name path size form page note here only just been some most less know like want need help work many much such them they have will been just 0000 1000 1500 2000 2500 3000 5000 7500 10000 15000 25000 50000 paid awarded medium high critical severity bounty range what whats cost costs hunt hunting probe probes find found please your mine about would could should does what's centrate correcto correctamente inyectan inyecten"
STOPGEN="${GNOC_WORKSPACE:-$HOME/.gnoc}/patterns/_meta/stopwords-generic.txt"
STOP="$STOP_BASE"
if [ -r "$STOPGEN" ]; then
  # Strip comments/blank lines, flatten to a space-joined token run, append to STOP.
  gen=$(sed -e 's/#.*//' "$STOPGEN" 2>/dev/null | tr 'A-Z' 'a-z' | tr -s '[:space:]' ' ') || gen=""
  STOP="$STOP $gen"
fi

# Short class-keyword whitelist (2026-05-24 trainer extension): canonical class
# tokens bypass the >=4-char filter. Phase 1 measurement showed many real hunting
# prompts use only these short tokens; the prior filter dropped them.
CLASS_SHORT="xss ssrf rce idor csrf xxe sqli ssti jwt lfi rfi mfa sso cve cwe"

# Build a deduped list of words: >=4 chars + not in stopwords, OR a class-short token.
mapfile -t words < <(
  for w in $norm; do
    case " $CLASS_SHORT " in *" $w "*) echo "$w"; continue ;; esac
    [ ${#w} -ge 4 ] || continue
    case " $STOP " in *" $w "*) continue ;; esac
    echo "$w"
  done | sort -u
)
[ ${#words[@]} -gt 0 ] || exit 0

# ---------------------------------------------------------------------------
# CLASS DETECTION (feeds the awk class-boost). Reuse CLASS_BROAD/CLASS_SHORT and
# the same specificity priority the fallback used, so the query's dominant vuln
# class is known BEFORE scoring. Empty when no class token is present (no boost).
CLASS_BROAD="api auth business-logic client-side cloud crypto electron infra injection llm mobile ssrf web3 apk webview deeplink graphql oauth saml ldap kerberos jwt cors csrf xss ssrf rce idor xxe sqli ssti smuggling deserialization race clickjacking upload redirect"
FB_PRIORITY="ssrf idor rce xss csrf xxe sqli ssti clickjacking lfi rfi jwt mfa sso graphql oauth saml ldap kerberos cors smuggling deserialization deeplink webview apk electron web3 crypto llm injection cloud infra mobile client-side business-logic api auth upload redirect race"
seen_class_tokens=""
for w in "${words[@]}"; do
  case " $CLASS_BROAD " in *" $w "*)
    case " $seen_class_tokens " in *" $w "*) ;; *) seen_class_tokens="$seen_class_tokens $w" ;; esac
    ;;
  esac
done
detected_class=""
for p in $FB_PRIORITY; do
  case " $seen_class_tokens " in *" $p "*) detected_class="$p"; break ;; esac
done
[ -z "$detected_class" ] && detected_class=$(printf '%s' "$seen_class_tokens" | awk '{print $1}')
# Map a detected acronym/keyword to the INDEX `class` column value so the class
# column comparison lands (e.g. detected "ssrf" -> class "ssrf"; "oauth" -> "auth";
# "sqli"/"xss" -> "injection"/"client-side"). Only maps the ones whose keyword
# differs from the class dir; everything else compares directly.
class_col=""
case "$detected_class" in
  oauth|saml|jwt|sso|mfa|ldap|kerberos) class_col="auth" ;;
  sqli|ssti|rce|lfi|rfi|xxe|deserialization) class_col="injection" ;;
  xss|csrf|clickjacking|redirect) class_col="client-side" ;;
  smuggling) class_col="infra" ;;
  idor) class_col="api" ;;
  ssrf|web3|cloud|crypto|electron|infra|llm|mobile|api|business-logic) class_col="$detected_class" ;;
  *) class_col="$detected_class" ;;
esac

# Score each pattern by the IDF-WEIGHTED sum of the distinct prompt terms that hit
# its INDEX row (2026-07-19 retrieval-ranking upgrade). INDEX.md is now:
#   | id | class | severity | bounty_range | triggers | fingerprint |
# Scoring (see patterns/_research/retrieval-ranking-best-practice-2026.md):
#   - base    = SUM over distinct matched query terms of idf[term] * fieldweight
#               (fieldweight 1.0 for a triggers-cell hit, 1.5 for a fingerprint-cell
#               hit; a term hitting both counts ONCE at the higher weight).
#               Generic terms (low IDF) contribute ~0 -> generic-word noise dies.
#   - phrase  = + sum-of-term-IDFs for any multi-word trigger phrase that appears
#               verbatim as a substring of the (expanded) prompt (precise-card lift).
#   - class   = + a fixed boost when the card's class column == the detected query class.
# Gate (relative floor, replaces the fixed >=3 count):
#   - keep a card only if score >= max(MINABS, topScore*0.5) AND it has >=1 matched
#     term whose IDF exceeds the median IDF of the query's matched-term universe
#     (the "non-generic hit" rule that kills 3-generic-word false positives).
# Cap: TOP-5 (was 8). Fail-open: a missing/empty IDF.tsv falls back to weight 1.0
# per term (degrades to the old count behaviour, never errors).
IDFTSV="${GNOC_WORKSPACE:-$HOME/.gnoc}/patterns/_meta/IDF.tsv"
FALLBACK_PREFACE=""
scored=$(
  awk -v words="$(printf '%s\n' "${words[@]}" | paste -sd' ')" \
      -v idffile="$IDFTSV" \
      -v promptnorm=" $norm " \
      -v qclass="$class_col" \
      -v nwords="${#words[@]}" \
      -v acr="$CLASS_SHORT" '
    BEGIN {
      n = split(words, w, " "); for (i=1;i<=n;i++) ws[w[i]] = 1
      # Load IDF.tsv into idf[term]. Missing file -> every term weight defaults to
      # 1.0 (DEFIDF) so scoring degrades to a plain hit-count, never fails.
      DEFIDF = 1.0
      haveidf = 0
      if (idffile != "") {
        while ((getline line < idffile) > 0) {
          nt = split(line, a, "\t")
          if (nt >= 2) { idf[a[1]] = a[2] + 0; haveidf = 1 }
        }
        close(idffile)
      }
      PHRASEW = 1.0     # multiplier on a verbatim multi-word-trigger phrase bonus
      FPW     = 1.5     # fingerprint-cell field weight (triggers-cell weight = 1.0)
      CLASSBOOST = 2.0  # fixed additive bonus when the card class matches the query
      MINABS  = 3.0     # absolute score floor (about one discriminating-term hit)
      TAU     = 0.5     # relative floor: keep card only if score >= TAU * topScore
      # ABSGENERIC: the IDF above which a term is genuinely DISCRIMINATING (not
      # generic security filler). Measured on this corpus, generic vocabulary
      # (request/token/account/authorization/session/bypass/user/auth) sits at
      # IDF < ~3.0 while class/mechanism terms (oauth/ssrf/cache/rbac/rebinding/
      # deception/webhook) sit >= ~3.2. A kept card MUST have >=1 hit at or above
      # max(query-median, ABSGENERIC) so an all-generic prompt (only low-IDF words)
      # surfaces nothing rather than random criticals.
      ABSGENERIC = 3.0
      ncards  = 0
    }
    function termidf(t,   v) {
      if (haveidf && (t in idf)) return idf[t]
      if (haveidf) return 0        # known corpus, term absent from it -> 0 (generic/none)
      return DEFIDF                # no IDF file -> flat weight
    }
    /^\| [a-z0-9]/ {
      row = $0
      sub(/^\| /, "", row)
      sub(/ \|[ \t]*$/, "", row)
      nf = split(row, F, / \| /)
      if (nf < 5) next
      id = F[1]; cls = F[2]; sev = F[3]; bounty = F[4]
      if (id == "id") next                 # skip the header row
      trigcell = tolower(F[5])
      fpcell   = (nf >= 6) ? tolower(F[6]) : ""

      # Normalised, space-padded token views for whole-token substring matching.
      tnorm = trigcell; gsub(/[^a-z0-9]/, " ", tnorm); tnorm = " " tnorm " "
      fnorm = fpcell;   gsub(/[^a-z0-9]/, " ", fnorm); fnorm = " " fnorm " "

      score = 0
      hits = ""
      besthit_idf = -1                     # highest IDF among this card matched terms
      nmatch = 0                           # distinct query terms this card matched
      ntrig  = 0                           # of those, how many hit the CURATED triggers cell
      for (k in ws) {
        hit_t = index(tnorm, " " k " ") > 0
        hit_f = index(fnorm, " " k " ") > 0
        if (!hit_t && !hit_f) continue
        wt = hit_f ? FPW : 1.0             # fingerprint hit outweighs a trigger hit
        iv = termidf(k)
        score += iv * wt
        hits = hits " " k
        nmatch++
        if (hit_t) ntrig++                 # curated-trigger hit (high precision)
        if (iv > besthit_idf) besthit_idf = iv
        matchedterm[k] = 1                 # query-wide matched-term universe (for median)
      }
      if (score <= 0) next

      # Phrase/bigram bonus: any multi-word trigger phrase present verbatim in the
      # prompt adds the sum of its own term IDFs (rewards the precise card the
      # single-token count misses). F[5] triggers are comma-separated phrases.
      np = split(F[5], phr, /,/)
      for (pi = 1; pi <= np; pi++) {
        ph = tolower(phr[pi])
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", ph)
        if (ph == "" || index(ph, " ") == 0) continue   # single-word: already scored
        if (index(promptnorm, " " ph " ") > 0) {
          pn = split(ph, pw, " "); psum = 0
          for (pj = 1; pj <= pn; pj++) psum += termidf(pw[pj])
          score += psum * PHRASEW
        }
      }

      # Class-boost.
      classhit = 0
      if (qclass != "" && cls == qclass) { score += CLASSBOOST; classhit = 1 }

      ncards++
      C_id[ncards]=id; C_cls[ncards]=cls; C_sev[ncards]=sev; C_bounty[ncards]=bounty
      C_score[ncards]=score; C_hits[ncards]=hits; C_bestidf[ncards]=besthit_idf
      C_classhit[ncards]=classhit; C_nmatch[ncards]=nmatch; C_ntrig[ncards]=ntrig
      if (score > topScore) topScore = score
    }
    END {
      if (ncards == 0) exit 0

      # Median IDF of the query matched-term universe -> the non-generic bar.
      mc = 0
      for (t in matchedterm) { mc++; mv[mc] = termidf(t) }
      # insertion sort (small array)
      for (i = 2; i <= mc; i++) { x = mv[i]; j = i - 1; while (j >= 1 && mv[j] > x) { mv[j+1]=mv[j]; j-- } mv[j+1]=x }
      medidf = (mc == 0) ? 0 : ((mc % 2) ? mv[(mc+1)/2] : (mv[mc/2] + mv[mc/2+1]) / 2)

      floor = (MINABS > topScore * TAU) ? MINABS : topScore * TAU
      # Discrimination bar = the stricter of the query-local median and the absolute
      # generic threshold. On a technical query the median dominates; on an
      # all-generic query ABSGENERIC dominates and nothing clears it -> silent.
      discbar = (medidf > ABSGENERIC) ? medidf : ABSGENERIC

      for (i = 1; i <= ncards; i++) {
        if (C_score[i] < floor) continue
        # non-generic gate: need >=1 matched hit whose IDF is at least the
        # discrimination bar, OR the card cleared on a class match (a same-class
        # card is topical even if its lexical hits are common). A card whose best
        # hit is below the bar (matched ONLY generic words) is dropped.
        if (C_bestidf[i] < discbar && !C_classhit[i]) continue
        # COORDINATION / minimum-should-match gate (2026-07-19, both research agents:
        # Lucene coord() + Elasticsearch minimum_should_match; BM25 rarity != term
        # informativeness). ROOT of the false-positive class: a rare-but-generic word
        # ("internet" IDF 5.16 > ssrf 3.26; "keep"/"setup"/"scoring") is the LONE
        # content word a long prose/meta prompt shares with a card, so the card scores
        # on ONE incidental term. Rule: when the query carries >=2 content terms, a
        # card must match >=2 distinct ones (a 1-of-many hit is incidental). A genuine
        # single-term query (nwords<2, a deliberate class lookup) or a lone bare class
        # acronym (ssrf/idor) is high-signal and exempt; a lone hit must also land on
        # the CURATED triggers field, never incidental fingerprint prose. Class-boosted
        # cards are topical and exempt.
        if (!C_classhit[i]) {
          reqmatch = (nwords >= 2) ? 2 : 1
          single = C_hits[i]; gsub(/^[ \t]+|[ \t]+$/, "", single)
          is_acr = (C_nmatch[i] == 1 && index(" " acr " ", " " single " ") > 0)
          if (C_nmatch[i] < reqmatch && !is_acr) continue
          if (C_nmatch[i] == 1 && C_ntrig[i] < 1 && !is_acr) continue
        }
        # severity-weighted rank key: score dominates within reason, severity breaks
        # near-ties (a same-score critical outranks a medium). score scaled x100.
        sw = (C_sev[i] ~ /crit/) ? 4 : (C_sev[i] ~ /high/) ? 3 : (C_sev[i] ~ /med/) ? 2 : 1
        rankkey = C_score[i] * 100 + sw
        printf "%.4f\t%.4f\t%s\t%s/%s\t%s\t%s\n", rankkey, C_score[i], C_hits[i], C_cls[i], C_id[i], C_sev[i], C_bounty[i]
      }
    }
  ' "$INDEX" | sort -t$'\t' -k1,1nr | head -n 5 \
  | awk -F'\t' '{ printf "%s\t%s\t%s\t%s\t%s\n", $2, $3, $4, $5, $6 }'
)

[ -n "$scored" ] || exit 0

# ---------------------------------------------------------------------------
# STACK-ROUTING (2026-06-10 Anthropic specialized-toolkit adaptation, rank 18).
# After the pattern suggestion, emit ONE additional "ROUTE:" line naming the
# specialized toolkit skill for a detected stack signal in the prompt. This is a
# pure APPEND to the existing output: it runs only AFTER $scored is non-empty (so
# it inherits the intent gate above and stays silent on non-hunting prompts), and
# it never alters which patterns were matched/ranked. Detection is on $norm (the
# already alias/acronym-expanded, lowercased prompt). When several stack signals
# coexist (e.g. sanitizer + CSP) we route to all matching toolkits on the one line.
#   GraphQL                          -> graphql-toolkit
#   CDN+origin layering / smuggle    -> http-smuggling
#   sanitizer / CSP                  -> xss-toolkit + csp-bypass
#   OAuth / redirect_uri             -> oauth-deep
#   websocket / ws upgrade           -> ws-cswsh
#   403 / WAF (vendor unknown)       -> waf-bypass
route=""
addroute() { case " $route " in *" $1 "*) ;; *) route="${route:+$route }$1" ;; esac; }
printf '%s' "$norm" | grep -Eq '\bgraphql\b' && addroute graphql-toolkit
printf '%s' "$norm" | grep -Eq '(\bsmuggl|\bcl te\b|\bte cl\b|\bh2 cl\b|\bh2 te\b|\bdesync\b|request splitting|cdn.*origin|origin.*cdn|\bcdn\b)' && addroute http-smuggling
if printf '%s' "$norm" | grep -Eq '(saniti[sz]|dompurify|strips? the tags?|unescaped|\bcsp\b|content security|script src|strict dynamic|\bnonce\b)'; then
  addroute xss-toolkit
  addroute csp-bypass
fi
printf '%s' "$norm" | grep -Eq '(\boauth\b|\boidc\b|redirect uri|redirect_uri|authorization code|\bopenid\b)' && addroute oauth-deep
printf '%s' "$norm" | grep -Eq '(\bwebsocket\b|\bws\b|\bwss\b|\bcswsh\b|socket upgrade|\bupgrade\b.*\bwebsocket\b)' && addroute ws-cswsh
printf '%s' "$norm" | grep -Eq '(\b403\b|\bwaf\b|blocked payload|request blocked|forbidden|wafw00f|datadome|cloudflare block)' && addroute waf-bypass
printf '%s' "$norm" | grep -Eq '(\bhunt\b|\brecon\b|new target|start(ing)? (a )?(hunt|target|session)|first pass|where (do i|to) start)' && route="${route:+$route }IDEATION[/hyp+/analogy MANDATORY before playbook] CRITICAL-FIRST[hunt ATO/RCE/BOLA/auth-bypass/payment goal first, Medium is a checkpoint] CHAIN-REFLEX[on every primitive ask: chain to Crit?]"
printf '%s' "$norm" | grep -Eq '(\b403\b|\b404\b|empty body|dead end|stuck|exhaust|nothing|by design|informative|same response)' && route="${route:+$route }DEADEND[/pivot+/lateral+/dig: invert the dev assumption, do not pivot target]"

# UserPromptSubmit hook output protocol: stdout is appended to the user prompt as
# context. scored columns (tab-separated): score, matched-hits, class/id, severity, bounty.
# (Dead stderr render block removed 2026-06-08: hook always exits 0, so stderr never surfaced.)

cat <<EOF
[pattern-library-auto-match]
${FALLBACK_PREFACE:+(fallback) $FALLBACK_PREFACE}
$(while IFS=$'\t' read -r score hits pat sev bounty; do
    hits_trim=$(echo "$hits" | xargs | tr ' ' ',' | cut -d, -f1-5)
    echo "- $pat ($sev, $bounty) matched: $hits_trim"
  done <<< "$scored")
${route:+ROUTE: stack signal detected -> load specialized toolkit skill(s): $route}
NOVEL-NUDGE: these cards are known/likely-duped shapes. Before reusing one, ask what is unique to THIS target's trust model that no card covers, and spend one probe on that lateral hypothesis first.
[end pattern-library-auto-match]
EOF

exit 0
