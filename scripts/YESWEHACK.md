# YesWeHack (YWH) program onboarding

Mirror of the HackerOne onboarding path (`h1-scope.sh` / `h1-rank-programs.sh`).
Two source channels feed the hunt loop; the API channel is the automation path,
YesWeBurp is a manual fallback for the operator.

## Channel 1 (PRIMARY, automated): the YWH REST API

Host: `https://api.yeswehack.com` (verified live 2026-06-15). This is YWH's own
platform API, the same one the official `yeswehack/YesWeBurp` extension and the
`yeswehack/ywh2bugtracker` tool call. Hitting it for program metadata is allowed,
exactly like `api.hackerone.com`. Do NOT point these scripts at any bounty target
host.

Endpoints (confirmed from YesWeBurp `api/API.kt` + live probes):

- `GET /programs?page=N`
  -> `{ "items":[{title,slug,bounty,bounty_reward_min,bounty_reward_max,
        reports_count,scopes_count,average_first_response_time,public,vdp,
        disabled,archived,status,type,...}], "pagination":{nb_pages,page,...} }`
  The public program list answers UNAUTHENTICATED (HTTP 200). Auth only adds the
  private programs you belong to.

- `GET /programs/<slug>`
  -> full program: `scopes:[{scope,scope_type,scope_type_name,asset_value}]`,
     `out_of_scope:[...]`, `qualifying_vulnerability:[...]`,
     `non_qualifying_vulnerability:[...]`, `rules` / `rules_html`,
     `account_access` / `account_access_html`, `reward_grid_default` and
     `reward_grid_{very_low,low,medium,high,critical}`, `public`, `vdp`,
     `bounty*`, `restricted_ips`, `business_unit`.

Host-like `scope_type` values (go into SCOPE.txt): `web-application`, `wildcard`,
`api`, `other`, `application`. Non-host types (`mobile-application-android/ios`,
etc.) are emitted under the OUT-OF-SCOPE divider as commented notes, never as
allowlist hosts.

### Auth

YWH supports two interchangeable bearer credentials on
`Authorization: Bearer <...>`:

1. Personal Access Token (PAT) - PREFERRED. Created on the YWH platform
   (Account -> API / Personal Access Tokens). Long-lived, no TOTP dance. As of
   ywh2bugtracker v2.5.0 the legacy OAuth/TOTP login options were removed in
   favor of the PAT, so this is the supported automation path. Set:
     `YWH_API_TOKEN=<pat>`

2. Email / password (-> short-lived JWT), with optional TOTP - FALLBACK. Flow
   from `api/API.kt`:
     - `POST /login`  body `{"email","password"}`
       -> `{"token","totp_token"}`. If `totp_token` is present, 2FA is required
          (mandatory for "Secured" programs).
     - `POST /account/totp`  body `{"token":<totp_token>,"code":<6-digit OTP>}`
       -> `{"token":<JWT>}`
     - Then `Authorization: Bearer <JWT>` on every request.
   Set: `YWH_EMAIL`, `YWH_PASSWORD`, and `YWH_TOTP` (current code) when 2FA is on.

Public programs need NO credential, so ranking and most onboarding run token-free.
Private/secured programs need a credential; the scripts emit a `NEEDS:` line if
one is missing.

### Secrets

Credentials live ONLY in `~/.config/gnoc/secrets.env` (chmod 600, outside the
workspace, gitignored), alongside the H1 vars. Variable names the scripts read:

```
YWH_API_TOKEN=<personal access token>     # preferred, single line
# or the login fallback:
YWH_EMAIL=<account email>
YWH_PASSWORD=<account password>
YWH_TOTP=<current 6-digit TOTP>            # only for 2FA / Secured programs
```

Never hardcode, echo, or commit a value. The scripts never print credentials.

## Channel 2 (FALLBACK, manual / the operator-only): the YesWeBurp extension

`YesWeBurp` (BApp, loaded in Burp Pro per
`reference_yesweburp_extension_2026_06_15.md`) lists every YWH program with its
Rules / Scopes / Qualifying-vulnerabilities / Account-access tabs and one-click
configures Burp scope. Login (email + password + TOTP) is the operator-only.

Programmatic readback via the Burp MCP is NOT viable for the program metadata:
- The extension fetches programs into in-memory Kotlin objects and fires them to
  the GUI via an internal EventBus (`programsLoaded.fire(programs)` in `API.kt`).
  It persists only credentials/settings through `saveExtensionSetting` (Settings.kt),
  NOT the scopes/rules/qualifying-vulns. So `mcp__burp__output_user_options` has
  nothing to read - the program data never lands in Burp's UserConfig.
- The ONE partial exception: after the operator clicks a program in the GUI, the
  extension writes that program's in-scope hosts into Burp's target scope
  `include` rules (BurpConfig.kt). Those hosts ARE readable via
  `mcp__burp__output_user_options` (`target.scope.include`), but it is hosts only
  (no rules / qualifying-vulns / rewards) and still requires a manual GUI click.
  Not automation-grade.

Verdict: treat YesWeBurp as a the operator-only browse channel. For automation use the
API scripts below, which call the exact same `/programs` + `/programs/<slug>`
endpoints YesWeBurp uses, so they produce equivalent data without the GUI.

## Scripts

- `scripts/ywh-rank-programs.sh`
  Ranks bounty-paying, live (not disabled/archived) programs by reward ceiling,
  then fewest reports, then fastest first-response. Runs token-free against the
  public list; add a credential to also see private programs. Columns mirror
  `h1-rank-programs.sh` so `loop-select-target.sh` / onboarding can consume it.
    `scripts/ywh-rank-programs.sh`

- `scripts/ywh-scope.sh <program-slug>`
  Pulls one program and writes `targets/<slug>/SCOPE.txt` (one in-scope host per
  line, same format `h1-scope.sh` emits: header comments, host lines, blank line,
  then a `# === OUT OF SCOPE ... ===` divider the scope-gate hook honors) +
  `targets/<slug>/PROGRAM.md` (visibility/bounty state, reward grid, qualifying /
  non-qualifying vulns, account access, rules). Self-provisions the bearer token
  from secrets.env (PAT or login->JWT). On a private/secured program with no
  credential it prints a `NEEDS:` line and exits non-zero.
    `scripts/ywh-scope.sh <slug>`

The `<slug>` is the YWH program slug (the `slug` field in the rank output, e.g.
`teamviewer-bounty-program`), used as the `targets/<slug>/` directory name just
like the H1 handle.

## NEEDS

- For PUBLIC YWH programs: nothing. Both scripts run token-free today.
- For PRIVATE / Secured YWH programs (or to see programs the operator is invited to):
  add `YWH_API_TOKEN` (preferred) - or `YWH_EMAIL` / `YWH_PASSWORD` (+ `YWH_TOTP`
  for 2FA) - to `~/.config/gnoc/secrets.env`. Absent that, private-program
  onboarding is the only blocked path; public onboarding already works.
