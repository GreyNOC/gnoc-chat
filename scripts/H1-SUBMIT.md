# H1 Hacker API: report submission contract (verified 2026-10-19)

Source: https://api.hackerone.com/hacker-resources/ (sections Create Report, Get Structured Scopes,
Get Weaknesses, Report Intents). Auth: HTTP Basic `HACKERONE_HANDLE:HACKERONE_API_TOKEN`
(`~/.config/gnoc/secrets.env`). Base: `https://api.hackerone.com/v1/hackers`.

## Create report: `POST /v1/hackers/reports` (#reports-create-report)
Headers `Content-Type: application/json`, `Accept: application/json`.
```
{"data":{"type":"report","attributes":{
  "team_handle":"<program>",            // required
  "title":"...",                        // required
  "vulnerability_information":"...",    // required, markdown: steps, material, references
  "impact":"...",                       // required
  "severity_rating":"none|low|medium|high|critical",  // optional
  "weakness_id":0,                      // optional integer (weakness object id, NOT the CWE number)
  "structured_scope_id":0}}}            // optional integer
```
Success returns the report object (`data.id`); URL is `https://hackerone.com/reports/<id>`.

## Lookups (read-only GETs, paginated with `links.next`, `page[size]`)
- Scopes: `GET /programs/{handle}/structured_scopes` (NOT embedded in `GET /programs/{handle}`).
  attributes: asset_type, asset_identifier, eligible_for_bounty, eligible_for_submission, max_severity.
- Weaknesses: `GET /programs/{handle}/weaknesses`; attributes.external_id is e.g. `cwe-602`,
  `id` is the value for `weakness_id` (vandelay: cwe-602 -> 102).
- Also: `/programs/{handle}/scope_exclusions`, `GET /reports/{id}`, `GET /me/reports`.

## Attachments: NOT available on Create Report
The create call has no attachment field and there is no `POST /reports/{id}/attachments`
in the Hacker API. The only upload endpoint is for REPORT INTENTS (Report Assistant flow):
`POST /report_intents/{id}/attachments` (multipart `files[]`), `GET`/`DELETE` variants,
`POST /report_intents` (`team_handle`, `description`), `PATCH /report_intents/{id}`,
`POST /report_intents/{id}/submit`. The program must have Report Assistant enabled, and the
intent flow takes a free-text description that H1 pipelines restructure, so this tool does
not use it. Attachments (repro.sh, capture.log) must be added by hand in the web UI after
filing, or inlined in the PoC.

## Tool
`scripts/h1-submit-report.py` (see its docstring). QAQC runs on the sanitized submitted
content (Gate:/Dedup:/ESCALATION TARGET:/**Unlock: lines removed), because the raw draft
always fails the internal-stamp checks by design.

## LIMITATION (2026-10-19, T-249): required custom fields
The Hacker API create carries NO custom fields and NO attachments. A program whose policy lists required form
fields (Globex: Affected URL, Affected Version(s), Sandbox ID) answers HTTP 400 "Required custom fields must be
filled in" to every API create, and the dry run cannot show it. Grep PROGRAM.md for those field names first; if
present, build the UI package (FILE-BY-HAND.md + paste body + attachments/) instead of running this script.
