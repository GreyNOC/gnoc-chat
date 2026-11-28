# gnoc_line - THE LINE (CLI reference)

Process, stations, gates, payouts: `scripts/HUNT-PROCESS-V2.md`. Code: `scripts/gnoc_line.py`.
Tests: `python3 -W error::ResourceWarning scripts/test_gnoc_line.py`.

```
gnoc_line.py open <p> --json wo.json | --data <urlencoded JSON>     station 0 SALES
gnoc_line.py advance <p> <wo> <1-8|NAME> <artifact path> | --data <urlencoded JSON>
gnoc_line.py market <p> <wo> --file HY.json[,AT.json] [--only id1,id2]   station 3 (commits oracles)
gnoc_line.py log <p> <H#> <capture>...                               floor: one probe per distinct file
gnoc_line.py burst <p> <H#> --serial <control> <arm> <arm>...        floor: a burst with its serial control
gnoc_line.py current <p> | show <p> <wo>                             the open work order (JSON)
gnoc_line.py status [<p>] | brief <p> <wo> [--bot B] | trap
```

Every JSON-printing command exits 0 on ok and 3 on a refusal; the refusal's `check` names the failing check.
Gate functions: gate_sales, gate_intel, gate_model, gate_market, gate_probe, gate_escalate, gate_qa,
gate_books, gate_retro. Python API: open, advance, market, log_capture, log_burst, current, status, brief,
trap_list, tids. `gnoc line` passthrough in scripts/gnoc is owed to the orchestrator.
