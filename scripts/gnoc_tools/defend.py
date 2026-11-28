"""Blue-team tools, enforcement and the defender command surface."""
from gnoc_core.runtime import bind
import gnoc_platform


def _defender_state(ctx):
    s = getattr(ctx, "s", None)
    if s is None:
        return {}
    return s.setdefault("defender", {})


def _defender_target(st):
    """A target from the saved chat state is still untrusted input: it must be a safe ssh destination."""
    (
        gnoc_enforce,
    ) = bind(
        "gnoc_enforce",
    )
    dest = st.get("target") if isinstance(st, dict) else None
    return dest if dest and gnoc_enforce.valid_dest(dest) else None


def _enforce_action(prof, op, target="", endpoint="", pid=0, ttl=1800):
    """Build one enforcement finding for defend(action=enforce). -> (finding, error)."""
    (
        gnoc_defender, gnoc_enforce,
    ) = bind(
        "gnoc_defender", "gnoc_enforce",
    )
    op = str(op or "").strip().lower().replace("_", "-")
    tgt = str(target or "").strip()
    ep = str(endpoint or "").strip()
    try:
        ttl = int(ttl)
    except (TypeError, ValueError):
        ttl = 1800
    ttl = max(60, min(86400, ttl))
    gw, plat = gnoc_enforce.gateway_dest(prof), gnoc_enforce.gateway_platform(prof)
    api, iface = gnoc_enforce.gateway_api(prof), gnoc_enforce.gateway_iface(prof)
    if op in ("block-ip", "block", "gateway-block-ip", "unblock-ip", "unblock"):
        if not (gw or api):
            return None, "no gateway enforcement configured; run /defender setup"
        kind = "gateway_unblock_ip" if op.startswith("unblock") else "gateway_block_ip"
        act = {"kind": kind, "ip": tgt, "ttl": ttl, "dest": gw, "platform": plat, "api": api}
        return ({**gnoc_defender._f(f"enforce:{kind}:{tgt}", "info", "enforcement",
                                    f"operator enforcement: {kind} {tgt}", "", act)}, "")
    if op in ("block-mac", "block-mac", "gateway-block-mac", "unblock-mac"):
        if not (gw or api):
            return None, "no gateway/AP enforcement configured; run /defender setup"
        kind = "gateway_unblock_mac" if op.startswith("unblock") else "gateway_block_mac"
        act = {"kind": kind, "mac": tgt, "ttl": ttl, "dest": gw, "platform": plat, "iface": iface, "api": api}
        return ({**gnoc_defender._f(f"enforce:{kind}:{tgt}", "info", "enforcement",
                                    f"operator enforcement: {kind} {tgt}", "", act)}, "")
    if op in ("deauth", "kick"):
        if not (api or gw):
            return None, "no gateway/AP enforcement configured; run /defender setup"
        act = {"kind": "gateway_deauth", "mac": tgt, "dest": gw, "platform": plat, "iface": iface, "api": api}
        return ({**gnoc_defender._f(f"enforce:deauth:{tgt}", "info", "enforcement",
                                    f"operator enforcement: deauth {tgt}", "", act)}, "")
    ep = ep or tgt
    if not ep:
        return None, "this operation needs an endpoint SSH destination (or target=<user@host>)"
    if op in ("isolate", "endpoint-isolate"):
        act = {"kind": "endpoint_isolate", "dest": ep, "ttl": ttl}
    elif op in ("unisolate", "endpoint-unisolate"):
        # the isolation's one-time token lives in this machine's journal (the helper never shows it again)
        act = {"kind": "endpoint_unisolate", "dest": ep, "token": gnoc_defender.isolation_token(ep)}
    elif op in ("pause", "endpoint-pause", "kill", "endpoint-kill", "resume", "endpoint-resume"):
        try:
            n = int(pid or 0)
        except (TypeError, ValueError):
            n = 0
        if n <= 1:
            return None, "pause/kill/resume need pid=<number above 1>"
        kind = {"pause": "endpoint_pause", "kill": "endpoint_kill", "resume": "endpoint_resume"}.get(
            op.replace("endpoint-", ""))
        act = {"kind": kind, "dest": ep, "pid": n}
    elif op in ("endpoint-block-ip", "endpoint-release", "release"):
        kind = "endpoint_release" if op in ("release", "endpoint-release") else "endpoint_block_ip"
        act = {"kind": kind, "dest": ep, "ip": tgt, "ttl": ttl}
    else:
        return None, ("op is block-ip|unblock-ip|block-mac|unblock-mac|deauth|isolate|unisolate|pause|kill|"
                      "resume|endpoint-block-ip|release")
    return ({**gnoc_defender._f(f"enforce:{act['kind']}:{ep}:{act.get('pid') or act.get('ip') or ''}",
                                "info", "enforcement", f"operator enforcement: {act['kind']} on {ep}", "", act)}, "")


def t_defend(ctx, action="sweep", target="", ports="", seconds=8, answers=None, apply=False, ids=None,
             id=None, op=None, note=None, pid=0, endpoint=""):
    """Blue-team defense of this machine, its LAN/WLAN and its gateways (gnoc_defend.py +
    gnoc_defender.py). The machine the checks run on is the one the user named with /defender target, never a
    model argument. `sweep` is the defender's start: findings, alerts, triage, and (by default) auto-defense
    of the reversible allowlisted actions. `respond` is the plan/apply path for a hand-picked response."""
    (
        _defender_state, _defender_target, _enforce_action, _truthy, defender_status,
        gnoc_defend, gnoc_defender, gnoc_enforce, gnoc_vulnwatch, json, os, re,
    ) = bind(
        "_defender_state", "_defender_target", "_enforce_action", "_truthy",
        "defender_status", "gnoc_defend", "gnoc_defender", "gnoc_enforce",
        "gnoc_vulnwatch", "json", "os", "re",
    )
    act = str(action or "audit").strip().lower()
    st = _defender_state(ctx)
    dest = _defender_target(st)
    prof = gnoc_defender.load_profile(dest)
    if act == "setup":
        return gnoc_enforce.setup_steps(prof)
    if act in ("endpoints", "endpoint"):
        sub = str(op or "list").lower()
        p = gnoc_defender.load_profile(dest)
        ep = str(target or endpoint or "").strip()
        if sub in ("list", "show", ""):
            return ("configured endpoints:\n  " + "\n  ".join(gnoc_enforce.endpoints(p))) \
                if gnoc_enforce.endpoints(p) else "no endpoints configured (run /defender setup)"
        if sub == "add":
            if not gnoc_enforce.valid_dest(ep):
                return "usage: defend(action=endpoints, op=add, target=<user@host>)"
            p["endpoints"] = sorted(set(p.get("endpoints", [])) | {ep})
            gnoc_defender.save_profile(p, dest)
            return f"endpoint added: {ep}  (test it with op=test)"
        if sub in ("rm", "remove", "del"):
            p["endpoints"] = [x for x in p.get("endpoints", []) if x != ep]
            gnoc_defender.save_profile(p, dest)
            return f"endpoint removed: {ep}"
        if sub in ("sweep", "scan"):
            if ep and not gnoc_enforce.valid_dest(ep):
                return "refused: endpoint is not an ssh destination (user@host)"
            if ep and ep not in gnoc_enforce.endpoints(p):
                return f"refused: {ep} is not a configured endpoint; /defender endpoint add {ep}"
            targets = [ep] if ep else gnoc_enforce.endpoints(p)
            if not targets:
                return "no endpoints configured (run /defender setup)"
            blocks = []
            for one in targets:
                findings, notes = gnoc_defender.sweep(one, light=True, profile=p, packet_secs=0)
                rows = gnoc_defender.plan(findings, p, one)
                alerts, assessment, case, _new = gnoc_defender.publish(findings, one, p)
                blocks.append(gnoc_defender.render(findings, notes, [], rows, one, p,
                                                    alerts=alerts, assessment=assessment, case=case))
                if any(f.get("area") == "enforcement" for f in findings):
                    blocks.append("  ENFORCEMENT: endpoint changes always wait for the user's explicit yes.")
            return "\n\n".join(blocks)
        if sub in ("test", "check"):
            if ep:
                return gnoc_enforce.endpoint_test(ep)
            return "\n".join(gnoc_enforce.endpoint_test(x) for x in gnoc_enforce.endpoints(p)) or \
                "no endpoints configured"
        return "endpoints op is list|add|rm|test"
    if act == "enforce":
        # `seconds` defaults to 8 (a packet capture); as a block TTL that clamped to 60 s, so a model-issued block
        # expired in a minute. A block lasts 30 min unless a real TTL was asked for (QAQC 2026-11-19).
        ttl = int(seconds) if seconds and int(seconds) > 60 else 1800
        finding, err = _enforce_action(prof, op, target, endpoint, pid, ttl)
        if err:
            return "refused: " + err
        finding["dest"] = finding["act"].get("dest")
        rows = gnoc_defender.plan([finding], prof, dest)
        if not rows:
            return "nothing to enforce"
        if rows[0][1] == "refused":
            return "refused: " + rows[0][2]
        out = gnoc_defender.apply([rows[0]], dest, auto=False)
        return "\n".join(["ENFORCEMENT APPLIED (operator-approved, journalled; /defender undo reverts):"]
                         + out)
    if act in ("gateway", "gateways", "router") and op:
        sub = str(op or "").lower()
        p = gnoc_defender.load_profile(dest)
        val = str(target or endpoint or "").strip()
        if sub == "test":
            return gnoc_enforce.gateway_test(p)
        if sub == "ssh":
            if not gnoc_enforce.valid_dest(val):
                return "usage: defend(action=gateway, op=ssh, target=<user@gateway>)"
            p["gateway_ssh"] = val
        elif sub == "platform":
            if val.lower() not in ("generic", "linux", "openwrt", "pfsense", "opnsense", "pf",
                                   "hostapd", "ap", "unifi"):
                return "platform is generic|linux|openwrt|pfsense|opnsense|hostapd|unifi"
            p["gateway_platform"] = val.lower()
        elif sub in ("iface", "wifi-iface"):
            p["gateway_wifi_iface"] = val[:32]
        elif sub in ("api", "api-url"):
            api = dict(p.get("gateway_api") or {})
            api["url"] = val
            if not gnoc_enforce._api_url_ok(val, api):
                return ("refused: that controller URL is not private/loopback. A public controller needs "
                        "allow_public + HTTPS in the profile, not a bare URL")
            p.setdefault("gateway_api", {})["url"] = val
        elif sub == "api-kind":
            if val.lower() not in ("generic", "unifi"):
                return "api-kind is generic|unifi"
            p.setdefault("gateway_api", {})["kind"] = val.lower()
        elif sub == "api-site":
            p.setdefault("gateway_api", {})["site"] = val[:80]
        elif sub == "api-token-env":
            p.setdefault("gateway_api", {})["token_env"] = val[:80]
        elif sub in ("clear", "off"):
            p["gateway_ssh"] = ""
            p["gateway_api"] = {}
        else:
            return "gateway op is ssh|platform|iface|api|api-kind|api-site|api-token-env|test|clear"
        gnoc_defender.save_profile(p, dest)
        return "gateway enforcement configured: " + gnoc_defender._enforcement_line(p)
    if act == "scan":
        return gnoc_defend.scan(str(target or ""), str(ports or ""))
    if act == "packets":
        with gnoc_defend.on_host(dest):
            return gnoc_defend.packets(seconds)
    if act in ("network", "scope"):
        return gnoc_defender.network_report(prof, dest)
    if act in ("gateway", "gateways", "router"):
        return gnoc_defender.gateway_report(prof, dest, targets=[target] if target else None)
    if act in ("wlan", "wifi"):
        return gnoc_defender.wlan_report(prof, dest)
    if act in ("discover", "inventory"):
        return gnoc_defend.discover(str(target or " ".join(prof.get("subnets") or [])))
    if act == "alerts":
        try:
            secs = int(seconds)
        except (TypeError, ValueError):
            secs = 0
        return gnoc_defender.alerts_report(str(op or "list"), id, str(note or ""),
                                           secs if secs >= 60 else 3600)
    if act == "triage":
        return gnoc_defender.triage_report(id, op, str(note or ""))
    if act == "summary":
        return gnoc_defender.summary(int(seconds) if str(seconds or "").isdigit() and int(seconds) <= 90 else 7)
    if act == "windows":
        # Windows Security from WSL or Windows: Defender and the firewall profiles, read-only (GreyNOC's desktop,
        # 2026-11-23: "are the windows defender settings correct on this machine?" looped on `powershell`, exit 127)
        import gnoc_winsec
        if not gnoc_winsec.available():
            return "this machine is not Windows or WSL: there is no Windows Security to read (defend sweep covers Linux)"
        try:
            d, fs = gnoc_winsec.check()
        except Exception as e:  # noqa: BLE001
            return f"could not read Windows Security: {e}"
        return gnoc_winsec.render(d, fs)
    if act == "vulnwatch":
        # op=run does a pass now (downloads only; the first pass can take a few minutes); otherwise the last
        # report and the timer state, which is what most questions need
        if str(op or "").lower() == "run":
            return gnoc_vulnwatch.run_and_publish(notify=False)[0]
        if str(op or "").lower() in ("on", "off", "enable", "disable", "start", "stop"):
            # the hourly timer is a schedule, and only the user sets one (dispatch refuses this call first; a
            # direct caller gets the same answer instead of a status read that looks like it worked)
            return ("refused: only the user turns the hourly vulnerability watch on or off. Give them the line to "
                    f"type in this chat: /defender vulnwatch {'off' if str(op).lower() in ('off', 'disable', 'stop') else 'on'}")
        try:
            with open(os.path.join(gnoc_defender.STATE, "vulnwatch-latest.txt")) as fh:
                last = fh.read()
        except OSError:
            last = "no pass yet: defend(action=vulnwatch, op=run) runs one"
        return gnoc_vulnwatch.status() + "\n\n" + last[:6000]
    if act == "auto":
        # "turn auto defense off for one hour": with no call for it, the lead told him "auto-defense is now OFF"
        # after a respond call that changed nothing (defense drive 2026-11-22). The approval gate asks him first.
        want = str(op or "").strip().lower()
        if want not in ("on", "off"):
            return ("auto-defense is " + ("ON" if gnoc_defender.auto_defense_on(prof, st) else "off") + " for this "
                    "chat. defend(action=auto, op=off|on) switches it after the user's yes; there is no timed off.")
        st["auto"] = want == "on"
        with __import__("contextlib").suppress(Exception):
            _w = __import__("gnoc_agent").DEFENDER_WATCH
            if _w.running():
                _w.auto = st["auto"]
        return (f"auto-defense {'ON' if st['auto'] else 'OFF'} for this chat"
                + ("" if st["auto"] else " (the watcher, if running, still alerts and does not act). There is NO "
                   "timed off: it stays off until /defender auto on or defend(action=auto, op=on)") + ".")
    _ids = [str(x) for x in (ids if isinstance(ids, (list, tuple)) else re.findall(r"[\w:/.\-]+", str(ids or "")))]
    if act == "respond" and _ids and all(re.fullmatch(r"A-\d{8}-\d{3,5}", i) for i in _ids):
        # ALERT ids handed to respond ran a whole sweep (defense batch 13): alerts are closed by GreyNOC's line
        verb = "resolve" if str(op or "").lower() in ("resolve", "close", "done") else "ack"
        return ("those are ALERT ids, not findings to act on: the user closes them themselves, one line each in the chat: "
                + "; ".join(f"/defender alerts {verb} {i}" for i in _ids) + ". Give them those lines; they are not "
                "closed until the user types them.")
    if act == "respond" and str(op or "").strip().lower().replace("_", "-") in ("block", "block-ip") \
            and str(target or "").strip() and not ids:
        # GreyNOC's own order to block one address ("block 203.0.113.9, it is scanning me"). respond only ran
        # sweep findings, so op=block/target= came back "nothing to apply" four times and the turn ended with no
        # answer (defense drive 2026-11-22). One host block, the same anti-lockout checks as auto-defense, and
        # GreyNOC's yes first (gnoc_defender.needs_approval asks for every call shaped like this).
        ip = str(target).strip().split("/")[0]
        f = gnoc_defender._f(f"operator:block:{ip}", "high", "operator",
                             f"The user's order: block {ip} on this machine", "",
                             {"kind": "block_ip", "ip": ip, "ttl": gnoc_defender.BLOCK_TTL})
        rows = gnoc_defender.plan([f], prof, dest)
        if not rows or rows[0][1] == "refused":
            why = rows[0][2] if rows else "not an executable block"
            return (f"refused: {why}. (A block is for one PUBLIC address; documentation ranges such as "
                    "203.0.113.0/24 and private LAN addresses are not public.)" if rows else f"refused: {why}")
        if not _truthy(apply):
            return (f"ready: block {ip} on this machine for {gnoc_defender.BLOCK_TTL // 60} min (an nft element "
                    "that expires by itself; journalled; /defender undo lifts it sooner). Run it with "
                    f"defend(action=respond, op=block, target={ip}, apply=true): it asks the user first.")
        out = gnoc_defender.apply([(f, "ask", "The user's order")], dest, auto=False)
        return "\n".join(["BLOCK (the user's order, journalled; /defender undo reverts):"] + out)
    if act in ("sweep", "respond"):
        findings, notes = gnoc_defender.sweep(dest, light=False, profile=prof,
                                              packet_secs=5 if act == "sweep" else 0)
        st["last_ids"] = [f["id"] for f in findings]
        want = [str(i) for i in (ids or [])] if isinstance(ids, (list, tuple)) else \
            [x for x in re.split(r"[,\s]+", str(ids or "")) if x]
        rows = gnoc_defender.plan(findings, prof, dest, ids=want or None)
        if act == "sweep":
            qs = gnoc_defender.questions(prof, findings, asked=st.get("asked", []), dest=dest)
            st["asked"] = sorted(set(st.get("asked", [])) | {k for k, _ in qs})
            alerts, assessment, case, _new_case = gnoc_defender.publish(findings, dest, prof)
            if assessment.get("active") and not gnoc_enforce.capabilities(prof):
                notes.append("active intrusion but no gateway/AP/endpoint enforcement is configured: run "
                             "defend(action=setup) and follow the SSH key/helper/API checklist; containment is "
                             "manual until then")
            text = gnoc_defender.render(findings, notes, qs, rows, dest, prof,
                                        alerts=alerts, assessment=assessment, case=case)
            # AUTO-DEFENSE IS THE DEFAULT (2026-11-18): run every reversible action the profile allows.
            # It is journalled with its undo; /defender auto off disables it for this chat.
            auto = gnoc_defender.auto_defense_on(prof, st)
            run = [r for r in rows if r[1] == "allowed"] if auto else []
            if run:
                applied = gnoc_defender.apply(run, dest, auto=True)
                text += ("\n\nAUTO-DEFENSE APPLIED (reversible, journalled; /defender undo reverts):\n"
                         + "\n".join(applied))
                text += "\n  re-sweep to verify the finding is gone (a paused process stays visible until removed)."
            elif auto:
                asks = [r for r in rows if r[1] in ("allowed", "ask")]
                text += ("\n\nAUTO-DEFENSE: on, but nothing executable was allowed for this pass."
                         if asks else "\n\nAUTO-DEFENSE: on, nothing to act on.")
            else:
                text += "\n\nAUTO-DEFENSE: off for this chat (/defender auto on to enable)."
            return text
        alerts, assessment, case, _new_case = gnoc_defender.publish(findings, dest, prof)
        if not _truthy(apply):
            return gnoc_defender.render(findings, [], [], rows, dest, prof, alerts=alerts,
                                        assessment=assessment, case=case) + \
                ("\n\n(plan only: apply=true runs AUTO-OK rows; apply=true with ids=[...] also runs the ASK rows "
                 "named. Auto-defense already acts during action=sweep.)")
        # what may run: AUTO-OK rows always (the profile allows them); ASK rows only when hand-picked by id, and
        # the approval gate has already asked GreyNOC for any call that names ids (gnoc_defender.needs_approval)
        run = [r for r in rows if r[1] == "allowed" or (want and r[1] == "ask")]
        if not run:
            return "nothing to apply: " + ("; ".join(f"{f['id']} is {v} ({w})" for f, v, w in rows[:8])
                                           or "no executable findings")
        out = gnoc_defender.apply(run, dest, auto=False)
        if case:
            out.append(f"TRIAGE {case.get('id')} {case.get('priority')} is open: "
                       f"defend(action=triage, id={case.get('id')})")
        return "\n".join(["RESPONSE APPLIED (journalled; /defender undo reverts):"] + out
                         + ["", "Now sweep again to verify."])
    if act == "answer":
        if isinstance(answers, str):
            try:
                answers = json.loads(answers)
            except ValueError:
                return "answers must be an object, e.g. {\"role\": \"workstation\", \"exposed.8001\": \"no\"}"
        ok, bad = gnoc_defender.record_answers(answers or {}, (getattr(ctx, "s", None) or {}).get("_turn_text"),
                                               dest, asked=st.get("asked", []))
        return ("RECORDED: " + "; ".join(ok) if ok else "nothing recorded") + \
            ("\nREFUSED: " + "; ".join(bad) if bad else "") + \
            ("\nThese are the user's decisions and only their own words answer them. Put the questions to them in your "
             "reply, numbered, and END YOUR TURN; record their answers when the user gives them. Do not answer for them and do "
             "not look for another way to set them." if bad else "\nSweep again: answers change the verdicts.")
    if act == "undo":
        return "\n".join(gnoc_defender.undo(" ".join(ids) if isinstance(ids, (list, tuple)) else str(ids or "last")))
    if act == "journal":
        return "\n".join(gnoc_defender.journal_lines(30))
    if act == "baseline":
        return gnoc_defender.baseline_summary(_defender_target(_defender_state(ctx)))
    if act == "status":
        return defender_status(ctx)
    fn = gnoc_defend.ACTIONS.get(act)
    if not fn:
        return ("action is one of: sweep, answer, respond, undo, journal, status, network, gateway, wlan, "
                "discover, setup, endpoints, enforce, alerts, triage, audit, exposure, processes, connections, "
                f"packets, settings, firewall, logins, services, onion, scan, persistence, vulnwatch (got {action!r})")
    with gnoc_defend.on_host(dest):
        out = fn()
    if act in ("logins", "login"):
        try:
            out = f"{gnoc_defender.login_verdict(dest)}\n\n{out}"   # first: read before the raw rows
        except Exception:  # noqa: BLE001 - the verdict is an addition; the read stands without it
            pass
    return out


def _vulnwatch_bg():
    """One vulnwatch pass on a thread: the first pass downloads and verifies for minutes, and the prompt must
    stay usable meanwhile. Its report prints when it finishes; a second request while one runs is a no-op."""
    (
        T, _VULNWATCH_RUNNING, dim, gnoc_vulnwatch, red, say, threading,
    ) = bind(
        "T", "_VULNWATCH_RUNNING", "dim", "gnoc_vulnwatch", "red", "say", "threading",
    )
    if _VULNWATCH_RUNNING.is_set():
        return

    def go():
        _VULNWATCH_RUNNING.set()
        try:
            text = gnoc_vulnwatch.run_and_publish()[0]
            say(T.bred("  ⛨ ") + dim(("  " + text).replace("\n", "\n  ")))
        except Exception as e:  # noqa: BLE001 - a failed pass is reported, the chat goes on
            say(red(f"  vulnwatch pass failed: {type(e).__name__}: {str(e)[:160]}"))
        finally:
            _VULNWATCH_RUNNING.clear()
    threading.Thread(target=go, daemon=True, name="gnoc-vulnwatch").start()


def defender_command(agent, rest):
    """The /defender command: the machinery behind /mode defender. Returns text for the caller to say."""
    (
        DEFENDER_INSTALL_WATCH, DEFENDER_USAGE, DEFENDER_WATCH, _defender_state,
        _defender_target, _vulnwatch_bg, defender_status, gnoc_defend, gnoc_defender,
        gnoc_enforce, gnoc_vulnwatch, os, t_defend,
    ) = bind(
        "DEFENDER_INSTALL_WATCH", "DEFENDER_USAGE", "DEFENDER_WATCH", "_defender_state",
        "_defender_target", "_vulnwatch_bg", "defender_status", "gnoc_defend",
        "gnoc_defender", "gnoc_enforce", "gnoc_vulnwatch", "os", "t_defend",
    )
    st = _defender_state(agent.ctx)
    dest = _defender_target(st)
    prof = gnoc_defender.load_profile(dest)
    parts = str(rest or "").split(maxsplit=2)
    sub = parts[0].lower() if parts else "status"
    arg = parts[1] if len(parts) > 1 else ""
    arg2 = parts[2] if len(parts) > 2 else ""
    if sub in ("status", "show", ""):
        return defender_status(agent.ctx) + "\n" + DEFENDER_USAGE
    if sub == "sweep":
        return t_defend(agent.ctx, "sweep")
    if sub == "respond":
        return t_defend(agent.ctx, "respond")
    if sub == "setup":
        return gnoc_enforce.setup_steps(prof)
    if sub in ("endpoint", "endpoints"):
        return t_defend(agent.ctx, "endpoints", op=arg or "list", target=arg2)
    if sub == "enforce":
        op = arg.lower() if arg else ""
        bits = (arg2 or "").split()
        if not op or not bits:
            return ("usage: /defender enforce block-ip|block-mac|deauth <ip|mac> [ttl] · "
                    "isolate <user@host> · pause|kill <user@host> <pid> · unisolate <user@host>")
        if op in ("pause", "kill"):
            if len(bits) < 2 or not bits[1].isdigit():
                return f"usage: /defender enforce {op} <user@host> <pid>"
            return t_defend(agent.ctx, "enforce", op=op, endpoint=bits[0], pid=int(bits[1]))
        if op == "isolate":
            return t_defend(agent.ctx, "enforce", op="isolate", endpoint=bits[0])
        if op in ("unisolate",):
            return t_defend(agent.ctx, "enforce", op="unisolate", endpoint=bits[0])
        ttl = int(bits[1]) if len(bits) > 1 and bits[1].isdigit() else 1800
        return t_defend(agent.ctx, "enforce", op=op, target=bits[0], seconds=ttl)
    if sub == "network":
        return gnoc_defender.network_report(prof, dest)
    if sub == "wlan":
        return gnoc_defender.wlan_report(prof, dest)
    if sub == "vulnwatch":
        op = (arg or "status").lower()
        if op in ("npm", "pip"):
            bits = arg2.split(maxsplit=1)
            return gnoc_vulnwatch.set_config(op, bits[0] if bits else "", bits[1] if len(bits) > 1 else "")
        if op in ("on", "off"):
            msg = gnoc_vulnwatch.timer(op)
            if gnoc_platform.is_termux():
                return msg   # no timer was set, so no "first pass started" either
            if op == "on":
                _vulnwatch_bg()
                msg += "\nfirst pass started now in the background; its report will print here when done"
            return msg
        if op == "run":
            _vulnwatch_bg()
            return "vulnwatch pass started in the background (the first one takes a few minutes); the report prints here"
        if op in ("report", "last"):
            try:
                with open(os.path.join(gnoc_defender.STATE, "vulnwatch-latest.txt")) as fh:
                    return fh.read()
            except OSError:
                return "no pass yet: /defender vulnwatch run"
        if op == "status":
            return gnoc_vulnwatch.status()
        return ("usage: /defender vulnwatch [status|run|report|on|off|npm add|rm <dir>|pip add|rm <python>]")
    if sub == "install":
        if not dest and gnoc_platform.is_termux():
            # nothing to install or watch for without root: the hint says so in one line
            return gnoc_defender.install_hint(prof, None, dest)
        status = gnoc_defender.install_check(prof, dest)
        text = gnoc_defender.install_hint(prof, status, dest)
        if gnoc_defender.install_done(status):
            DEFENDER_INSTALL_WATCH.stop()
            return text
        DEFENDER_INSTALL_WATCH.start(prof, dest, status=status)
        return text + ("\n\nWATCHING: I re-check every few seconds and say each step the moment it is done "
                       "(stops when all 5 are done, or after 15 minutes).")
    if sub == "auto":
        if arg not in ("on", "off"):
            return "usage: /defender auto on|off [seconds]"
        st["auto"] = arg == "on"
        agent.save()
        if arg == "on":
            secs = int(arg2) if arg2.isdigit() else 60
            if not DEFENDER_WATCH.running():
                DEFENDER_WATCH.start(dest, secs, auto=True)
            else:
                DEFENDER_WATCH.auto = True
            return (f"auto-defense ON every {max(20, secs)}s: reversible actions the profile allows run on each "
                    "watcher pass; every one is journalled and /defender undo reverts it.")
        if DEFENDER_WATCH.running():
            DEFENDER_WATCH.auto = False
        return "auto-defense off for this chat (the watcher, if running, still alerts and does not act)."
    if sub == "watch":
        if arg not in ("on", "off"):
            return "usage: /defender watch on|off [seconds]"
        if arg == "off":
            DEFENDER_WATCH.stop()
            return "defender watcher stopped."
        secs = int(arg2) if arg2.isdigit() else 60
        st["auto"] = False
        agent.save()
        DEFENDER_WATCH.start(dest, secs, auto=False)
        return "defender watcher started in ALERT-ONLY mode: " + DEFENDER_WATCH.status()
    if sub == "admin":
        if not (arg2 or arg):
            return "usage: /defender admin <ip/cidr> [...]"
        ok, bad = gnoc_defender.record_answers({"admin_sources": arg2 or arg}, arg2 or arg, dest)
        return "; ".join(ok + bad)
    if sub == "target":
        if arg in ("", "local", "this", "off", "clear", "none"):
            st["target"] = None
            st.pop("asked", None)
            st.pop("last_ids", None)
            agent.save()
            if DEFENDER_WATCH.running():
                DEFENDER_WATCH.start(None, auto=DEFENDER_WATCH.auto)
            return "defender target: this machine"
        if not gnoc_enforce.valid_dest(arg):
            return "usage: /defender target <ssh-dest|local>   (an ssh destination such as alice@10.0.0.5)"
        with gnoc_defend.on_host(arg):
            got = gnoc_defend.hostname()
        if "unreachable" in got:
            return f"refused: {arg} is unreachable over ssh ({got})"
        st["target"] = arg
        st.pop("asked", None)
        st.pop("last_ids", None)
        agent.save()
        if DEFENDER_WATCH.running():
            DEFENDER_WATCH.start(arg, auto=DEFENDER_WATCH.auto)
        return f"defender target: {arg} ({got})"
    if sub in ("allow", "deny"):
        kinds = {"block": "allow_block_ips", "blocks": "allow_block_ips", "block_ips": "allow_block_ips",
                 "contain": "allow_contain", "pause": "allow_contain", "sysctl": "allow_sysctl",
                 "quarantine": "allow_quarantine", "scan": "allow_net_scan", "net-scan": "allow_net_scan",
                 "auto": "auto_defense"}
        key = kinds.get(arg.lower())
        if not key:
            return "usage: /defender allow|deny block|contain|sysctl|quarantine|scan|auto"
        prof[key] = sub == "allow"
        gnoc_defender.save_profile(prof, dest)
        return f"{key} = {prof[key]}"
    if sub == "summary":
        return gnoc_defender.summary(int(arg) if str(arg).isdigit() else 7)
    if sub == "schedule":
        return gnoc_defender.schedule(" ".join(x for x in (arg, arg2) if x))
    if sub in ("level", "notify"):
        # settings he types himself, so they need no approval (defense batch 12: "only bother me for critical
        # things" had no line to type; the only route was a defend call held for approval)
        if sub == "level":
            lvl = arg.lower()
            if lvl not in ("critical", "high", "medium", "low", "info"):
                return "usage: /defender level critical|high|medium|low|info   (the lowest severity that alerts)"
            prof["alert_min_severity"] = lvl
            gnoc_defender.save_profile(prof, dest)
            return f"alert_min_severity = {lvl}: only {lvl}" + ("" if lvl == "info" else " and above") + " alert now"
        val = arg.lower()
        if val not in ("on", "off", "yes", "no"):
            return "usage: /defender notify on|off   (a desktop notification for each new alert)"
        prof["notify"] = val in ("on", "yes")
        gnoc_defender.save_profile(prof, dest)
        return f"notify = {prof['notify']}: desktop notifications {'on' if prof['notify'] else 'off'}"
    if sub == "undo":
        return "\n".join(gnoc_defender.undo(" ".join(x for x in (arg, arg2) if x) or "last"))  # every id: "undo d11 d12" undid only d12
    if sub == "journal":
        return "\n".join(gnoc_defender.journal_lines(30))
    if sub == "alerts":
        if arg in ("ack", "acknowledge", "resolve", "suppress", "mute", "reopen") and arg2:
            return gnoc_defender.alerts_report(arg, arg2.split()[0])
        return gnoc_defender.alerts_report("show", arg) if arg else gnoc_defender.alerts_report("list")
    if sub == "triage":
        if not arg:
            return gnoc_defender.triage_report()
        if arg.upper().startswith("IR-"):
            op = arg2.split()[0] if arg2 else None
            note = arg2.split(maxsplit=1)[1] if len(arg2.split(maxsplit=1)) > 1 else ""
            return gnoc_defender.triage_report(arg, op, note)
        if arg in ("ack", "contain", "eradicate", "recover", "close", "closed", "false_positive", "note", "step"):
            bits = arg2.split(maxsplit=1)
            note = bits[1] if len(bits) > 1 else ""
            return gnoc_defender.triage_report(bits[0] if bits else None, arg, note)
        return gnoc_defender.triage_report(arg)
    if sub == "gateway":
        if arg in ("ssh", "platform", "iface", "api", "api-kind", "api-site", "api-token-env", "test", "clear"):
            return t_defend(agent.ctx, "gateway", op=arg, target=arg2)
        if arg in ("add", "rm", "remove", "del"):
            if not arg2:
                return "usage: /defender gateway add|rm <ip>"
            if arg == "add":
                good, bad = gnoc_defender.add_gateways(arg2, dest)
                return ("added: " + ", ".join(good) if good else "nothing added") + \
                    ("\nrefused: " + "; ".join(bad) if bad else "")
            return "removed: " + ", ".join(gnoc_defender.remove_gateways(arg2, dest))
        if arg:
            return gnoc_defender.gateway_report(prof, dest, targets=[arg])
        return gnoc_defender.gateway_report(prof, dest)
    if sub == "baseline":
        if arg in ("", "show", "list", "status"):
            return gnoc_defender.baseline_summary(dest)
        part = arg2.strip().lower()
        if arg in ("reset", "clear", "accept") and part in ("", "network", "net", "lan", "host"):
            msgs = []
            if part != "host":
                msgs.append(gnoc_defender.reset_baseline(dest))
            if part in ("", "host"):
                msgs.append(gnoc_defender.accept_host_drift(dest))
            return "\n".join(msgs)
        return ("usage: /defender baseline [show] | accept [network|host]   (accept after verifying a real gateway/device MAC "
                "change, or a unit/cron/key/port change you made yourself)")
    if sub in ("subnet", "subnets"):
        if arg in ("add", "rm", "remove", "del"):
            if not arg2:
                return "usage: /defender subnet add|rm <cidr>"
            if arg == "add":
                good, bad = gnoc_defender.add_subnets(arg2, dest)
                return ("added: " + ", ".join(good) if good else "nothing added") + \
                    ("\nrefused: " + "; ".join(bad) if bad else "")
            return "removed: " + ", ".join(gnoc_defender.remove_subnets(arg2, dest))
        return gnoc_defender.network_report(prof, dest)
    if sub in ("help", "?"):
        return DEFENDER_USAGE
    return "unknown /defender command " + repr(sub) + "\n" + DEFENDER_USAGE


def _schedule_word():
    try:
        import gnoc_defender
        s = gnoc_defender.schedule("show")
        return s.split("scheduled sweep: ", 1)[1].split("  (")[0] if s.startswith("scheduled sweep:") else "none"
    except Exception:  # noqa: BLE001
        return "unknown"


def defender_status(ctx):
    (
        DEFENDER_WATCH, _defender_state, _defender_target, gnoc_defender,
    ) = bind(
        "DEFENDER_WATCH", "_defender_state", "_defender_target", "gnoc_defender",
    )
    st = _defender_state(ctx)
    dest = _defender_target(st)
    gnoc_defender.sync_stores()
    prof = gnoc_defender.load_profile(dest)
    auto = gnoc_defender.auto_defense_on(prof, st)
    perms = [k for k in gnoc_defender.PERMISSION.values() if prof.get(k)]
    if prof.get("allow_net_scan"):
        perms.append("allow_net_scan")
    ok, _ = gnoc_defender.helper(["status"], dest)
    ac = gnoc_defender.A.counts()
    return "\n".join([
        f"target: {dest or 'this machine'}",
        f"auto-defense: {'ON' if auto else 'off'} (default ON; /defender auto off)" +
        (f"  ·  {DEFENDER_WATCH.status()}" if DEFENDER_WATCH.running() else ""),
        "may act unasked: " + (", ".join(perms) if perms else "nothing (alerts only)"),
        gnoc_defender.status_scope(prof, dest),
        f"alerts: open {ac['open'] + ac['ack']} (critical {ac['critical']}, high {ac['high']})  ·  "
        f"{gnoc_defender.T.summary_line()}",
        f"admin sources (never blocked): {', '.join(prof.get('admin_sources') or []) or 'not set yet'}",
        # his own switches, in one line: "what's my current alert level and is notify on" read the SYSTEM settings
        # audit instead and guessed (defense batch 17)
        f"alert level: {prof.get('alert_min_severity') or 'high'} and above  ·  desktop notifications: "
        f"{'on' if prof.get('notify') else 'off'}  ·  scheduled sweep: {_schedule_word()}",
        f"root helper: {'installed' if ok else 'not installed (/defender install)'}",
        f"journal: {len(gnoc_defender.journal(100000))} entr(ies)  ·  /defender undo reverts the last",
        gnoc_defender.auto_rules(prof, DEFENDER_WATCH.status() if DEFENDER_WATCH.running() else "")])


def _fn(name, desc, props, req=()):
    return {"type": "function", "function": {"name": name, "description": desc, "parameters": {
        "type": "object", "properties": props, "required": list(req)}}}
