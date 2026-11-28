#!/usr/bin/env python3
"""phone-link - keeps the Android phone (USB, adb) wired into the laptop, the way link-desktop.ps1 wires the desktop.

Runs under pm2 as `phone-link` (gnoc phone up). Every 10 s:
  1. finds the phone on adb (state: none / unauthorized / no-permissions / device);
  2. keeps three adb FORWARDS in place (laptop port -> the phone's localhost), re-adding them after a replug:
       127.0.0.1:11441 -> phone 11434   the phone's Ollama        (server-room rack, `@phone` models)
       127.0.0.1:50053 -> phone 50052   the phone's ggml-rpc-server (third device in `gnoc split`)
       127.0.0.1:8022  -> phone 8022    the phone's sshd          (the reviver's way in)
  3. REVIVES the phone side when its serve loop has died (see the REVIVER block below);
  4. reads model, Android version, battery and memory over adb, and asks the phone's Ollama for /api/version;
  5. writes .claude/state/orch/phone.json atomically (gnoc-office's rack and `gnoc phone status` read it).

An adb forward ACCEPTS on the laptop even when nothing listens on the phone, so a TCP connect proves nothing:
Ollama is checked with a real HTTP call, and the RPC end is checked by llama.cpp itself (`gnoc split`).
Phone side, once: scripts/phone-link/termux-setup.sh (see `gnoc phone setup`).

    phone_link.py            run the loop (pm2)
    phone_link.py --once     one pass, print the status JSON (ssh included)
    phone_link.py --revive   force one repair of the phone's serve loop now, print what it did
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
STATUS = os.path.join(WS, ".claude/state/orch/phone.json")
ADB = shutil.which("adb") or os.path.expanduser("~/.local/bin/adb")  # pm2 may not have ~/.local/bin on PATH
FORWARDS = [(11441, 11434, "ollama"), (50053, 50052, "rpc"), (8022, 8022, "ssh")]
EVERY = 10

# BATTERY MANAGER. The phone lives on the cable, and a lithium cell pinned at 100 % ages fast, so the
# link keeps it inside a band instead: Samsung's own "Protect battery" (global setting protect_battery)
# stops the charge, and we flip it off again at the bottom of the band. Serving is the heat source, so
# a hot or nearly-flat phone has its Ollama forward REMOVED (the office and gnoc then see it as down,
# which is true) and its loaded models unloaded; both come back on their own once it recovers.
BAND_LOW = int(os.environ.get("PHONE_BATT_LOW", "60"))     # charge again at or below this
BAND_HIGH = int(os.environ.get("PHONE_BATT_HIGH", "80"))   # stop charging at or above this
TEMP_HOT = float(os.environ.get("PHONE_TEMP_HOT", "42"))   # C: pause serving
TEMP_OK = float(os.environ.get("PHONE_TEMP_OK", "38"))     # C: resume serving
LEVEL_FLOOR = int(os.environ.get("PHONE_BATT_FLOOR", "20"))  # pause serving when unplugged and this low
LEVEL_RESUME = int(os.environ.get("PHONE_BATT_RESUME", "35"))
PAUSE = {"on": False, "why": ""}   # hysteresis, seeded from the last status file at startup

# REVIVER. Ollama, the RPC server and the loop that keeps them up all live inside the Termux app's process
# group, so when Android kills Termux under memory or thermal pressure the whole phone side goes at once and
# nothing over there puts it back: Termux:Boot only fires at boot, and this (Play Store) build of Termux ships
# no RunCommandService, so adb cannot run a command inside it. Measured 2026-10-24: a thermal pause took the
# serve loop with it and the phone sat dead for a day and a half while every laptop-side check stayed green.
# Two ways in, tried in that order:
#   1. ssh over the 8022 forward - Termux alive, only the loop dead. Exact, and it reports what happened.
#   2. `am start` on the Termux activity - Termux itself dead. Its login shell runs the .bashrc hook that
#      termux-setup.sh installs, which calls greynoc-phone-up.sh. Blunt (it puts Termux on screen) but it works
#      with no add-on app installed.
# Only fires when the battery manager has NOT paused serving: a pause is a deliberate down, not a fault.
SSH_PORT = 8022
SSH_KEY = os.path.expanduser(os.environ.get("PHONE_SSH_KEY", "~/.ssh/gnoc-phone"))
PHONE_UP = "$HOME/greynoc-phone-up.sh"            # idempotent launcher, written by termux-setup.sh
REVIVE_AFTER = int(os.environ.get("PHONE_REVIVE_AFTER", "3"))      # consecutive down passes (~30 s) first
REVIVE_BACKOFF = (60, 120, 300, 600)              # seconds between attempts; the last value repeats
REVIVE = {"down": 0, "attempts": 0, "next": 0.0, "last": "", "at": ""}
PROBE_SSH = False                                 # --once only: a status read, not worth a spawn every pass

# NAS. The phone's shared storage (462 GB, ~399 GB free) mounted on the laptop over the SAME ssh link, by
# rclone's sftp backend (scripts/phone-link/phone-nas.sh). `phone-nas.sh mount` leaves NAS_ON behind and this
# keeper puts the mount back whenever it is gone or stale - a replug, a phone reboot, Android recycling Termux.
# Unplug the cable and the mount goes away by itself; nothing of this is on WiFi.
NAS_MNT = os.path.expanduser(os.environ.get("PHONE_NAS_MNT", "~/phone-nas"))
NAS_ON = os.path.join(WS, ".claude/state/orch/phone-nas.on")
NAS_SH = os.path.join(WS, "scripts/phone-link/phone-nas.sh")
NAS = {"next": 0.0, "last": ""}


def adb(*args, serial=None, timeout=8):
    cmd = [ADB] + (["-s", serial] if serial else []) + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout, r.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, "", str(e)


def find_device():
    """(serial, state): the first USB device adb sees; state 'device' is the only usable one."""
    rc, out, err = adb("devices", "-l")
    if rc != 0:
        return None, f"adb failed: {(err or out).strip()[:120]}"
    for ln in out.splitlines()[1:]:
        parts = ln.split()
        if len(parts) >= 2:
            return parts[0], parts[1]  # device | unauthorized | no permissions (...) | offline
    return None, "none"


def ensure_forwards(serial):
    _, out, _ = adb("forward", "--list", serial=serial)
    have = set(out.split())
    done = []
    for local, remote, name in FORWARDS:
        if name == "ollama" and PAUSE["on"]:
            continue   # paused by the battery manager: leave the port closed so nobody reloads a model
        if f"tcp:{local}" not in have:
            rc, _, err = adb("forward", f"tcp:{local}", f"tcp:{remote}", serial=serial)
            if rc != 0:
                print(f"phone-link: forward {local}->{remote} failed: {err.strip()[:120]}", flush=True)
                continue
            print(f"phone-link: forward 127.0.0.1:{local} -> phone {remote} ({name})", flush=True)
        done.append({"name": name, "laptop": f"127.0.0.1:{local}", "phone_port": remote})
    return done


EGRESS_PORT = 1081
EGRESS_BIN = os.path.join(WS, "scripts/phone-egress/phone-socks5")
EGRESS_OFF = os.path.join(WS, ".claude/state/orch/phone-egress.off")   # touch to disable the SOCKS egress


def phone_egress(serial):
    """Keep a loopback-only SOCKS5 (static Go binary, run by the adb shell user) on the phone and the
    laptop forward 127.0.0.1:1081 -> phone 1081. Off when the battery manager has paused serving, or
    when EGRESS_OFF exists. See scripts/PHONE-EGRESS.md."""
    _, out, _ = adb("forward", "--list", serial=serial)
    fwd = f"tcp:{EGRESS_PORT}" in out.split()
    _, pid, _ = adb("shell", "pidof phone-socks5", serial=serial)
    up = bool(pid.strip())
    if PAUSE["on"] or os.path.exists(EGRESS_OFF):
        if up:
            adb("shell", "kill " + pid.split()[0], serial=serial)
        if fwd:
            adb("forward", "--remove", f"tcp:{EGRESS_PORT}", serial=serial)
        return {"up": False, "why": "paused" if PAUSE["on"] else "disabled"}
    if not up:
        if not os.path.exists(EGRESS_BIN):
            return {"up": False, "why": "binary missing: build scripts/phone-egress (see PHONE-EGRESS.md)"}
        adb("push", EGRESS_BIN, "/data/local/tmp/phone-socks5", serial=serial, timeout=30)
        adb("shell", "chmod 755 /data/local/tmp/phone-socks5; (setsid nohup /data/local/tmp/phone-socks5 "
            f"127.0.0.1:{EGRESS_PORT} >/data/local/tmp/phone-socks5.log 2>&1 </dev/null &)", serial=serial)
        time.sleep(1)
        _, pid, _ = adb("shell", "pidof phone-socks5", serial=serial)
        up = bool(pid.strip())
    if up and not fwd:
        adb("forward", f"tcp:{EGRESS_PORT}", f"tcp:{EGRESS_PORT}", serial=serial)
    return {"up": up, "laptop": f"socks5h://127.0.0.1:{EGRESS_PORT}"}


def phone_ssh(cmd, timeout=20):
    """Run a command in Termux over the 8022 forward. (rc, output). Any username works with Termux's sshd."""
    ssh = shutil.which("ssh")
    if not ssh:
        return 1, "ssh is not installed on the laptop"
    if not os.path.exists(SSH_KEY):
        return 1, f"no key at {SSH_KEY} (run: gnoc phone setup)"
    cmd_line = [ssh, "-i", SSH_KEY, "-p", str(SSH_PORT), "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                # The phone's host key changes whenever Termux is reinstalled, and the endpoint is a USB
                # forward to our own device, so pinning it buys nothing and breaks the repair when it rotates.
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
                "127.0.0.1", cmd]
    try:
        r = subprocess.run(cmd_line, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return r.returncode, (r.stdout + r.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, f"{e.__class__.__name__}"


def ssh_up():
    rc, out = phone_ssh("echo ok", timeout=12)
    return {"up": rc == 0 and "ok" in out} if rc == 0 else {"up": False, "err": out[:120]}


def revive(serial, force=False):
    """Put the phone's serve loop back. Backs off so a phone that is off, flat or mid-reboot is left alone."""
    now = time.time()
    if not force and now < REVIVE["next"]:
        return REVIVE["last"]
    step = REVIVE_BACKOFF[min(REVIVE["attempts"], len(REVIVE_BACKOFF) - 1)]
    REVIVE["attempts"] += 1
    REVIVE["next"] = now + step
    REVIVE["at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    rc, out = phone_ssh(f"bash {PHONE_UP}", timeout=25)
    if rc == 0:
        REVIVE["last"] = "ssh: " + (out.splitlines() or ["(no output)"])[-1][:80]
    else:
        # Termux is not answering: start the app itself and let its login shell run the hook.
        arc, _, aerr = adb("shell", "am start -n com.termux/.app.TermuxActivity", serial=serial, timeout=15)
        REVIVE["last"] = (f"am start TermuxActivity (ssh: {out[:60]})" if arc == 0
                          else f"am start failed: {(aerr or '').strip()[:60]}")
    print(f"phone-link: revive #{REVIVE['attempts']} - {REVIVE['last']}; next attempt in {step}s", flush=True)
    return REVIVE["last"]


def nas_state():
    """(mounted, why). A dead FUSE mount answers ENOTCONN rather than hanging, so this stays cheap."""
    try:
        if not os.path.ismount(NAS_MNT):
            return False, "not mounted"
        os.stat(NAS_MNT)
        return True, ""
    except OSError as e:
        return False, f"stale ({e.__class__.__name__})"


def nas_keeper():
    """Hold the NAS mount up while NAS_ON exists. Mounting needs the phone's sshd, so it rides on the
    reviver: if the phone side is dead the mount attempt fails, backs off, and succeeds once ssh is back."""
    if not os.path.exists(NAS_ON):
        return None
    ok, why = nas_state()
    if ok:
        NAS["next"] = 0.0
        return {"mount": NAS_MNT, "up": True}
    now = time.time()
    if now < NAS["next"]:
        return {"mount": NAS_MNT, "up": False, "why": why, "retry_in_s": round(NAS["next"] - now),
                "last": NAS["last"]}
    NAS["next"] = now + 60
    try:
        r = subprocess.run(["bash", NAS_SH, "mount"], capture_output=True, text=True, timeout=45,
                           stdin=subprocess.DEVNULL)
        NAS["last"] = (r.stdout + r.stderr).strip().splitlines()[-1][:120] if (r.stdout or r.stderr) else ""
    except subprocess.TimeoutExpired:
        # rclone's --daemon parent can block past our patience while the child goes on to mount perfectly
        # well, so a timeout here says nothing about the outcome. Only the mountpoint does.
        NAS["last"] = "mount script timed out; checking the mountpoint anyway"
    except OSError as e:
        NAS["last"] = e.__class__.__name__
    ok = False
    for _ in range(15):          # the mountpoint is the single authority, on every path through this
        ok, _ = nas_state()
        if ok:
            break
        time.sleep(1)
    print(f"phone-link: nas {'re-mounted' if ok else 'mount failed'} at {NAS_MNT} - {NAS['last']}", flush=True)
    return {"mount": NAS_MNT, "up": ok, "why": None if ok else why, "last": NAS["last"]}


def device_facts(serial):
    def sh(cmd):
        return adb("shell", cmd, serial=serial)[1]
    facts = {"model": sh("getprop ro.product.model").strip(), "android": sh("getprop ro.build.version.release").strip()}
    bat = sh("dumpsys battery")
    m = re.search(r"level: (\d+)", bat)
    facts["battery"] = int(m.group(1)) if m else None
    facts["charging"] = bool(re.search(r"(AC|USB|Wireless) powered: true", bat))
    t = re.search(r"temperature: (\d+)", bat)
    facts["battery_c"] = int(t.group(1)) / 10 if t else None
    mem = sh("cat /proc/meminfo")
    for key, field in (("MemTotal", "mem_total_mb"), ("MemAvailable", "mem_avail_mb")):
        m = re.search(rf"{key}:\s+(\d+) kB", mem)
        facts[field] = int(m.group(1)) // 1024 if m else None
    return facts


def protect_read(serial):
    """Samsung's Protect battery flag: 1 = charging is held back, 0 = charge normally, None = unknown."""
    rc, out, _ = adb("shell", "settings get global protect_battery", serial=serial)
    out = out.strip()
    return int(out) if rc == 0 and out in ("0", "1") else None


def protect_write(serial, on):
    rc, _, err = adb("shell", f"settings put global protect_battery {1 if on else 0}", serial=serial)
    if rc != 0:
        print(f"phone-link: protect_battery write failed: {err.strip()[:120]}", flush=True)
    return rc == 0


def unload_models():
    """Drop every resident model on the phone (keep_alive 0): the loaded weights are the heat and the RAM."""
    dropped = []
    for name in (ollama_status().get("loaded") or []):
        body = json.dumps({"model": name, "keep_alive": 0}).encode()
        req = urllib.request.Request("http://127.0.0.1:11441/api/generate", body,
                                     {"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=10).read()
            dropped.append(name)
        except Exception as e:
            print(f"phone-link: unload {name} failed: {e.__class__.__name__}", flush=True)
    return dropped


def manage_battery(serial, facts):
    """Hold the cell in the band and pause serving when the phone is hot or nearly flat.

    Returns the row written to phone.json; mutates PAUSE, which ensure_forwards() reads."""
    level, temp = facts.get("battery"), facts.get("battery_c")
    charging = facts.get("charging")
    row = {"band": f"{BAND_LOW}-{BAND_HIGH}", "protect": protect_read(serial)}
    if level is None:
        row["note"] = "no battery level from adb"
        return row

    want = row["protect"]                       # unknown -> leave it alone
    if level >= BAND_HIGH:
        want = 1                                # full enough: stop feeding the cell
    elif level <= BAND_LOW:
        want = 0                                # bottom of the band: let it charge
    if want is not None and want != row["protect"]:
        if protect_write(serial, want):
            print(f"phone-link: battery {level} % -> protect_battery {want} (band {BAND_LOW}-{BAND_HIGH})", flush=True)
            row["protect"] = want
    row["charging_allowed"] = (row["protect"] == 0)

    hot = temp is not None and temp >= TEMP_HOT
    flat = not charging and level <= LEVEL_FLOOR
    if PAUSE["on"]:
        cool = temp is None or temp <= TEMP_OK
        fed = charging or level >= LEVEL_RESUME
        if cool and fed:
            PAUSE.update(on=False, why="")
            print(f"phone-link: serving resumed ({level} %, {temp} C)", flush=True)
    elif hot or flat:
        PAUSE.update(on=True, why="hot" if hot else "battery low")
        dropped = unload_models()
        adb("forward", "--remove", "tcp:11441", serial=serial)
        print(f"phone-link: serving paused - {PAUSE['why']} ({level} %, {temp} C); unloaded {dropped or 'nothing'}",
              flush=True)
    row["serving"] = not PAUSE["on"]
    if PAUSE["on"]:
        row["paused_because"] = PAUSE["why"]
    return row


def ollama_status():
    try:
        with urllib.request.urlopen("http://127.0.0.1:11441/api/version", timeout=3) as r:
            ver = json.loads(r.read()).get("version")
        with urllib.request.urlopen("http://127.0.0.1:11441/api/ps", timeout=3) as r:
            ps = [m.get("name") for m in json.loads(r.read()).get("models") or []]
        return {"up": True, "version": ver, "loaded": ps}
    except Exception as e:
        return {"up": False, "err": e.__class__.__name__}


def write(status):
    os.makedirs(os.path.dirname(STATUS), exist_ok=True)
    tmp = f"{STATUS}.tmp.{os.getpid()}"
    with open(tmp, "w") as fh:
        json.dump(status, fh, indent=1)
    os.replace(tmp, STATUS)


def once():
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if not os.path.exists(ADB):
        st = {"ts": now, "state": "no-adb", "hint": "adb is not installed (~/.local/opt/platform-tools)"}
        write(st)
        return st
    serial, state = find_device()
    st = {"ts": now, "serial": serial, "state": state}
    if state == "unauthorized":
        st["hint"] = "accept the 'Allow USB debugging' prompt on the phone"
    elif state and state.startswith("no"):
        st["hint"] = ("plug the phone in and turn on Developer options > USB debugging" if state == "none"
                      else "adb cannot open the device (USB permissions)")
    if state == "device":
        st.update(device_facts(serial))
        st["battery_mgr"] = manage_battery(serial, st)
        st["forwards"] = ensure_forwards(serial)
        try:
            st["egress"] = phone_egress(serial)
        except Exception as e:
            st["egress"] = {"up": False, "why": str(e)[:80]}
        st["ollama"] = ollama_status() if not PAUSE["on"] else {"up": False, "err": "paused: " + PAUSE["why"]}
        if PROBE_SSH:
            st["ssh"] = ssh_up()
        if PAUSE["on"] or st["ollama"].get("up"):
            REVIVE.update(down=0, attempts=0, next=0.0)   # healthy (or deliberately down): forget the streak
        else:
            REVIVE["down"] += 1
            if REVIVE["down"] >= REVIVE_AFTER:
                revive(serial)
        try:
            nas = nas_keeper()
        except Exception as e:
            nas = {"up": False, "why": str(e)[:80]}
        if nas is not None:
            st["nas"] = nas
        if REVIVE["attempts"] or REVIVE["down"]:
            st["revive"] = {"down_passes": REVIVE["down"], "attempts": REVIVE["attempts"],
                            "last": REVIVE["last"], "at": REVIVE["at"],
                            "next_in_s": max(0, round(REVIVE["next"] - time.time()))}
    write(st)
    return st


def main():
    prev = {}
    try:
        with open(STATUS) as fh:
            prev = (json.load(fh).get("battery_mgr") or {})
    except Exception:
        pass
    if prev.get("paused_because"):   # survive a pm2 restart without flapping the forward
        PAUSE.update(on=True, why=prev["paused_because"])
    global PROBE_SSH
    if "--once" in sys.argv or "--revive" in sys.argv:
        PROBE_SSH = True
        if "--revive" in sys.argv:
            serial, state = find_device()
            if state != "device":
                print(json.dumps({"ok": False, "why": f"phone not on adb ({state})"}, indent=1))
                return 1
            print(json.dumps({"ok": True, "did": revive(serial, force=True)}, indent=1))
            return 0
        print(json.dumps(once(), indent=1))
        return 0
    last = None
    while True:
        try:
            st = once()
            sig = (st.get("state"), (st.get("ollama") or {}).get("up"))
            if sig != last:
                print(f"phone-link: {st.get('state')} {st.get('model') or ''} ollama "
                      f"{'up' if sig[1] else 'down' if st.get('state') == 'device' else '-'}"
                      + (f"  ({st['hint']})" if st.get("hint") else ""), flush=True)
                last = sig
        except Exception as e:  # never die: pm2 would restart-loop on a flaky cable
            print(f"phone-link: pass failed: {e}", flush=True)
        time.sleep(EVERY)


if __name__ == "__main__":
    sys.exit(main())
