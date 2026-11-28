#!/usr/bin/env python3
"""gnoc_phone.py - an Android phone plugged into this computer, used as one more machine that runs models.

The phone runs gnoc's own engine (scripts/gnoc_engine.py, with llama.cpp's Android build) inside Termux, on the
phone's own loopback address. This computer reaches it through the USB cable with `adb forward`, so nothing is
opened on Wi-Fi and pulling the cable ends it. gnoc then treats the phone like any second machine: a model
there is `<model>@phone`.

    gnoc phone                 what is plugged in, whether its engine answers, its models, battery and heat
    gnoc phone setup           the walk-through: adb, the phone, Termux, the engine, a model sized to the phone
    gnoc phone up | down       put the USB link in place / take it away (it is also restored when a chat starts)
    gnoc phone pull <model>    download a model ONTO the phone (over the phone's own connection)
    gnoc phone models          the models on the phone

What a phone is good for (measured on a Snapdragon 8+ Gen 1 with 11 GB of memory: a 4B model at about 7
tokens a second, a 1.7B at about 18): short side jobs, a helper beside the model on this computer, a model to
talk to when this computer's GPU is busy. It runs on the phone's CPU and gets hot under long load, so it is
never the right place for the lead model. Use it with  /model worker <model>@phone  in the chat, or let the
setup do it.

Android only (adb). Under Windows, gnoc runs inside WSL, which does not see USB devices until they are
attached with usbipd (https://learn.microsoft.com/windows/wsl/connect-usb).
"""
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_engine  # noqa: E402
import llm_endpoints  # noqa: E402

LOCAL_PORT = int(os.environ.get("GNOC_PHONE_PORT", "11441"))   # this computer's end of the cable
PHONE_PORT = 11434                                             # the engine on the phone's loopback
ADDR = f"127.0.0.1:{LOCAL_PORT}"
PUSH_DIR = "/sdcard/Download/gnoc"
TERMUX = "com.termux"
TERMUX_URL = "https://f-droid.org/packages/com.termux/"
HOT_C = 42.0     # a battery this warm should rest: the same line the long-running phone link uses
# (least memory in GB, model, download) - what a phone of that size runs without Android killing Termux
TIERS = ((10.0, "qwen3:4b", "2.5 GB"), (6.0, "qwen3:1.7b", "1.8 GB"), (0.0, "qwen3:0.6b", "0.6 GB"))

# Runs ONCE inside Termux on the phone. It installs Python, puts the engine and its command in place, fetches
# llama.cpp's Android build, and makes the engine start whenever Termux opens (Android may stop Termux under
# memory pressure; opening it again brings the engine back).
PHONE_SETUP = r"""#!/data/data/com.termux/files/usr/bin/bash
# gnoc phone setup - run once inside Termux:  bash ~/storage/downloads/gnoc/gnoc-phone-setup.sh
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
echo "== python"
command -v python >/dev/null 2>&1 || { pkg update -y && pkg install -y python; }
echo "== the engine"
mkdir -p "$HOME/gnoc-engine"
cp "$here/gnoc_engine.py" "$HOME/gnoc-engine/gnoc_engine.py"
cat > "$PREFIX/bin/gnoc-engine" <<'EOF'
#!/data/data/com.termux/files/usr/bin/sh
GNOC_ENGINE_PROG=gnoc-engine GNOC_ENGINE_ADDR="${GNOC_ENGINE_ADDR:-127.0.0.1:@PHONE_PORT@}" exec python "$HOME/gnoc-engine/gnoc_engine.py" "$@"
EOF
chmod +x "$PREFIX/bin/gnoc-engine"
echo "== llama.cpp for Android"
gnoc-engine install
echo "== start with Termux"
cat > "$HOME/gnoc-phone-up.sh" <<'EOF'
#!/data/data/com.termux/files/usr/bin/sh
# keeps the phone awake enough to answer while it is plugged in, and starts the engine if it is not running
command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock
gnoc-engine start >/dev/null 2>&1 || true
EOF
chmod +x "$HOME/gnoc-phone-up.sh"
grep -q gnoc-phone-up "$HOME/.bashrc" 2>/dev/null || echo '[ -x "$HOME/gnoc-phone-up.sh" ] && "$HOME/gnoc-phone-up.sh"' >> "$HOME/.bashrc"
mkdir -p "$HOME/.termux/boot" && cp "$HOME/gnoc-phone-up.sh" "$HOME/.termux/boot/gnoc-phone-up.sh"
"$HOME/gnoc-phone-up.sh"
gnoc-engine
echo
echo "Done. Leave Termux open (it can be in the background) and go back to your computer."
""".replace("@PHONE_PORT@", str(PHONE_PORT))


class PhoneError(Exception):
    pass


# ------------------------------------------------------------------ adb
def adb_path():
    """The adb program, or None. PATH first, then the usual places it is unpacked to."""
    found = shutil.which("adb")
    if found:
        return found
    homes = [os.path.expanduser("~/.local/bin"), os.path.join(os.environ.get("ANDROID_HOME", ""), "platform-tools"),
             os.path.join(os.environ.get("ANDROID_SDK_ROOT", ""), "platform-tools"),
             os.path.expanduser("~/Android/Sdk/platform-tools"),
             os.path.expanduser("~/Library/Android/sdk/platform-tools")]
    for d in homes:
        p = os.path.join(d, "adb.exe" if os.name == "nt" else "adb")
        if d and os.path.isfile(p):
            return p
    return None


def adb(*args, serial=None, timeout=20):
    """Run adb. Returns (exit code, stdout, stderr). Never raises for a failing or slow adb."""
    exe = adb_path()
    if not exe:
        return 127, "", "adb is not installed"
    cmd = [exe] + (["-s", serial] if serial else []) + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"adb {args[0] if args else ''} did not answer in {timeout}s"
    except OSError as e:
        return 126, "", str(e)


def devices():
    """[{'serial', 'state', 'model'}] for everything adb sees. state: device (ready), unauthorized (the prompt on
    the phone was not accepted), no permissions (this user may not open the USB device), offline."""
    rc, out, _err = adb("devices", "-l")
    rows = []
    for ln in out.splitlines()[1:] if rc == 0 else []:
        m = re.match(r"^(\S+)\s+(device|unauthorized|offline|no permissions|recovery|sideload)\b(.*)$", ln.strip())
        if m:
            model = re.search(r"model:(\S+)", m.group(3))
            rows.append({"serial": m.group(1), "state": m.group(2), "model": model.group(1) if model else ""})
    return rows


def pick(serial=None):
    """The phone to use: the one asked for, else the only ready one. None when there is none (or several and
    no choice was made)."""
    ready = [d for d in devices() if d["state"] == "device"]
    if serial:
        return next((d for d in ready if d["serial"] == serial), None)
    saved = _saved().get("serial")
    return next((d for d in ready if d["serial"] == saved), None) or (ready[0] if len(ready) == 1 else None)


def facts(serial):
    """What the phone is: model, Android version, memory, battery level and temperature, whether Termux is on it."""
    def sh(cmd):
        return adb("shell", cmd, serial=serial)[1].strip()
    mem = re.search(r"MemTotal:\s+(\d+)", sh("cat /proc/meminfo"))
    batt = sh("dumpsys battery")
    level = re.search(r"^\s*level:\s*(\d+)", batt, re.M)
    temp = re.search(r"^\s*temperature:\s*(\d+)", batt, re.M)
    plugged = re.search(r"^\s*(?:AC|USB|Wireless) powered:\s*true", batt, re.M)
    return {"serial": serial, "model": sh("getprop ro.product.model"), "android": sh("getprop ro.build.version.release"),
            "ram_gb": round(int(mem.group(1)) / 2 ** 20, 1) if mem else 0.0,
            "battery": int(level.group(1)) if level else None,
            "temp_c": int(temp.group(1)) / 10 if temp else None, "charging": bool(plugged),
            "termux": f"package:{TERMUX}" in sh(f"pm list packages {TERMUX}").split()}


def forwarded(serial=None):
    """True when this computer's port already leads to the phone's engine port."""
    rc, out, _ = adb("forward", "--list")
    want = (f"tcp:{LOCAL_PORT}", f"tcp:{PHONE_PORT}")
    return rc == 0 and any(ln.split()[1:3] == list(want) and (not serial or ln.split()[0] == serial)
                           for ln in out.splitlines() if len(ln.split()) >= 3)


def forward(serial):
    rc, _out, err = adb("forward", f"tcp:{LOCAL_PORT}", f"tcp:{PHONE_PORT}", serial=serial)
    if rc != 0:
        raise PhoneError(f"could not set up the USB link: {err.strip()[:200]}")


def unforward():
    adb("forward", "--remove", f"tcp:{LOCAL_PORT}")


def answering(timeout=3):
    """True when the engine ON THE PHONE answers through the cable. An adb forward accepts connections on this
    computer even when nothing listens on the phone, so only a real answer counts."""
    return gnoc_engine.who(ADDR, timeout) == "gnoc"


# ------------------------------------------------------------------ remembered between starts
def _state_file():
    return os.path.join(os.path.dirname(llm_endpoints.SAVED_HOSTS), "phone-link.json")


def _saved():
    try:
        with open(_state_file()) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _remember(**kv):
    d = dict(_saved(), **kv)
    os.makedirs(os.path.dirname(_state_file()), exist_ok=True)
    tmp = f"{_state_file()}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        json.dump(d, f)
    os.replace(tmp, _state_file())


def _save_host():
    """Make `@phone` mean this cable from now on. Skipped when it already does (an install whose phone address
    is configured elsewhere keeps its own settings file as it is)."""
    if llm_endpoints.HOSTS.get("phone") != ADDR:
        llm_endpoints.save_host("phone", ADDR)


def linked():
    """True when this install was set up to use a phone (the setup finished at least once)."""
    return bool(_saved().get("serial"))


def up(serial=None):
    """Put the USB link in place for the phone. Returns the device row. Raises PhoneError with what to do."""
    if not adb_path():
        raise PhoneError("adb is not installed (gnoc phone setup says how to get it)")
    dev = pick(serial)
    if not dev:
        seen = devices()
        if not seen:
            raise PhoneError("no phone is plugged in (or USB debugging is off)")
        if len([d for d in seen if d["state"] == "device"]) > 1:
            raise PhoneError("more than one phone is plugged in: gnoc phone up <serial>  ("
                             + ", ".join(d["serial"] for d in seen) + ")")
        raise PhoneError(_state_hint(seen[0]["state"]))
    forward(dev["serial"])
    _save_host()
    _remember(serial=dev["serial"], model=dev.get("model") or "")
    return dev


def down():
    unforward()


def ensure(wait=False):
    """When a chat starts: restore the USB link if this install uses a phone and it is plugged in. Runs on a
    thread so a missing or slow adb never delays the chat; never raises."""
    if not linked() or not adb_path():
        return None

    def work():
        try:
            dev = pick()
            if dev and not forwarded(dev["serial"]):
                forward(dev["serial"])
        except Exception:  # noqa: BLE001 - a phone that is not there is not an error for the chat
            pass
    t = threading.Thread(target=work, daemon=True, name="gnoc-phone-link")
    t.start()
    if wait:
        t.join(15)
    return t


def _state_hint(state):
    return {"unauthorized": "the phone is asking whether to allow USB debugging from this computer: unlock it and "
                            "tap Allow (tick 'Always allow from this computer')",
            "no permissions": "this user may not open the phone's USB device: unplug it, run  adb kill-server , "
                              "plug it in again (on Linux the android-udev-rules / android-sdk-platform-tools-common "
                              "package adds the rule that fixes this for good)",
            "offline": "adb sees the phone but it is not answering: unplug it and plug it in again"
            }.get(state, f"the phone is in state '{state}', not ready")


# ------------------------------------------------------------------ status
def status():
    """Everything `gnoc phone` prints, as a dict."""
    out = {"adb": adb_path(), "addr": ADDR, "linked": linked(), "devices": [], "phone": None, "engine": False,
           "models": [], "loaded": []}
    if not out["adb"]:
        return out
    out["devices"] = devices()
    dev = pick()
    if dev:
        out["phone"] = facts(dev["serial"])
        out["forwarded"] = forwarded(dev["serial"])
        if out["forwarded"] and answering():
            out["engine"] = True
            try:
                out["models"] = [m["name"] for m in gnoc_engine.api(ADDR, "/api/tags", timeout=5).get("models") or []]
                out["loaded"] = [m["name"] for m in gnoc_engine.api(ADDR, "/api/ps", timeout=5).get("models") or []]
            except Exception:  # noqa: BLE001
                pass
    return out


def print_status(st=None):
    st = st or status()
    if not st["adb"]:
        print("  adb is not installed, so no phone can be reached.  gnoc phone setup  walks through it.")
        return 1
    if not st["phone"]:
        if not st["devices"]:
            print("  no phone is plugged in (or USB debugging is off).  gnoc phone setup  walks through it.")
        elif len([d for d in st["devices"] if d["state"] == "device"]) > 1:
            print("  more than one phone is plugged in: " + ", ".join(d["serial"] for d in st["devices"]))
        else:
            print("  " + _state_hint(st["devices"][0]["state"]))
        return 1
    p = st["phone"]
    heat = "" if p["temp_c"] is None else f", {p['temp_c']:.0f} C" + (" (HOT: let it rest)" if p["temp_c"] >= HOT_C else "")
    print(f"  phone     {p['model']}  Android {p['android']}  {p['ram_gb']:g} GB memory  battery "
          f"{p['battery'] if p['battery'] is not None else '?'}%{heat}" + ("" if p["charging"] else "  (not charging)"))
    print(f"  termux    {'installed' if p['termux'] else 'NOT installed  (' + TERMUX_URL + ')'}")
    print(f"  usb link  {st['addr']} -> the phone's {PHONE_PORT}: " + ("in place" if st.get("forwarded") else
                                                                    "not set up  (gnoc phone up)"))
    if st["engine"]:
        print(f"  engine    answering  ·  models: {', '.join(st['models']) or 'none yet (gnoc phone pull <model>)'}"
              + (f"  ·  loaded: {', '.join(st['loaded'])}" if st["loaded"] else ""))
        if st["models"]:
            print(f"  use it    /model worker {st['models'][0]}@phone   in the chat")
    else:
        print("  engine    not answering" + ("  (open Termux on the phone; if it was never set up: gnoc phone setup)"
                                             if st.get("forwarded") else ""))
    return 0 if st["engine"] else 1


# ------------------------------------------------------------------ the walk-through
def recommend(ram_gb):
    """(model, download size) a phone with this much memory runs comfortably."""
    for least, model, size in TIERS:
        if ram_gb >= least:
            return model, size
    return TIERS[-1][1], TIERS[-1][2]


def push_files(serial):
    """Put the engine and the phone-side setup script in the phone's Download folder."""
    import tempfile
    engine = os.path.abspath(gnoc_engine.__file__)
    adb("shell", f"mkdir -p {PUSH_DIR}", serial=serial)
    with tempfile.TemporaryDirectory() as tmp:
        script = os.path.join(tmp, "gnoc-phone-setup.sh")
        with open(script, "w", newline="\n") as f:
            f.write(PHONE_SETUP)
        for src, name in ((engine, "gnoc_engine.py"), (script, "gnoc-phone-setup.sh")):
            rc, out, err = adb("push", src, f"{PUSH_DIR}/{name}", serial=serial, timeout=60)
            if rc != 0:
                raise PhoneError(f"could not copy {name} to the phone: {(err or out).strip()[:200]}")


def _wait(io, check, seconds, every=2.0):
    """Ask check() every few seconds for up to `seconds`. Counted in sleeps, so a test's instant sleep is instant."""
    for _ in range(int(seconds / every)):
        if check():
            return True
        io.sleep(every)
    return bool(check())


class Io:
    """Terminal I/O, swappable in tests."""

    def __init__(self, ask=input, say=print, sleep=time.sleep):
        self.ask, self.say, self.sleep = ask, say, sleep

    def yes(self, prompt, default=True):
        try:
            a = self.ask(f"{prompt} [{'Y/n' if default else 'y/N'}] > ").strip().lower()
        except (EOFError, OSError):
            return False
        return default if not a else a in ("y", "yes")

    def enter(self, prompt):
        """Wait for Enter. False when the user typed q, or there is no terminal."""
        try:
            return self.ask(prompt + " (Enter when done, q to stop) > ").strip().lower() not in ("q", "quit", "exit")
        except (EOFError, OSError):
            return False


def _install_adb_hint():
    if sys.platform == "darwin":
        return "brew install android-platform-tools"
    if os.name == "nt":
        return "winget install Google.PlatformTools"
    wsl = "microsoft" in os.uname().release.lower() if hasattr(os, "uname") else False
    base = "sudo apt install adb   (Fedora: sudo dnf install android-tools; Arch: sudo pacman -S android-tools)"
    return base + ("\n      This is WSL: Windows must first hand the phone's USB device to WSL with usbipd "
                   "(https://learn.microsoft.com/windows/wsl/connect-usb)." if wsl else "")


def setup(io=None, set_role=None):
    """The walk-through. Each step is checked before the next. Returns True when the phone's engine answers and a
    model is on it. set_role(role, spec) -> error text or None, as in gnoc_setup."""
    io = io or Io()
    io.say("\n  ── gnoc phone setup ───────────────────────────────────────")
    io.say("  This makes an Android phone on a USB cable run models for gnoc. Nothing is opened on Wi-Fi, and")
    io.say("  nothing is installed or downloaded without asking you.")
    # 1 adb
    io.say("\n  step 1 of 5: adb (Android's own USB tool) on this computer")
    while not adb_path():
        io.say("  adb is not installed. Install it with:\n      " + _install_adb_hint())
        if not io.enter("  Install it in another terminal"):
            return False
    io.say(f"  ✓ adb: {adb_path()}")
    # 2 the phone
    io.say("\n  step 2 of 5: the phone")
    io.say("  On the phone: Settings > About phone > tap 'Build number' seven times, then Settings > Developer")
    io.say("  options > turn on 'USB debugging'. Plug it in and accept the prompt that appears on its screen.")
    dev = pick()
    while not dev:
        seen = devices()
        io.say("  " + ("no phone is seen on USB yet" if not seen else
                       "more than one phone is plugged in; leave one" if len(seen) > 1 else _state_hint(seen[0]["state"])))
        if not io.enter("  Fix that"):
            return False
        dev = pick()
    f = facts(dev["serial"])
    io.say(f"  ✓ {f['model']}, Android {f['android']}, {f['ram_gb']:g} GB memory, battery {f['battery']}%")
    # 3 Termux
    io.say("\n  step 3 of 5: Termux (a terminal app; the engine runs inside it)")
    while not f["termux"]:
        io.say(f"  Termux is not on the phone. Install it from F-Droid: {TERMUX_URL}")
        io.say("  (the Play Store build is out of date and cannot run this). Open it once after installing.")
        if not io.enter("  Install Termux on the phone"):
            return False
        f = facts(dev["serial"])
    io.say("  ✓ Termux is installed")
    # 4 the engine
    io.say("\n  step 4 of 5: the engine on the phone")
    forward(dev["serial"])
    if answering():
        io.say("  ✓ the engine on the phone already answers")
    else:
        if not io.yes("  Copy gnoc's engine and its setup script to the phone's Download folder?", True):
            return False
        push_files(dev["serial"])
        io.say("  ✓ copied. Now, in Termux on the phone, type these two lines (the second takes a few minutes: it")
        io.say("    installs Python and downloads llama.cpp for Android, about 80 MB):")
        io.say("        termux-setup-storage")
        io.say("        bash ~/storage/downloads/gnoc/gnoc-phone-setup.sh")
        if not io.enter("  Run them on the phone"):
            return False
        if not _wait(io, answering, 60):
            io.say("  The engine on the phone does not answer through the cable yet. Check that the script finished")
            io.say("  without an error and that Termux is still open, then run  gnoc phone setup  again.")
            return False
        io.say("  ✓ the engine on the phone answers")
    _save_host()
    _remember(serial=dev["serial"], model=f["model"])
    # 5 a model
    io.say("\n  step 5 of 5: a model on the phone")
    try:
        have = [m["name"] for m in gnoc_engine.api(ADDR, "/api/tags", timeout=10).get("models") or []]
    except Exception:  # noqa: BLE001
        have = []
    model = have[0] if have else None
    if model:
        io.say(f"  ✓ the phone already has {', '.join(have)}")
    else:
        model, size = recommend(f["ram_gb"])
        io.say(f"  Suggested for a phone with {f['ram_gb']:g} GB of memory: {model} ({size}).")
        io.say("  The PHONE downloads it over its own connection, so put it on Wi-Fi first.")
        if not io.yes(f"  Download {model} onto the phone now?", True):
            io.say(f"  Do it any time with  gnoc phone pull {model}")
            return True
        try:
            gnoc_engine.remote_pull(ADDR, model)
        except gnoc_engine.EngineError as e:
            io.say(f"  The download did not finish ({e}). Run  gnoc phone pull {model}  to resume it.")
            return True
        io.say(f"  ✓ {model} is on the phone")
    io.say(f"\n  The phone is ready: its models are <model>@phone, for example  /model worker {model}@phone")
    if set_role and io.yes("  Use it as gnoc's WORKER now (the helper beside your main model)? A phone is slow for more "
                           "than short jobs", False):
        err = set_role("worker", f"{model}@phone")
        io.say(f"  could not set the worker: {err}" if err else f"  ✓ worker -> {model}@phone")
    io.say("  Keep the phone plugged in and Termux open. gnoc phone shows how it is doing.\n")
    return True


# ------------------------------------------------------------------ command line
def main(argv=None):
    a = list(sys.argv[1:] if argv is None else argv)
    cmd, rest = (a[0], a[1:]) if a else ("status", [])
    try:
        if cmd in ("status", "st"):
            return print_status()
        if cmd == "setup":
            set_role = None
            try:
                import gnoc_agent
                set_role = gnoc_agent.set_role
            except Exception:  # noqa: BLE001 - the walk-through still works without the role step
                pass
            return 0 if setup(set_role=set_role) else 1
        if cmd == "up":
            dev = up(rest[0] if rest else None)
            print(f"  usb link in place for {dev.get('model') or dev['serial']}: {ADDR}"
                  + ("" if answering() else "\n  the engine on the phone is not answering yet: open Termux on it "
                                            "(gnoc phone setup if it was never set up)"))
            return 0
        if cmd == "down":
            down()
            print("  usb link removed (models named @phone are unreachable until  gnoc phone up)")
            return 0
        if cmd == "models":
            if not answering():
                raise PhoneError("the engine on the phone is not answering (gnoc phone)")
            for m in gnoc_engine.api(ADDR, "/api/tags", timeout=10).get("models") or []:
                print(f"  {m['name']}@phone  {m.get('size', 0) / 1e9:.1f} GB")
            return 0
        if cmd == "pull" and rest:
            if not answering():
                raise PhoneError("the engine on the phone is not answering (gnoc phone)")
            gnoc_engine.remote_pull(ADDR, rest[0])
            print(f"  {rest[0]} is on the phone: /model worker {rest[0]}@phone")
            return 0
        print(__doc__)
        return 0 if cmd in ("help", "-h", "--help") else 2
    except (PhoneError, gnoc_engine.EngineError) as e:
        print(f"  {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n  stopped", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
