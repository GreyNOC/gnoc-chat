#!/usr/bin/env python3
"""droid - Android app workbench: intake, static mining and dynamic observation of IN-SCOPE apps.

  droid.py setup                               install / verify the toolchain under ~/.local/share/workbench
  droid.py intake <program> <pkg|apk|xapk> [--force-oos-research] [--dry-run]
                                               fetch (apkeep, APKPure) or copy the APK into targets/<p>/mobile/<pkg>/apk/
  droid.py static <program> <pkg>              apktool + jadx, then mine URLs/hosts, API paths, secrets, manifest,
                                               deeplinks, WebView bridges, NSC, RN/Flutter -> STATIC.md, routes.txt
  droid.py up [--burp] [--port N]              boot AVD vr1 headless, root, system CA (apex bind on API 34+),
                                               global proxy -> workbench mitmdump, frida-server
  droid.py run <program> <pkg> [--minutes N] [--monkey N] [--no-frida] [--burp]
                                               install, frida spawn with the TLS-pinning bypass, record flows
  droid.py status | down                       state / stop everything the workbench started
  droid.py report <program> <pkg>              one-screen digest of static + dynamic

Wired as `gnoc droid <args>`. Design notes and gotchas: scripts/workbench/README.md.

Scope rules: intake refuses a package / APK that is not an app row (GOOGLE_PLAY_APP_ID / OTHER_APK) in
targets/<program>/SCOPE.txt unless --force-oos-research (logged). Hosts the app contacts on its own are
recorded passively; only IN-SCOPE hosts are ever written to a routes file that a sweeper may fire (GET-only).
Env WORKBENCH_TARGETS overrides the targets root (the self-test uses it so no fake program appears in targets/).
"""
import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import zipfile
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
HERE = os.path.dirname(os.path.abspath(__file__))
TARGETS = os.environ.get("WORKBENCH_TARGETS", os.path.join(WS, "targets"))
WB = os.path.expanduser("~/.local/share/workbench")
SDK = os.path.expanduser("~/android-sdk")
ADB = os.path.join(SDK, "platform-tools/adb")
EMU = os.path.join(SDK, "emulator/emulator")
BT = os.path.join(SDK, "build-tools/35.0.0")
AAPT2 = os.path.join(BT, "aapt2")
APKEEP = os.path.join(WB, "bin/apkeep")
APKTOOL_JAR = os.path.join(WB, "apktool/apktool.jar")
JADX = os.path.join(WB, "jadx/bin/jadx")
VENV = os.path.join(WB, "venv")
FRIDA = os.path.join(VENV, "bin/frida")
FRIDA_PS = os.path.join(VENV, "bin/frida-ps")
STATE_DIR = os.path.join(WS, ".claude/state/workbench")
STATE = os.path.join(STATE_DIR, "state.json")
AVD, SERIAL, EMU_PORT = "vr1", "emulator-5554", "5554"
MITM_PORT = 8877
MITM_CA = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
BYPASS_JS = os.path.join(HERE, "frida/ssl-bypass.js")
ADDON = os.path.join(HERE, "mitm_flows.py")
VERSIONS = {"jadx": "1.5.6", "apktool": "3.0.3", "apkeep": "1.1.0", "frida": "17.24.3", "frida-tools": "14.11.0"}

sys.path.insert(0, os.path.join(WS, "scripts/bbtools"))
from lib_scope import in_scope  # noqa: E402

PKG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$")


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def die(msg, code=1):
    print(f"droid: {msg}", file=sys.stderr)
    sys.exit(code)


def sh(cmd, check=False, timeout=None, quiet=False, env=None):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    if check and r.returncode != 0:
        die(f"{' '.join(cmd[:4])} failed rc={r.returncode}: {(r.stderr or r.stdout).strip()[-400:]}")
    if not quiet and r.returncode != 0:
        pass
    return r


def adb(*args, timeout=60, check=False):
    return sh([ADB, "-s", SERIAL] + list(args), timeout=timeout, check=check)


def ashell(cmd, timeout=60, check=False):
    return adb("shell", cmd, timeout=timeout, check=check)


def load_state():
    try:
        return json.load(open(STATE))
    except (OSError, ValueError):
        return {}


def save_state(st):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(STATE, "w") as f:
        json.dump(st, f, indent=1)


def alive(pid):
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
    except OSError:
        return False
    try:  # a zombie answers kill(0) too
        return open(f"/proc/{pid}/stat").read().split(")")[-1].split()[0] != "Z"
    except OSError:
        return False


# ----------------------------------------------------------------------------------------- scope

def scope_file(program):
    return os.path.join(TARGETS, program, "SCOPE.txt")


def app_rows(program):
    """App rows from SCOPE.txt: GOOGLE_PLAY_APP_ID / OTHER_APK (commented or not; H1 pulls put the
    non-host types below the divider as '# TYPE ident' and OTHER_APK filenames as 'URL x.apk # ...OTHER_APK')."""
    rows = []
    try:
        lines = open(scope_file(program), encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return rows
    for raw in lines:
        line = re.sub(r"^\s*#\s*", "", raw).strip()
        kind = None
        if line.startswith("GOOGLE_PLAY_APP_ID"):
            kind = "GOOGLE_PLAY_APP_ID"
        elif line.startswith("OTHER_APK") or "as OTHER_APK" in line:
            kind = "OTHER_APK"
        if not kind:
            continue
        body = re.sub(r"^(GOOGLE_PLAY_APP_ID|OTHER_APK|URL)\s+", "", line)
        ident = body.split("\t")[0].split("  [")[0].split(" [")[0].strip()
        m = re.search(r"[?&]id=([A-Za-z0-9_.]+)", ident)
        pkg = m.group(1) if m else (ident if PKG_RE.match(ident) and not ident.endswith(".apk") else "")
        fname = ident if ident.lower().endswith(".apk") else ""
        rows.append({"kind": kind, "ident": ident, "pkg": pkg, "file": fname, "raw": raw.strip()[:200]})
    return rows


def row_for(program, pkg=None, fname=None):
    for r in app_rows(program):
        if pkg and r["pkg"] and r["pkg"] == pkg:
            return r
        if fname and r["file"] and os.path.basename(fname).lower() == r["file"].lower():
            return r
    return None


def host_scoped(program, host):
    try:
        return bool(host) and in_scope(host, scope_file(program))
    except Exception:
        return False


def mobile_dir(program, pkg):
    return os.path.join(TARGETS, program, "mobile", pkg)


def log_intake(program, rec):
    d = os.path.join(TARGETS, program, "mobile")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "INTAKE-LOG.jsonl"), "a") as f:
        f.write(json.dumps(dict(rec, ts=now())) + "\n")


# ----------------------------------------------------------------------------------------- setup

def gh_dl(url, dest):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    r = sh(["curl", "-sSfL", "--max-time", "600", "-o", dest, url])
    if r.returncode != 0:
        print(f"  NEEDS: download blocked or failed: {url}: {r.stderr.strip()[-200:]}")
        return False
    return True


def cmd_setup(a):
    fv = VERSIONS["frida"]
    ok = True
    if not os.path.exists(JADX):
        z = os.path.join(WB, "jadx.zip")
        if gh_dl(f"https://github.com/skylot/jadx/releases/download/v{VERSIONS['jadx']}/jadx-{VERSIONS['jadx']}.zip", z):
            os.makedirs(os.path.join(WB, "jadx"), exist_ok=True)
            sh(["unzip", "-qo", z, "-d", os.path.join(WB, "jadx")])
            os.remove(z)
    if not os.path.exists(APKTOOL_JAR):
        v = VERSIONS["apktool"]
        gh_dl(f"https://github.com/iBotPeaches/Apktool/releases/download/v{v}/apktool_{v}.jar", APKTOOL_JAR)
    if not os.path.exists(APKEEP):
        v = VERSIONS["apkeep"]
        if gh_dl(f"https://github.com/EFForg/apkeep/releases/download/{v}/apkeep-x86_64-unknown-linux-gnu", APKEEP):
            os.chmod(APKEEP, 0o755)
    if not os.path.exists(FRIDA):
        sh([sys.executable, "-m", "venv", VENV])
        sh([os.path.join(VENV, "bin/pip"), "install", "-q", f"frida=={fv}", f"frida-tools=={VERSIONS['frida-tools']}"])
    fs = os.path.join(WB, f"frida/frida-server-{fv}-android-x86_64")
    if not os.path.exists(fs):
        xz = fs + ".xz"
        if gh_dl(f"https://github.com/frida/frida/releases/download/{fv}/frida-server-{fv}-android-x86_64.xz", xz):
            with open(fs, "wb") as out:
                subprocess.run(["xz", "-dc", xz], stdout=out)
            os.remove(xz)
            os.chmod(fs, 0o755)
    if not os.path.exists(AAPT2):
        sm = os.path.join(SDK, "cmdline-tools/latest/bin/sdkmanager")
        subprocess.run(f"yes | {sm} --sdk_root={SDK} 'build-tools;35.0.0'", shell=True, capture_output=True)
    checks = [
        ("jadx", [JADX, "--version"]), ("apktool", ["java", "-jar", APKTOOL_JAR, "--version"]),
        ("apkeep", [APKEEP, "--version"]), ("frida", [FRIDA, "--version"]), ("aapt2", [AAPT2, "version"]),
        ("adb", [ADB, "version"]), ("emulator", [EMU, "-version"]), ("mitmdump", ["mitmdump", "--version"]),
    ]
    for name, c in checks:
        try:
            r = sh(c, timeout=60, env=dict(os.environ, PYTHONNOUSERSITE="1") if name == "mitmdump" else None)
            out = (r.stdout or r.stderr).strip().splitlines()
            print(f"  {name:9s} {'ok ' if r.returncode == 0 else 'ERR'} {out[0][:70] if out else ''}")
            ok &= r.returncode == 0
        except Exception as e:
            print(f"  {name:9s} ERR {e}")
            ok = False
    print(f"  frida-server {'ok ' if os.path.exists(fs) else 'MISSING'} {fs}")
    try:
        os.close(os.open("/dev/kvm", os.O_RDWR))
        print("  /dev/kvm  ok  (read-write for this user)")
    except OSError as e:
        ok = False
        print(f"  /dev/kvm  ERR {e}  NEEDS: add {os.environ.get('USER')} to group kvm")
    return 0 if ok else 1


# ----------------------------------------------------------------------------------------- intake

def apk_package(path):
    r = sh([AAPT2, "dump", "packagename", path])
    return r.stdout.strip() if r.returncode == 0 else ""


def unpack_bundle(src, apkdir):
    """XAPK / APKS / APKM (zip of base + split APKs, maybe OBB): extract the APKs, keep a manifest."""
    out = []
    with zipfile.ZipFile(src) as z:
        for n in z.namelist():
            if n.lower().endswith(".apk") and "/" not in n.strip("/"):
                dest = os.path.join(apkdir, os.path.basename(n))
                with z.open(n) as fi, open(dest, "wb") as fo:
                    shutil.copyfileobj(fi, fo)
                out.append(dest)
            elif n.lower().endswith(".apk"):
                dest = os.path.join(apkdir, os.path.basename(n))
                with z.open(n) as fi, open(dest, "wb") as fo:
                    shutil.copyfileobj(fi, fo)
                out.append(dest)
        if "manifest.json" in z.namelist():
            with open(os.path.join(apkdir, "xapk-manifest.json"), "wb") as fo:
                fo.write(z.read("manifest.json"))
    return out


def base_apk(apkdir):
    apks = sorted(f for f in os.listdir(apkdir) if f.endswith(".apk")) if os.path.isdir(apkdir) else []
    if not apks:
        return None, []
    # the base is the one that is not a config./split_ APK; fall back to the largest
    cand = [f for f in apks if not re.match(r"(config\.|split_)", f)]
    base = cand[0] if len(cand) == 1 else max(apks, key=lambda f: os.path.getsize(os.path.join(apkdir, f)))
    if "base.apk" in apks:
        base = "base.apk"
    return os.path.join(apkdir, base), [os.path.join(apkdir, f) for f in apks]


def cmd_intake(a):
    prog, arg = a.program, a.target
    if not os.path.exists(scope_file(prog)):
        die(f"no {scope_file(prog)}; run the scope pull first")
    rows = app_rows(prog)
    local = os.path.exists(arg)
    pkg = None
    if local:
        if arg.lower().endswith((".xapk", ".apks", ".apkm")):
            tmp = os.path.join(STATE_DIR, "intake-tmp")
            shutil.rmtree(tmp, ignore_errors=True)
            os.makedirs(tmp)
            apks = unpack_bundle(arg, tmp)
            b, _ = base_apk(tmp)
            pkg = apk_package(b) if b else ""
        else:
            pkg = apk_package(arg)
        if not pkg:
            die(f"cannot read the package name of {arg} (aapt2)")
        row = row_for(prog, pkg=pkg, fname=arg)
    else:
        if not PKG_RE.match(arg) and not arg.lower().endswith(".apk"):
            die(f"{arg!r} is neither a file nor a package id")
        if arg.lower().endswith(".apk"):
            row = row_for(prog, fname=arg)
            print(f"scope row: {row['raw'] if row else 'NONE'}")
            print("An OTHER_APK row names a file the vendor distributes, not a store id: download it from the vendor's "
                  "own channel, then run: droid.py intake <program> /path/to/" + os.path.basename(arg))
            if row:
                log_intake(prog, {"action": "row-check", "target": arg, "row": row["raw"], "decision": "accepted-row"})
            return 0 if row else 3
        pkg = arg
        row = row_for(prog, pkg=pkg)
    decision = "in-scope" if row else ("forced-oos-research" if a.force_oos_research else "refused-oos")
    print(f"package   {pkg}\nscope row {row['raw'] if row else 'NONE (no GOOGLE_PLAY_APP_ID / OTHER_APK row matches)'}")
    print(f"decision  {decision}")
    if not row:
        print("app rows in SCOPE.txt:")
        for r in rows:
            print(f"   {r['kind']:19s} {r['ident']}")
    log_intake(prog, {"action": "intake", "target": arg, "pkg": pkg, "row": row["raw"] if row else None,
                      "decision": decision, "dry_run": bool(a.dry_run)})
    if decision == "refused-oos":
        return 3
    if a.dry_run:
        print("dry run: nothing fetched")
        return 0
    md = mobile_dir(prog, pkg)
    apkdir = os.path.join(md, "apk")
    os.makedirs(apkdir, exist_ok=True)
    if decision == "forced-oos-research":
        with open(os.path.join(md, "OOS-RESEARCH.txt"), "a") as f:
            f.write(f"{now()} intake forced with --force-oos-research: {pkg} has no app row in SCOPE.txt. "
                    "Research only, nothing from this app is fileable against the program without a scope row.\n")
    if local:
        if arg.lower().endswith((".xapk", ".apks", ".apkm")):
            got = unpack_bundle(arg, apkdir)
        else:
            dest = os.path.join(apkdir, "base.apk")
            shutil.copy2(arg, dest)
            got = [dest]
    else:
        dl = os.path.join(STATE_DIR, "apkeep-" + pkg)
        shutil.rmtree(dl, ignore_errors=True)
        os.makedirs(dl)
        print(f"apkeep -a {pkg} -d apk-pure ...")
        r = sh([APKEEP, "-a", pkg, "-d", "apk-pure", dl], timeout=1800)
        files = [os.path.join(dl, f) for f in os.listdir(dl)]
        if r.returncode != 0 or not files:
            die(f"apkeep failed rc={r.returncode}: {(r.stderr or r.stdout).strip()[-400:]}\n"
                f"NEEDS: supply the APK file and run: droid.py intake {prog} /path/to/{pkg}.apk")
        got = []
        for f in files:
            if f.lower().endswith((".xapk", ".apks", ".apkm")):
                got += unpack_bundle(f, apkdir)
            elif f.lower().endswith(".apk"):
                dest = os.path.join(apkdir, "base.apk" if len(files) == 1 else os.path.basename(f))
                shutil.move(f, dest)
                got.append(dest)
        shutil.rmtree(dl, ignore_errors=True)
    b, allapks = base_apk(apkdir)
    real = apk_package(b) if b else ""
    if real and real != pkg:
        die(f"downloaded APK reports package {real}, expected {pkg}: refusing to continue")
    meta = {"pkg": pkg, "program": prog, "ts": now(), "decision": decision, "base": b, "apks": allapks,
            "split": len(allapks) > 1, "sizes": {os.path.basename(p): os.path.getsize(p) for p in allapks},
            "badging": sh([AAPT2, "dump", "badging", b]).stdout.splitlines()[:3] if b else []}
    json.dump(meta, open(os.path.join(md, "intake.json"), "w"), indent=1)
    print(f"stored    {len(allapks)} APK(s) in {apkdir} (base {os.path.basename(b) if b else '?'})")
    for line in meta["badging"]:
        print("          " + line[:150])
    return 0


# ----------------------------------------------------------------------------------------- static

URL_RE = re.compile(r"""(?:https?|wss?)://[A-Za-z0-9._~-]+(?::\d{2,5})?(?:/[^\s"'<>\\`)(\]{}|^]*)?""")
API_PATH_RE = re.compile(r"""["'`](/(?:api|v[0-9]{1,2}|graphql|gql|rest|oauth2?|auth|login|token|user|users|account|accounts|"""
                         r"""admin|internal|mobile|app|payments?|wallet|orders?|me|profile|config)(?:/[A-Za-z0-9_.{}:%-]*)*)["'`]""")
RETROFIT_RE = re.compile(r"""@(GET|POST|PUT|DELETE|PATCH|HEAD|HTTP)\(\s*(?:value\s*=\s*)?"([^"]*)\"""")
SECRET_RES = [
    ("google-api-key", r"AIza[0-9A-Za-z_-]{35}"),
    ("aws-access-key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("stripe-live", r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}"),
    ("stripe-pk-live", r"\bpk_live_[0-9A-Za-z]{20,}"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}"),
    ("google-oauth-client-id", r"\b[0-9]{6,}-[0-9a-z]{32}\.apps\.googleusercontent\.com"),
    ("oauth-client-secret", r"""(?i)client[_-]?secret["'\s]*[:=,]\s*["']([A-Za-z0-9_\-./+=]{12,})["']"""),
    ("google-oauth-secret", r"\bGOCSPX-[A-Za-z0-9_-]{20,}"),
    ("basic-auth-url", r"""https?://[A-Za-z0-9._%-]{2,}:[A-Za-z0-9._%!$&*+-]{3,}@[A-Za-z0-9.-]+"""),
    ("basic-auth-header", r"""["']Basic\s+[A-Za-z0-9+/]{12,}={0,2}["']"""),
    ("slack-token", r"\bxox[abposr]-[0-9A-Za-z-]{10,}"),
    ("github-token", r"\bgh[pousr]_[0-9A-Za-z]{30,}"),
    ("private-key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ("sendgrid", r"\bSG\.[0-9A-Za-z_-]{20,}\.[0-9A-Za-z_-]{20,}"),
    ("twilio-sid", r"\bAC[0-9a-f]{32}\b"),
    ("mapbox-secret", r"\bsk\.eyJ[A-Za-z0-9_-]{20,}"),
    ("generic-assignment", r"""(?i)\b(?:api[_-]?key|api[_-]?secret|access[_-]?token|secret[_-]?key|app[_-]?secret)\b["'\s]*[:=]\s*["']([A-Za-z0-9_\-./+=]{16,})["']"""),
]
SECRET_RES = [(n, re.compile(r)) for n, r in SECRET_RES]
FIREBASE_KEYS = ("google_api_key", "google_app_id", "firebase_database_url", "gcm_defaultSenderId", "project_id",
                 "google_storage_bucket", "default_web_client_id", "google_crash_reporting_api_key")
NOISE_HOSTS = re.compile(r"(^|\.)(schemas\.android\.com|w3\.org|apache\.org|xml\.org|xmlpull\.org|ns\.adobe\.com|"
                         r"purl\.org|json-schema\.org|openxmlformats\.org|example\.(com|org|net)|localhost|"
                         r"schemas\.microsoft\.com|java\.sun\.com|jcp\.org|mozilla\.org|unicode\.org)$", re.I)
TEXT_EXT = (".java", ".kt", ".smali", ".xml", ".json", ".js", ".bundle", ".html", ".htm", ".txt", ".properties",
            ".yaml", ".yml", ".cfg", ".conf", ".plist", ".dart", ".jsbundle", ".graphql", ".gql", ".ini")
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def iter_texts(roots, max_file=4_000_000):
    """(relpath, text) for source/resource files plus printable strings of native libs and bundles."""
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dp, dn, fn in os.walk(root):
            dn[:] = [d for d in dn if d not in ("original",)]
            for f in fn:
                p = os.path.join(dp, f)
                try:
                    sz = os.path.getsize(p)
                except OSError:
                    continue
                low = f.lower()
                if low.endswith(TEXT_EXT) or "." not in f:
                    if sz > max_file:
                        continue
                    try:
                        data = open(p, "rb").read()
                    except OSError:
                        continue
                    if data[:4] == b"\xc6\x1f\xbc\x03" or b"\x00" in data[:2048]:  # Hermes bytecode / binary
                        yield p, " ".join(s.decode("latin-1") for s in re.findall(rb"[\x20-\x7e]{6,}", data))
                    else:
                        yield p, data.decode("utf-8", "replace")
                elif low.endswith((".so", ".dex", ".bin", ".dat")) and sz < 150_000_000:
                    try:
                        data = open(p, "rb").read()
                    except OSError:
                        continue
                    yield p, "\n".join(s.decode("latin-1") for s in re.findall(rb"[\x20-\x7e]{6,}", data))


def badging_sdk(apk):
    r = sh([AAPT2, "dump", "badging", apk])
    m = re.search(r"targetSdkVersion:'(\d+)'", r.stdout)
    return m.group(1) if m else None


def parse_manifest(path, nsc_dir, target_sdk=None):
    out = {"package": "", "debuggable": False, "allowBackup": None, "usesCleartextTraffic": None, "nsc": None,
           "targetSdk": None, "exported": [], "deeplinks": [], "permissions": []}
    try:
        tree = ET.parse(path)
    except (ET.ParseError, OSError) as e:
        out["error"] = str(e)
        return out
    m = tree.getroot()
    out["package"] = m.get("package", "")
    for us in m.iter("uses-sdk"):
        out["targetSdk"] = us.get(ANDROID_NS + "targetSdkVersion")
    out["targetSdk"] = out["targetSdk"] or target_sdk  # apktool 3 moves uses-sdk into apktool.yml
    out["permissions"] = sorted({p.get(ANDROID_NS + "name", "") for p in m.iter("uses-permission")})
    app = m.find("application")
    if app is not None:
        out["debuggable"] = app.get(ANDROID_NS + "debuggable") == "true"
        out["allowBackup"] = app.get(ANDROID_NS + "allowBackup")
        out["usesCleartextTraffic"] = app.get(ANDROID_NS + "usesCleartextTraffic")
        out["nsc"] = app.get(ANDROID_NS + "networkSecurityConfig")
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for c in app.iter(tag):
                name = c.get(ANDROID_NS + "name", "")
                exp = c.get(ANDROID_NS + "exported")
                filters = c.findall("intent-filter")
                implicit = exp is None and filters and (out["targetSdk"] or "0").isdigit() and int(out["targetSdk"] or 0) < 31
                if exp == "true" or implicit:
                    perm = c.get(ANDROID_NS + "permission") or (c.get(ANDROID_NS + "readPermission") if tag == "provider" else None)
                    extra = ""
                    if tag == "provider":
                        extra = f" authorities={c.get(ANDROID_NS + 'authorities')} grantUriPermissions={c.get(ANDROID_NS + 'grantUriPermissions')}"
                    out["exported"].append(f"{tag} {name}{' (implicit, targetSdk<31)' if implicit else ''}"
                                           f"{' perm=' + perm if perm else ' NO-PERMISSION'}{extra}")
                for f in filters:
                    cats = {x.get(ANDROID_NS + "name", "") for x in f.findall("category")}
                    acts = {x.get(ANDROID_NS + "name", "") for x in f.findall("action")}
                    datas = f.findall("data")
                    schemes = [d.get(ANDROID_NS + "scheme") for d in datas if d.get(ANDROID_NS + "scheme")]
                    hosts = [d.get(ANDROID_NS + "host") for d in datas if d.get(ANDROID_NS + "host")]
                    paths = [d.get(ANDROID_NS + "path") or d.get(ANDROID_NS + "pathPrefix") or d.get(ANDROID_NS + "pathPattern")
                             for d in datas if any(d.get(ANDROID_NS + k) for k in ("path", "pathPrefix", "pathPattern"))]
                    if schemes and "android.intent.action.VIEW" in acts:
                        out["deeplinks"].append({"component": name, "schemes": sorted(set(schemes)),
                                                 "hosts": sorted(set(hosts)), "paths": paths[:6],
                                                 "browsable": "android.intent.category.BROWSABLE" in cats,
                                                 "autoVerify": f.get(ANDROID_NS + "autoVerify") == "true"})
    if out["nsc"] and out["nsc"].startswith("@xml/"):
        nf = os.path.join(nsc_dir, out["nsc"][5:] + ".xml")
        nsc = {"file": nf, "cleartext": [], "user_ca": [], "pins": [], "debug_overrides": False}
        try:
            r = ET.parse(nf).getroot()
            for el in r.iter():
                if el.get("cleartextTrafficPermitted") == "true":
                    doms = [d.text for d in el.findall("domain")] or ["(base-config)"]
                    nsc["cleartext"] += doms
                if el.tag == "certificates" and el.get("src") == "user":
                    nsc["user_ca"].append("debug-overrides" if any(p.tag == "debug-overrides" for p in r.iter() if el in list(p.iter())) else "trust-anchors")
                if el.tag == "pin-set":
                    nsc["pins"].append(len(el.findall("pin")))
                if el.tag == "debug-overrides":
                    nsc["debug_overrides"] = True
        except (ET.ParseError, OSError) as e:
            nsc["error"] = str(e)
        out["nsc_parsed"] = nsc
    return out


def detect_frameworks(apk_root, jadx_root):
    fw = []
    libs = set()
    for dp, _, fn in os.walk(os.path.join(apk_root, "lib")):
        libs |= set(fn)
    assets = os.path.join(apk_root, "assets")
    def has(p):
        return os.path.exists(os.path.join(assets, p))
    if has("index.android.bundle") or "libreactnativejni.so" in libs or "libreactnative.so" in libs:
        hermes = False
        bp = os.path.join(assets, "index.android.bundle")
        if os.path.exists(bp):
            hermes = open(bp, "rb").read(4) == b"\xc6\x1f\xbc\x03"
        fw.append(f"React Native (bundle assets/index.android.bundle, {'Hermes bytecode' if hermes else 'plain JS'})")
    if "libflutter.so" in libs or "libapp.so" in libs:
        fw.append("Flutter (Dart AOT in lib/*/libapp.so; ignores the system proxy and does its own TLS: "
                  "use reFlutter or a transparent iptables redirect, the Java bypass will not see it)")
    if has("www/index.html") or has("www/cordova.js"):
        fw.append("Cordova/Capacitor (assets/www)")
    if has("public/index.html") and has("capacitor.config.json"):
        fw.append("Capacitor (assets/public)")
    if any(x.startswith("libmonodroid") for x in libs) or os.path.isdir(os.path.join(apk_root, "assemblies")):
        fw.append("Xamarin/.NET (assemblies)")
    if "libunity.so" in libs or "libil2cpp.so" in libs:
        fw.append("Unity (il2cpp)" if "libil2cpp.so" in libs else "Unity")
    if any(re.match(r"libUE4\.so|libUnreal\.so", x) for x in libs):
        fw.append("Unreal Engine (native networking: libcurl/OpenSSL inside the engine library)")
    abis = sorted(os.listdir(os.path.join(apk_root, "lib"))) if os.path.isdir(os.path.join(apk_root, "lib")) else []
    return fw, abis


def cmd_static(a):
    prog, pkg = a.program, a.pkg
    md = mobile_dir(prog, pkg)
    b, allapks = base_apk(os.path.join(md, "apk"))
    if not b:
        die(f"no APK under {md}/apk; run intake first")
    work = os.path.join(md, "decoded")
    os.makedirs(work, exist_ok=True)
    env = dict(os.environ, JAVA_OPTS=os.environ.get("JAVA_OPTS", "-Xmx4g"))
    t0 = time.time()
    adir = os.path.join(work, "apktool")
    jdir = os.path.join(work, "jadx")
    if a.redo or not os.path.isdir(adir):
        r = sh(["java", "-Xmx3g", "-jar", APKTOOL_JAR, "d", "-f", "-o", adir, b], timeout=3600)
        if r.returncode != 0:
            print("apktool full decode failed, retrying without resources:", (r.stderr or r.stdout).strip()[-200:])
            sh(["java", "-Xmx3g", "-jar", APKTOOL_JAR, "d", "-f", "-r", "-o", adir, b], timeout=3600)
    if a.redo or not os.path.isdir(jdir):
        sh([JADX, "-d", jdir, "-j", "4", "--show-bad-code", "--no-imports", b], timeout=7200, env=env)
    # split APKs: decode their resources/native libs too (config splits carry the .so files)
    for sp in allapks:
        if sp == b:
            continue
        sd = os.path.join(work, "split-" + os.path.basename(sp)[:-4])
        if a.redo or not os.path.isdir(sd):
            sh(["java", "-jar", APKTOOL_JAR, "d", "-f", "-s", "-o", sd, sp], timeout=1800)
    decode_s = int(time.time() - t0)

    man_path = os.path.join(adir, "AndroidManifest.xml")
    man = parse_manifest(man_path, os.path.join(adir, "res/xml"), badging_sdk(b))
    fw, abis = detect_frameworks(adir, jdir)
    for sp in allapks:
        sd = os.path.join(work, "split-" + os.path.basename(sp)[:-4])
        if os.path.isdir(os.path.join(sd, "lib")):
            f2, a2 = detect_frameworks(sd, jdir)
            fw += [x for x in f2 if x not in fw]
            abis += [x for x in a2 if x not in abis]

    urls, paths, secrets, bridges, jsenabled = {}, {}, {}, [], []
    roots = [os.path.join(jdir, "sources"), os.path.join(adir, "res"), os.path.join(adir, "assets"),
             os.path.join(adir, "lib"), os.path.join(adir, "unknown")]
    roots += [os.path.join(work, d) for d in os.listdir(work) if d.startswith("split-")]
    nfiles = 0
    for p, text in iter_texts(roots):
        nfiles += 1
        rel = os.path.relpath(p, md)
        for u in URL_RE.findall(text):
            u = u.rstrip(".,;:'\")")
            urls.setdefault(u, rel)
        for m in API_PATH_RE.findall(text):
            paths.setdefault(m, rel)
        for verb, pth in RETROFIT_RE.findall(text):
            if pth:
                paths.setdefault(pth if pth.startswith(("/", "http")) else "/" + pth, rel + f" (@{verb})")
        for name, rx in SECRET_RES:
            for mm in rx.finditer(text):
                val = mm.group(1) if rx.groups else mm.group(0)
                if name == "generic-assignment" and re.fullmatch(r"[a-z_.]+|[A-Z_]+", val):
                    continue
                secrets.setdefault((name, val), rel)
        if p.endswith((".java", ".kt")):
            if "addJavascriptInterface" in text:
                for i, line in enumerate(text.splitlines(), 1):
                    if "addJavascriptInterface" in line:
                        bridges.append(f"{rel}:{i}: {line.strip()[:160]}")
            if "@JavascriptInterface" in text:
                cls = re.search(r"class\s+(\w+)", text)
                meths = re.findall(r"@JavascriptInterface\s+(?:public\s+)?[\w<>\[\], ]+\s+(\w+)\s*\(", text)
                bridges.append(f"{rel}: class {cls.group(1) if cls else '?'} exposes @JavascriptInterface {', '.join(meths[:12])}")
            if "setJavaScriptEnabled(true)" in text and len(jsenabled) < 40:
                jsenabled.append(rel)
    # firebase / google-services values from res/values/strings.xml
    firebase = {}
    sx = os.path.join(adir, "res/values/strings.xml")
    if os.path.exists(sx):
        try:
            for s in ET.parse(sx).getroot().iter("string"):
                if s.get("name") in FIREBASE_KEYS and s.text:
                    firebase[s.get("name")] = s.text
        except ET.ParseError:
            pass
    for k, v in firebase.items():
        if k in ("google_api_key", "google_crash_reporting_api_key"):
            secrets.setdefault(("google-api-key", v), "res/values/strings.xml " + k)

    hosts = {}
    for u in urls:
        h = (urlparse(u).hostname or "").lower()
        if h and not NOISE_HOSTS.search(h):
            hosts.setdefault(h, 0)
            hosts[h] += 1
    for k in ("firebase_database_url",):
        if k in firebase:
            h = urlparse(firebase[k]).hostname
            if h:
                hosts.setdefault(h.lower(), 1)
    in_h = sorted(h for h in hosts if host_scoped(prog, h))
    out_h = sorted(h for h in hosts if h not in in_h)
    in_urls = sorted(u for u in urls if (urlparse(u).hostname or "").lower() in in_h)

    # ------------------------------------------------------------- write artifacts
    with open(os.path.join(md, "hosts.txt"), "w") as f:
        f.write(f"# hosts referenced by {pkg} ({now()}); IN = matches targets/{prog}/SCOPE.txt\n")
        for h in in_h:
            f.write(f"IN   {h}\t{hosts[h]}\n")
        for h in out_h:
            f.write(f"OUT  {h}\t{hosts[h]}\n")
    with open(os.path.join(md, "urls.txt"), "w") as f:
        for u in sorted(urls):
            h = (urlparse(u).hostname or "").lower()
            f.write(f"{'IN ' if h in in_h else 'OUT'} {u}\t{urls[u]}\n")
    with open(os.path.join(md, "secrets.txt"), "w") as f:
        f.write("# candidate secrets: a string match is NOT a finding until a live in-scope call proves it works\n")
        for (n, v), rel in sorted(secrets.items()):
            f.write(f"{n}\t{v}\t{rel}\n")
    write_routes_static(prog, pkg, md, in_urls, paths)
    summary = {"pkg": pkg, "program": prog, "ts": now(), "decode_seconds": decode_s, "files_scanned": nfiles,
               "manifest": man, "frameworks": fw, "abis": abis, "hosts_in": in_h, "hosts_out_count": len(out_h),
               "urls_in": len(in_urls), "urls_total": len(urls), "api_paths": len(paths),
               "secrets": [{"type": n, "value": v, "where": rel} for (n, v), rel in sorted(secrets.items())],
               "firebase": firebase, "webview_bridges": bridges, "js_enabled_files": jsenabled}
    json.dump(summary, open(os.path.join(md, "static.json"), "w"), indent=1)
    write_static_md(md, summary, in_urls, paths, out_h)
    print(f"static {pkg}: {nfiles} files, {len(urls)} URLs ({len(in_urls)} in scope), {len(hosts)} hosts "
          f"({len(in_h)} in scope), {len(paths)} API paths, {len(secrets)} secret candidates, "
          f"{len(man['exported'])} exported components, {len(man['deeplinks'])} deeplink filters, "
          f"{len(bridges)} JS-bridge lines, frameworks: {', '.join(fw) or 'native Java/Kotlin'}")
    print(f"  -> {os.path.join(md, 'STATIC.md')}")
    return 0


def auto_routes_file(prog, pkg):
    d = os.path.join(TARGETS, prog, "hunts/auto-exposure/routes")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, f"android-{pkg}.txt")


def write_routes_static(prog, pkg, md, in_urls, paths):
    """routes.txt in the auto-hunt routes/ format: '#' comment header, relative paths, absolute URLs.
    The auto-exposure copy carries ONLY absolute in-scope URLs (a relative path has no host there)."""
    clean_in = sorted({c for c in (u.split("?")[0].split("#")[0] for u in in_urls) if not re.search(r"[{}$<>%]", c)})
    rel = sorted(p for p in paths if p.startswith("/") and not re.search(r"[{}$:<>]|\.\.|//", p))
    with open(os.path.join(md, "routes.txt"), "w") as f:
        f.write(f"# routes mined statically from APK {pkg} at {now()} (relative paths have no host binding)\n")
        for p in rel:
            f.write(p + "\n")
        for u in clean_in:
            f.write(u + "\n")
    rf = auto_routes_file(prog, pkg)
    keep = []
    if os.path.exists(rf):  # keep the dynamic section a previous run appended
        keep = [l.rstrip("\n") for l in open(rf) if l.strip()]
        try:
            i = next(i for i, l in enumerate(keep) if l.startswith("# dynamic"))
            keep = keep[i:]
        except StopIteration:
            keep = []
    with open(rf, "w") as f:
        f.write(f"# routes mined from APK {pkg} (static) at {now()} - in-scope absolute URLs only, sweep GET-only\n")
        for u in clean_in:
            if u.startswith("http"):
                f.write(u + "\n")
        for l in keep:
            f.write(l + "\n")


def write_static_md(md, s, in_urls, paths, out_h):
    m = s["manifest"]
    L = [f"# STATIC - {s['pkg']} ({s['program']})", "",
         f"Generated {s['ts']} by scripts/workbench/droid.py static. Raw: static.json, urls.txt, hosts.txt, "
         f"secrets.txt, routes.txt, decoded/ (apktool + jadx).", "",
         "Every item below is a STATIC candidate. Nothing here is a finding until a live in-scope request "
         "captures the capability (T-45, mobile-hunter contract).", "",
         "## App", f"- package `{m.get('package')}` targetSdk {m.get('targetSdk')} ABIs {', '.join(s['abis']) or 'none (pure Java)'}",
         f"- frameworks: {', '.join(s['frameworks']) or 'native Java/Kotlin'}",
         f"- debuggable={m.get('debuggable')} allowBackup={m.get('allowBackup')} "
         f"usesCleartextTraffic={m.get('usesCleartextTraffic')} networkSecurityConfig={m.get('nsc')}"]
    n = m.get("nsc_parsed")
    if n:
        L.append(f"- NSC: cleartext permitted for {n['cleartext'] or 'none'}; user-CA trust {n['user_ca'] or 'no'}; "
                 f"pin-sets {n['pins'] or 'none'}; debug-overrides {n['debug_overrides']}")
    L += ["", f"## In-scope hosts ({len(s['hosts_in'])})"] + [f"- {h}" for h in s["hosts_in"]]
    L += ["", f"Out-of-scope hosts referenced: {len(out_h)} (hosts.txt; passive observation, never probed)"]
    L += ["", f"## In-scope URLs ({len(in_urls)}, first 60)"] + [f"- {u}" for u in in_urls[:60]]
    L += ["", f"## API path literals ({len(paths)}, first 80)"] + [f"- `{p}` ({w})" for p, w in sorted(paths.items())[:80]]
    L += ["", f"## Secret candidates ({len(s['secrets'])})"]
    for x in s["secrets"][:60]:
        v = x["value"]
        L.append(f"- {x['type']}: `{v[:12]}...{v[-4:] if len(v) > 20 else ''}` ({x['where']})")
    if s["firebase"]:
        L += ["", "## Firebase / google-services"] + [f"- {k}: `{v}`" for k, v in s["firebase"].items()]
        L.append("- next: unauth read of `<firebase_database_url>/.json`, Firestore REST with the api key, "
                 "Identity Toolkit signUp with the api key (is self-signup open?)")
    L += ["", f"## Exported components ({len(m['exported'])})"] + [f"- {e}" for e in m["exported"][:80]]
    L += ["", f"## Deeplinks ({len(m['deeplinks'])})"]
    for d in m["deeplinks"][:60]:
        L.append(f"- {d['component']}: {'/'.join(d['schemes'])}://{','.join(d['hosts']) or '*'} {d['paths']} "
                 f"browsable={d['browsable']} autoVerify={d['autoVerify']}")
    L += ["", f"## WebView JavaScript bridges ({len(s['webview_bridges'])})"] + [f"- {b}" for b in s["webview_bridges"][:40]]
    L += [f"- setJavaScriptEnabled(true) in {len(s['js_enabled_files'])} file(s)"]
    L += ["", "## Device-gated items", "Exported components, deeplinks and JS bridges are PARKED LEADS for the "
          "mobile-hunter (runtime on-device exploitation is disabled in its agent file). The live-service legs "
          "(hosts, routes, keys) are the fileable surface."]
    with open(os.path.join(md, "STATIC.md"), "w") as f:
        f.write("\n".join(L) + "\n")


# ----------------------------------------------------------------------------------------- device

def emu_running():
    r = sh([ADB, "devices"], timeout=20)
    return any(l.startswith(SERIAL) and l.endswith("device") for l in r.stdout.splitlines())


def wait_boot(timeout=420):
    t0 = time.time()
    sh([ADB, "-s", SERIAL, "wait-for-device"], timeout=timeout)
    while time.time() - t0 < timeout:
        r = ashell("getprop sys.boot_completed", timeout=20)
        if r.stdout.strip() == "1":
            return True
        time.sleep(3)
    return False


def root_device():
    adb("root", timeout=30)
    time.sleep(2)
    sh([ADB, "-s", SERIAL, "wait-for-device"], timeout=120)
    return ashell("id -u", timeout=20).stdout.strip() == "0"


AVD_PIN = os.environ.get("WB_AVD_PIN", "1234")  # vr1 carries a PIN lock set on 2026-10-10 (locksettings verify)


def unlock_user():
    """A PIN-locked AVD boots RUNNING_LOCKED: credential-encrypted storage is sealed, nothing non-directBoot
    launches and `resolve-activity` says 'No activity found' (frida: 'unable to find a front-door activity')."""
    for _ in range(3):
        if "RUNNING_UNLOCKED" in ashell("dumpsys user | grep -m1 'State:'").stdout:
            return True
        ashell("input keyevent KEYCODE_WAKEUP; sleep 1; input keyevent 82; sleep 1; input swipe 540 1800 540 600 200; "
               f"sleep 1; input text {AVD_PIN}; input keyevent 66; sleep 4", timeout=60)
    ok = "RUNNING_UNLOCKED" in ashell("dumpsys user | grep -m1 'State:'").stdout
    if not ok:
        print(f"WARN: user 0 still locked (PIN {AVD_PIN!r} wrong? set WB_AVD_PIN)")
    return ok


def ca_hash():
    r = sh(["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-noout", "-in", MITM_CA], check=True)
    return r.stdout.strip().splitlines()[0]


APEX_SCRIPT = r"""
set -e
H={h}
mkdir -p -m 700 /data/local/tmp/wb-ca
cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/wb-ca/ 2>/dev/null || true
cp /data/local/tmp/$H.0 /data/local/tmp/wb-ca/$H.0
mount -t tmpfs tmpfs /system/etc/security/cacerts
cp /data/local/tmp/wb-ca/* /system/etc/security/cacerts/
chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*
for Z in $(pidof zygote) $(pidof zygote64); do
  nsenter --mount=/proc/$Z/ns/mnt -- /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts
done
for Z in $(pidof zygote) $(pidof zygote64); do
  for P in $(ps -o PID= -P $Z); do
    nsenter --mount=/proc/$P/ns/mnt -- /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts 2>/dev/null || true
  done
done
rm -rf /data/local/tmp/wb-ca
echo APEX-CA-OK
"""


def install_ca(st):
    h = ca_hash()
    z = ashell("pidof zygote64 || pidof zygote").stdout.split()
    if z and ashell(f"nsenter --mount=/proc/{z[0]}/ns/mnt -- ls /apex/com.android.conscrypt/cacerts/{h}.0").returncode == 0:
        st.setdefault("ca", {"hash": h})["visible_to_zygote"] = True  # already installed this boot: idempotent
        return st["ca"]
    adb("push", MITM_CA, f"/data/local/tmp/{h}.0", timeout=60, check=True)
    sdk = int(ashell("getprop ro.build.version.sdk").stdout.strip() or 0)
    res = {"hash": h, "sdk": sdk}
    # legacy store (pre-14, and the source the apex trick copies from on 14+ when remount worked)
    rm = adb("remount", timeout=120)
    res["remount"] = (rm.stdout + rm.stderr).strip()[-200:]
    if rm.returncode == 0 and "reboot" not in res["remount"].lower():
        ashell(f"cp /data/local/tmp/{h}.0 /system/etc/security/cacerts/{h}.0 && chmod 644 /system/etc/security/cacerts/{h}.0")
    if sdk >= 34:
        r = ashell(APEX_SCRIPT.format(h=h), timeout=120)
        res["apex"] = "APEX-CA-OK" in r.stdout
        if not res["apex"]:
            res["apex_err"] = (r.stderr or r.stdout)[-300:]
    z = ashell("pidof zygote64 || pidof zygote").stdout.split()
    if z:
        chk = ashell(f"nsenter --mount=/proc/{z[0]}/ns/mnt -- ls /apex/com.android.conscrypt/cacerts/{h}.0")
        res["visible_to_zygote"] = chk.returncode == 0
    st["ca"] = res
    return res


def burp_port():
    try:
        r = sh([sys.executable, os.path.join(WS, "scripts/bbtools/burp_resolve.py")], timeout=20)
        return int(json.loads(r.stdout).get("proxy_port") or 0) or None
    except Exception:
        return None


def start_mitm(st, flows_file, jsonl, scope=None, burp=False, port=None):
    stop_mitm(st)
    port = port or st.get("mitm_port") or MITM_PORT
    os.makedirs(os.path.dirname(flows_file), exist_ok=True)
    cmd = ["mitmdump", "--listen-host", "127.0.0.1", "-p", str(port), "-w", flows_file, "-s", ADDON, "-q",
           "--set", "stream_large_bodies=5m"]
    cmd += os.environ.get("WB_MITM_EXTRA", "").split()  # e.g. --set ssl_verify_upstream_trusted_ca=<pem>

    if burp:
        bp = burp_port()
        if not bp:
            die("--burp: burp_resolve.py found no Burp proxy port")
        cmd += ["--mode", f"upstream:http://127.0.0.1:{bp}", "--ssl-insecure"]
        st["mitm_upstream"] = f"burp:{bp}"
    else:
        st.pop("mitm_upstream", None)
    # PYTHONNOUSERSITE: the user-site cryptography 50 breaks the system mitmproxy/pyOpenSSL (GEN_EMAIL error)
    env = dict(os.environ, WB_JSONL=jsonl, WB_SCOPE=scope or "", PYTHONNOUSERSITE="1")
    log = open(os.path.join(STATE_DIR, "mitmdump.log"), "a")
    p = subprocess.Popen(cmd, stdout=log, stderr=log, stdin=subprocess.DEVNULL, env=env, start_new_session=True)
    time.sleep(2)
    if p.poll() is not None:
        die(f"mitmdump exited rc={p.returncode}; see {STATE_DIR}/mitmdump.log (port {port} busy?)")
    st.update(mitm_pid=p.pid, mitm_port=port, mitm_flows=flows_file, mitm_jsonl=jsonl)
    save_state(st)
    return p.pid


def stop_mitm(st):
    pid = st.get("mitm_pid")
    if alive(pid):
        os.kill(pid, signal.SIGTERM)
        for _ in range(20):
            if not alive(pid):
                break
            time.sleep(0.25)
        if alive(pid):
            os.kill(pid, signal.SIGKILL)
    st.pop("mitm_pid", None)


def frida_server_path():
    return os.path.join(WB, f"frida/frida-server-{VERSIONS['frida']}-android-x86_64")


def start_frida_server():
    if ashell("pidof frida-server").stdout.strip():
        return True
    adb("push", frida_server_path(), "/data/local/tmp/frida-server", timeout=180, check=True)
    ashell("chmod 755 /data/local/tmp/frida-server")
    ashell("/data/local/tmp/frida-server -D </dev/null >/dev/null 2>&1 &", timeout=30)
    time.sleep(2)
    if not ashell("pidof frida-server").stdout.strip():
        ashell("setenforce 0")
        ashell("/data/local/tmp/frida-server -D </dev/null >/dev/null 2>&1 &", timeout=30)
        time.sleep(2)
    return bool(ashell("pidof frida-server").stdout.strip())


def cmd_up(a):
    os.makedirs(STATE_DIR, exist_ok=True)
    st = load_state()
    try:
        os.close(os.open("/dev/kvm", os.O_RDWR))
    except OSError as e:
        die(f"/dev/kvm not usable ({e}). NEEDS: sudo usermod -aG kvm {os.environ.get('USER')} (then re-login)")
    if not emu_running():
        cmd = [EMU, "-avd", AVD, "-port", EMU_PORT, "-no-window", "-no-audio", "-no-boot-anim",
               "-gpu", "swiftshader_indirect", "-writable-system", "-no-snapshot", "-netdelay", "none",
               "-netspeed", "full"]
        log = open(os.path.join(STATE_DIR, "emulator.log"), "a")
        p = subprocess.Popen(cmd, stdout=log, stderr=log, stdin=subprocess.DEVNULL, start_new_session=True)
        st.update(emu_pid=p.pid, booted_at=now())
        save_state(st)
        print(f"emulator pid {p.pid} booting headless ({AVD}) ...")
        if not wait_boot():
            die(f"boot timeout; see {STATE_DIR}/emulator.log")
    print("boot ok")
    if not root_device():
        die("adb root failed (needs a google_apis image, not google_play)")
    rm = adb("remount", timeout=120)
    if "reboot" in (rm.stdout + rm.stderr).lower():  # first -writable-system boot: verity disabled, needs a reboot
        print("remount asked for a reboot (verity just disabled), rebooting once ...")
        adb("reboot", timeout=30)
        time.sleep(5)
        if not wait_boot():
            die("boot timeout after the verity reboot")
        root_device()
    print(f"user unlocked: {unlock_user()}")
    ca = install_ca(st)
    print(f"CA {ca['hash']}.0 sdk={ca['sdk']} remount={'ok' if 'remount succeeded' in ca.get('remount', '').lower() else ca.get('remount', '')[:60]!r} "
          f"apex={ca.get('apex')} visible_to_zygote={ca.get('visible_to_zygote')}")
    idle = os.path.join(STATE_DIR, "idle")
    start_mitm(st, os.path.join(idle, f"{time.strftime('%Y%m%d-%H%M%S')}.mitm"), os.path.join(idle, "flows.jsonl"),
               burp=a.burp, port=a.port)
    ashell(f"settings put global http_proxy 10.0.2.2:{st['mitm_port']}")
    print(f"mitmdump pid {st['mitm_pid']} on 127.0.0.1:{st['mitm_port']} (device proxy 10.0.2.2:{st['mitm_port']})"
          f"{' upstream ' + st['mitm_upstream'] if st.get('mitm_upstream') else ''}")
    fs = start_frida_server()
    st["frida_server"] = fs
    save_state(st)
    r = sh([FRIDA_PS, "-U"], timeout=60)
    print(f"frida-server {'running' if fs else 'FAILED'}; frida-ps -U -> {len(r.stdout.splitlines()) - 2} processes")
    return 0


def cmd_down(a):
    st = load_state()
    if emu_running():
        ashell("settings put global http_proxy :0", timeout=20)
        ashell("pkill -f frida-server", timeout=20)
        adb("emu", "kill", timeout=30)
    stop_mitm(st)
    pid = st.get("emu_pid")
    for _ in range(60):
        if not alive(pid):
            break
        time.sleep(0.5)
    if alive(pid):
        os.kill(pid, signal.SIGTERM)
        time.sleep(3)
        if alive(pid):
            os.kill(pid, signal.SIGKILL)
    # any qemu left for this AVD (ours only: matched on -avd vr1 -port 5554)
    for l in sh(["pgrep", "-af", "qemu-system"], timeout=10).stdout.splitlines():
        if f"-avd {AVD}" in l or f"@{AVD}" in l:
            try:
                os.kill(int(l.split()[0]), signal.SIGKILL)
            except (OSError, ValueError):
                pass
    for l in sh(["pgrep", "-af", "frida -U"], timeout=10).stdout.splitlines():
        if BYPASS_JS in l:
            try:
                os.kill(int(l.split()[0]), signal.SIGTERM)
            except (OSError, ValueError):
                pass
    sh([ADB, "kill-server"], timeout=20)
    for k in ("emu_pid", "frida_server", "mitm_port", "mitm_flows", "mitm_jsonl", "ca", "mitm_upstream"):
        st.pop(k, None)
    st["down_at"] = now()
    save_state(st)
    left = sh(["pgrep", "-af", "qemu-system|frida-server|mitm_flows.py"], timeout=10).stdout.strip()
    print("down: emulator, workbench mitmdump, frida stopped; adb server killed")
    print("leftover: " + (left or "none"))
    return 0


def cmd_status(a):
    st = load_state()
    up = emu_running()
    print(f"emulator  {'UP ' + SERIAL if up else 'down'}  (pid {st.get('emu_pid')} alive={alive(st.get('emu_pid'))})")
    if up:
        print(f"  boot_completed={ashell('getprop sys.boot_completed').stdout.strip()} uid={ashell('id -u').stdout.strip()} "
              f"proxy={ashell('settings get global http_proxy').stdout.strip()} "
              f"frida-server={ashell('pidof frida-server').stdout.strip() or 'no'}")
        print(f"  CA {st.get('ca')}")
    print(f"mitmdump  pid {st.get('mitm_pid')} alive={alive(st.get('mitm_pid'))} port {st.get('mitm_port')} "
          f"{st.get('mitm_upstream', '')}\n  flows {st.get('mitm_flows')}")
    if st.get("last_run"):
        print(f"last run  {st['last_run']}")
    return 0


# ----------------------------------------------------------------------------------------- run

STATIC_EXT = re.compile(r"\.(png|jpe?g|gif|webp|svg|ico|css|js|mjs|woff2?|ttf|otf|eot|mp4|mp3|m4a|webm|avif|map)$", re.I)


def cmd_run(a):
    prog, pkg = a.program, a.pkg
    md = mobile_dir(prog, pkg)
    b, allapks = base_apk(os.path.join(md, "apk"))
    if not b:
        die(f"no APK under {md}/apk; run intake first")
    if not emu_running():
        die("emulator is down: run `droid.py up` first")
    st = load_state()
    unlock_user()
    ts = time.strftime("%Y%m%d-%H%M%S")
    fdir = os.path.join(md, "flows")
    os.makedirs(fdir, exist_ok=True)
    flows = os.path.join(fdir, f"{ts}.mitm")
    jsonl = os.path.join(fdir, f"{ts}.flows.jsonl")
    start_mitm(st, flows, jsonl, scope=scope_file(prog), burp=a.burp)
    ashell(f"settings put global http_proxy 10.0.2.2:{st['mitm_port']}")
    # install
    r = adb(*(["install-multiple", "-r", "-g"] + allapks if len(allapks) > 1 else ["install", "-r", "-g", b]), timeout=900)
    if "Success" not in r.stdout:
        die(f"install failed: {(r.stdout + r.stderr).strip()[-300:]}\n(arm-only native libs on the x86_64 AVD "
            f"fail with INSTALL_FAILED_NO_MATCHING_ABIS: that app needs an arm64 device)")
    print(f"installed {pkg} ({len(allapks)} APK)")
    flog = os.path.join(fdir, f"{ts}.frida.log")
    fp = None
    if not a.no_frida:
        if not start_frida_server():
            die("frida-server not running")
        secs = int(a.minutes * 60)
        fp = subprocess.Popen([FRIDA, "-U", "-f", pkg, "-l", BYPASS_JS, "-q", "-t", str(secs), "--kill-on-exit"],
                              stdout=open(flog, "w"), stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                              start_new_session=True)
        print(f"frida spawn {pkg} with {os.path.relpath(BYPASS_JS, WS)} (log {flog})")
    else:
        act = ashell(f"cmd package resolve-activity --brief {pkg} | tail -n 1").stdout.strip()
        ashell(f"am start -n {act}" if "/" in act else f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1")
    time.sleep(8)
    if fp and fp.poll() is not None:  # spawn refused: launch normally and attach late (early pins may be missed)
        print("frida spawn failed: " + open(flog, errors="replace").read().strip()[-200:])
        act = ashell(f"cmd package resolve-activity --brief {pkg} | tail -n 1").stdout.strip()
        ashell(f"am start -n {act}" if "/" in act else f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1")
        time.sleep(4)
        pid = ashell(f"pidof {pkg}").stdout.split()
        if pid:
            fp = subprocess.Popen([FRIDA, "-U", "-p", pid[0], "-l", BYPASS_JS, "-q", "-t", str(int(a.minutes * 60))],
                                  stdout=open(flog, "a"), stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                  start_new_session=True)
            print(f"frida attached late to pid {pid[0]}")
    if a.monkey:
        print(f"monkey {a.monkey} events, throttle 600ms")
        ashell(f"monkey -p {pkg} --throttle 600 --pct-syskeys 0 --pct-appswitch 0 -s 4242 {a.monkey}",
               timeout=int(a.monkey * 0.8) + 120)
    end = time.time() + a.minutes * 60 - 8
    while time.time() < end:
        if fp and fp.poll() is not None:
            break
        time.sleep(5)
    if fp and fp.poll() is None:
        fp.terminate()
        try:
            fp.wait(15)
        except subprocess.TimeoutExpired:
            fp.kill()
    ashell(f"am force-stop {pkg}")
    time.sleep(2)
    stop_mitm(st)  # flush the -w file
    save_state(st)
    recs = []
    for l in open(jsonl) if os.path.exists(jsonl) else []:
        try:
            recs.append(json.loads(l))
        except ValueError:
            pass
    # the run-level flows.jsonl the task names: one cumulative summary per package
    with open(os.path.join(md, "flows.jsonl"), "a") as f:
        for x in recs:
            f.write(json.dumps(dict(x, run=ts)) + "\n")
    added = append_dynamic_routes(prog, pkg, recs, ts)
    ins = [x for x in recs if x.get("in_scope") and x.get("method")]
    outs = [x for x in recs if not x.get("in_scope") and x.get("method")]
    tlsfail = [x for x in recs if x.get("event") == "client-tls-failed"]
    hooks = ""
    if os.path.exists(flog):
        hooks = next((l.strip() for l in open(flog, errors="replace") if "attached hooks" in l), "")
    st["last_run"] = {"pkg": pkg, "program": prog, "ts": ts, "flows": len(recs), "in_scope": len(ins)}
    save_state(st)
    print(f"run {ts}: {len(recs)} flow lines, {len(ins)} in-scope, {len(outs)} out-of-scope (passive), "
          f"{len(tlsfail)} client TLS failures (pinning not bypassed / native TLS), {added} new in-scope routes")
    print(f"  frida: {hooks or 'no hook line (see ' + flog + ')'}")
    print(f"  flows {flows}\n  jsonl {jsonl}")
    # restart the idle recorder so the proxy setting on the device keeps working
    idle = os.path.join(STATE_DIR, "idle")
    start_mitm(st, os.path.join(idle, f"{time.strftime('%Y%m%d-%H%M%S')}.mitm"), os.path.join(idle, "flows.jsonl"))
    return 0


def append_dynamic_routes(prog, pkg, recs, ts):
    rf = auto_routes_file(prog, pkg)
    have = set()
    if os.path.exists(rf):
        have = {l.strip() for l in open(rf) if l.strip() and not l.startswith("#")}
    else:
        with open(rf, "w") as f:
            f.write(f"# routes from APK {pkg} - in-scope absolute URLs only, sweep GET-only\n")
    new = []
    for x in recs:
        if not x.get("in_scope") or not x.get("method") or not x.get("host"):
            continue
        if STATIC_EXT.search(x.get("path", "")):
            continue
        port = x.get("port")
        default = (x.get("scheme") == "https" and port == 443) or (x.get("scheme") == "http" and port == 80)
        u = f"{x.get('scheme', 'https')}://{x['host']}{'' if default or not port else ':' + str(port)}{x.get('path', '/')}"
        if re.search(r"[{}$<>]", u) or u in have:
            continue
        have.add(u)
        new.append((u, x.get("method"), x.get("status")))
    if new:
        with open(rf, "a") as f:
            f.write(f"# dynamic flows {ts} (observed {', '.join(sorted({m for _, m, _ in new}))}; replay GET-only)\n")
            for u, _, _ in new:
                f.write(u + "\n")
        with open(os.path.join(mobile_dir(prog, pkg), "routes.txt"), "a") as f:
            f.write(f"# dynamic flows {ts}\n")
            for u, m, s in new:
                f.write(u + "\n")
    return len(new)


# ----------------------------------------------------------------------------------------- report

def cmd_report(a):
    prog, pkg = a.program, a.pkg
    md = mobile_dir(prog, pkg)
    print(f"== droid report {prog} / {pkg}  ({md})")
    try:
        it = json.load(open(os.path.join(md, "intake.json")))
        print(f"intake   {it['ts']} {it['decision']} {len(it['apks'])} APK(s) {'split' if it['split'] else 'single'}")
    except (OSError, ValueError):
        print("intake   none")
    try:
        s = json.load(open(os.path.join(md, "static.json")))
        m = s["manifest"]
        print(f"static   {s['ts']} targetSdk {m.get('targetSdk')} ABIs {','.join(s['abis']) or '-'} "
              f"fw {'; '.join(x.split(' (')[0] for x in s['frameworks']) or 'Java/Kotlin'}")
        print(f"  hosts in-scope {len(s['hosts_in'])} (out {s['hosts_out_count']}), URLs in-scope {s['urls_in']}/{s['urls_total']}, "
              f"API paths {s['api_paths']}")
        for h in s["hosts_in"][:8]:
            print(f"    {h}")
        st = {}
        for x in s["secrets"]:
            st[x["type"]] = st.get(x["type"], 0) + 1
        print(f"  secrets {', '.join(f'{k}={v}' for k, v in sorted(st.items())) or 'none'}")
        if s["firebase"]:
            print(f"  firebase {s['firebase'].get('project_id', '')} {s['firebase'].get('firebase_database_url', '')}")
        print(f"  exported {len(m['exported'])} ({sum('NO-PERMISSION' in e for e in m['exported'])} without permission), "
              f"deeplinks {len(m['deeplinks'])}, JS bridges {len(s['webview_bridges'])}, debuggable {m.get('debuggable')}, "
              f"cleartext {m.get('usesCleartextTraffic')}")
        n = m.get("nsc_parsed")
        if n:
            print(f"  NSC cleartext {n['cleartext'][:4]} user-CA {n['user_ca']} pins {n['pins']}")
    except (OSError, ValueError, KeyError):
        print("static   none (run droid.py static)")
    fj = os.path.join(md, "flows.jsonl")
    if os.path.exists(fj):
        recs = [json.loads(l) for l in open(fj) if l.strip()]
        runs = sorted({r.get("run") for r in recs})
        ins = [r for r in recs if r.get("in_scope") and r.get("method")]
        hosts_in, hosts_out = {}, {}
        for r in recs:
            if r.get("method"):
                d = hosts_in if r.get("in_scope") else hosts_out
                d[r["host"]] = d.get(r["host"], 0) + 1
        print(f"dynamic  {len(runs)} run(s), {len(recs)} flow lines, {len(ins)} in-scope; "
              f"TLS failures {sum(r.get('event') == 'client-tls-failed' for r in recs)}")
        for h, c in sorted(hosts_in.items(), key=lambda x: -x[1])[:8]:
            print(f"    IN  {c:4d} {h}")
        print(f"    out-of-scope hosts (passive): {len(hosts_out)}")
        seen = set()
        for r in ins:
            k = (r["method"], r["host"], r["path"])
            if k not in seen and len(seen) < 12:
                seen.add(k)
                print(f"    {r['method']:6s} {r.get('status')} {r['host']}{r['path'][:80]} ({r.get('length')}B)")
    else:
        print("dynamic  none (droid.py up; droid.py run)")
    rf = auto_routes_file(prog, pkg)
    n = sum(1 for l in open(rf) if l.strip() and not l.startswith("#")) if os.path.exists(rf) else 0
    print(f"routes   {n} in-scope URL(s) in {os.path.relpath(rf, WS) if rf.startswith(WS) else rf}")
    return 0


def main(argv):
    ap = argparse.ArgumentParser(prog="droid", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd")
    sp.add_parser("setup")
    p = sp.add_parser("intake")
    p.add_argument("program")
    p.add_argument("target")
    p.add_argument("--force-oos-research", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p = sp.add_parser("static")
    p.add_argument("program")
    p.add_argument("pkg")
    p.add_argument("--redo", action="store_true", help="re-run apktool/jadx even if decoded/ exists")
    p = sp.add_parser("up")
    p.add_argument("--burp", action="store_true", help="chain mitmdump upstream into Burp (port via burp_resolve.py)")
    p.add_argument("--port", type=int, default=None)
    sp.add_parser("down")
    sp.add_parser("status")
    p = sp.add_parser("run")
    p.add_argument("program")
    p.add_argument("pkg")
    p.add_argument("--minutes", type=float, default=3)
    p.add_argument("--monkey", type=int, default=0, help="adb monkey event count (keep it low, e.g. 150)")
    p.add_argument("--no-frida", action="store_true")
    p.add_argument("--burp", action="store_true")
    p = sp.add_parser("report")
    p.add_argument("program")
    p.add_argument("pkg")
    a = ap.parse_args(argv)
    fn = {"setup": cmd_setup, "intake": cmd_intake, "static": cmd_static, "up": cmd_up, "down": cmd_down,
          "status": cmd_status, "run": cmd_run, "report": cmd_report}.get(a.cmd)
    if not fn:
        ap.print_help()
        return 2
    return fn(a) or 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
