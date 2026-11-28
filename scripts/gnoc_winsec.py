"""Windows Security, read from WSL (or Windows): Defender antivirus status and settings, and the firewall profiles.

The user's desktop, 2026-11-23: "are the windows defender settings correct on this machine?" - under WSL the lead ran
`powershell -Command "Get-MpPreference"` six times (exit 127: inside WSL it is powershell.exe), then swept the Linux
side four times. The defender reads Windows itself now: read-only, no administrator needed for the status.

    check() -> (rows, findings)   rows: what was read; findings: [(severity, text, fix)]
    render(rows, findings) -> text
"""
import json
import os
import shutil
import subprocess

PS = ("$ErrorActionPreference='SilentlyContinue'; "
      "$s = Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,"
      "BehaviorMonitorEnabled,IoavProtectionEnabled,OnAccessProtectionEnabled,IsTamperProtected,"
      "AntivirusSignatureAge,AntivirusSignatureLastUpdated,QuickScanAge,FullScanAge,AMRunningMode; "
      "$p = Get-MpPreference | Select-Object DisableRealtimeMonitoring,PUAProtection,MAPSReporting,"
      "SubmitSamplesConsent,EnableControlledFolderAccess,EnableNetworkProtection,ExclusionPath,ExclusionProcess; "
      "$f = Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction; "
      "[pscustomobject]@{status=$s; prefs=$p; firewall=@($f)} | ConvertTo-Json -Depth 4 -Compress")


def _exe():
    return shutil.which("powershell.exe") or shutil.which("powershell")


def available():
    return bool(_exe())


def read(timeout=60):
    exe = _exe()
    if not exe:
        raise RuntimeError("this is not Windows or WSL: there is no Windows Security to read here")
    r = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", PS], capture_output=True, text=True,
                       timeout=timeout, cwd="/mnt/c" if os.path.isdir("/mnt/c") else None)
    out = (r.stdout or "").strip()
    if not out.startswith("{"):
        raise RuntimeError(f"PowerShell gave no status ({(r.stderr or out or 'empty').strip()[:200]})")
    return json.loads(out)


def _on(v):
    return v is True or str(v).lower() in ("true", "1", "enabled")


def findings(d):
    s, p = d.get("status") or {}, d.get("prefs") or {}
    out = []
    if not s:
        out.append(("high", "Microsoft Defender Antivirus did not report a status",
                    "another antivirus may be installed and own protection (Windows Security > Virus & threat "
                    "protection shows which); if none is, turn Defender on there"))
        return out
    if str(s.get("AMRunningMode", "")).lower() in ("passive mode", "edr in block mode") or not _on(s.get("AntivirusEnabled")):
        out.append(("warn", f"Defender is not the active antivirus (mode: {s.get('AMRunningMode') or 'off'})",
                    "fine if another antivirus is installed and up to date; otherwise turn Defender on"))
    if not _on(s.get("RealTimeProtectionEnabled")) or _on(p.get("DisableRealtimeMonitoring")):
        out.append(("high", "real-time protection is OFF",
                    "Windows Security > Virus & threat protection > Manage settings > Real-time protection: On"))
    if s.get("IsTamperProtected") is not None and not _on(s.get("IsTamperProtected")):
        out.append(("warn", "tamper protection is off (malware can switch Defender off)",
                    "Windows Security > Virus & threat protection > Manage settings > Tamper Protection: On"))
    for k, what in (("BehaviorMonitorEnabled", "behaviour monitoring"), ("IoavProtectionEnabled",
                                                                        "scanning of downloads and attachments")):
        if s.get(k) is not None and not _on(s.get(k)):
            out.append(("warn", f"{what} is off", "turn real-time protection fully on (it carries this)"))
    age = s.get("AntivirusSignatureAge")
    if isinstance(age, int) and age > 3:
        out.append(("warn" if age <= 14 else "high", f"virus definitions are {age} days old",
                    "Windows Security > Virus & threat protection > Protection updates > Check for updates"))
    qa = s.get("QuickScanAge")
    if isinstance(qa, int) and qa > 14:
        out.append(("info", f"no quick scan for {qa} days", "a scheduled quick scan normally runs weekly"))
    if str(p.get("PUAProtection")) in ("0", "False", "false"):
        out.append(("info", "potentially unwanted app blocking is off",
                    "Windows Security > App & browser control > Reputation-based protection > PUA blocking: On"))
    if str(p.get("MAPSReporting")) in ("0", "False", "false"):
        out.append(("info", "cloud-delivered protection is off", "Virus & threat protection settings: "
                    "Cloud-delivered protection: On (faster detection of new threats)"))
    ex = [x for x in (p.get("ExclusionPath") or []) if x and "N/A" not in str(x)] if isinstance(
        p.get("ExclusionPath"), list) else []
    if ex:
        out.append(("warn", f"{len(ex)} folder(s) excluded from scanning: {', '.join(map(str, ex[:4]))}",
                    "malware hides in exclusions: remove any you did not add yourself (Virus & threat protection "
                    "settings > Exclusions)"))
    for f in d.get("firewall") or []:
        if not _on(f.get("Enabled")):
            out.append(("high", f"the Windows firewall is OFF for the {f.get('Name')} profile",
                        "Windows Security > Firewall & network protection > that profile: On"))
    return out


def render(d, fs):
    s = d.get("status") or {}
    lines = ["WINDOWS SECURITY (read from Windows; nothing was changed):"]
    if s:
        lines.append(f"  antivirus: {'on' if _on(s.get('AntivirusEnabled')) else 'OFF'} ({s.get('AMRunningMode') or '?'}) "
                     f"· real-time {'on' if _on(s.get('RealTimeProtectionEnabled')) else 'OFF'} · tamper protection "
                     f"{'on' if _on(s.get('IsTamperProtected')) else 'off'} · definitions "
                     f"{s.get('AntivirusSignatureAge', '?')} day(s) old · last quick scan "
                     f"{s.get('QuickScanAge', '?')} day(s) ago")
    fw = d.get("firewall") or []
    if fw:
        lines.append("  firewall: " + ", ".join(f"{f.get('Name')} {'on' if _on(f.get('Enabled')) else 'OFF'}"
                                                 for f in fw))
    if fs:
        lines.append(f"  {len(fs)} finding(s):")
        for sev, what, fix in sorted(fs, key=lambda x: {"high": 0, "warn": 1, "info": 2}[x[0]]):
            lines.append(f"  [{sev.upper()}] {what}\n      fix: {fix}")
    else:
        lines.append("  no findings: Defender and the firewall are set the safe way")
    lines.append("  (these are Windows settings: the user changes them in Windows Security themselves; gnoc reads only)")
    return "\n".join(lines)


def check():
    d = read()
    return d, findings(d)
