# gnoc inside Termux

How gnoc behaves on an Android phone inside Termux, and why. User-facing summary: the README section
"gnoc inside Termux (Android)".

## Detection

One detector, `scripts/gnoc_platform.py`, used by `gnoc doctor`, `gnoc setup`, the defender, the vulnerability
watch and gnoc's engine (the Phase-6 scheduler can import it too):

- `is_termux()`: `TERMUX_VERSION` is set (the Termux app sets it in every shell), or `$PREFIX` ends in
  `/com.termux/files/usr` (a shell that kept PREFIX and lost TERMUX_VERSION), or `/data/data/com.termux/files/usr`
  exists.
- `termux_prefix()`: the live `$PREFIX` when it is a Termux one, else the fixed install root.
- `on_android()`: exactly the engine's old test (`sys.getandroidapilevel`, `TERMUX_VERSION`, the install root),
  because it decides which llama.cpp build a phone downloads. `gnoc_engine.on_android()` delegates to it and
  keeps an inline copy, since `gnoc phone setup` copies `gnoc_engine.py` alone onto a phone.
- `pkg_hint()`, `unavailable()`, `crond_state()`, `CROND_HELP`: the shared wording.

`install.sh` is shell, so it repeats the first two tests in `is_termux()` (same rule, same order).

## Installer

- Paths: the command is linked into `$PREFIX/bin` (override with `GNOC_BIN`); the Python environment and the
  workspace stay under `$HOME` as on Linux. Nothing goes to `/usr/local` or `/opt`.
- Hints: `pkg install python git` when Python is missing, `pkg upgrade python` when it is too old, and
  `pkg install python git clang` when the private environment does not build (packages without an Android wheel
  compile on the phone).
- `GNOC_INSTALL_DRY_RUN=1` (every platform): each change (chmod, the environment build, mkdir, the link, the
  shell-file line, the fish file) is printed as `[dry run] ...` and not made. The tests run it in a faked Termux
  and a plain Linux, and a sandboxed real Linux run pins the pre-Termux behaviour.

## Doctor and setup

- `gnoc doctor` adds a platform row, says root/systemd features are off, reports crond (a warning only when a
  `/defender schedule` line exists and crond would never run it) and shared-storage access, and when the lead
  model does not work it names the three ways a phone gets one. Fixes say `pkg`, never `sudo`.
- `gnoc setup` on Termux skips the automatic local install and shows a menu: the paired desktop (default once
  `desktop` is saved), a cloud provider (default otherwise), or a small model on the phone. The on-phone model is
  sized by `gnoc_phone.TIERS` (4B at 10 GB or more, 1.7B at 6 GB, 0.6B below), never a desktop tier. All three
  run the existing paths: `_remote_path` (pairing), `_cloud_path` (gnoc_cloud), `_local_path` (gnoc's engine,
  `pick_variant()` returning `android-arm64`).

## Defender

| feature | on Termux |
|---|---|
| `/defender sweep` of this phone | reduced read-only set from `scripts/gnoc_termux.py` (below); a named remote host still gets the full sweep over ssh |
| root helper, `/defender install`, block/pause/sysctl actions | one line: needs root or systemd, not available on Termux; sudo is never run |
| `/defender vulnwatch on|off|status` (systemd user timer) | one line; no unit files written, no crontab line added |
| `/defender schedule` | crontab as on Linux, typed by the user only; notes when crond is not enabled |
| `gnoc-engine` boot autostart | explains Termux:Boot (`~/.termux/boot/`), adds no `@reboot` line |

The reduced sweep checks what an unprivileged app can see: listening sockets in `/proc/net/{tcp,tcp6,udp,udp6}`
(Android 10 and newer may refuse these; that is reported as "not checked", never as "nothing listens"), Termux's
own `$PREFIX/etc/ssh/sshd_config` (password login, high when sshd is listening on a reachable port),
`~/storage` (shared-storage access), and `apt list --upgradable` for waiting upgrades (pkg has no read-only form;
Termux's apt lives in `$PREFIX`, needs no root and reads only the cached lists). Its findings carry no actions.
Every note includes what Android hides: other apps' processes, system logs, the firewall, packet capture and
kernel settings.

The vulnerability watch's timer does not fall back to a crontab line on its own: a model can reach it through
`defend(action=vulnwatch)`, and only the user sets a schedule.

## Not verified here

These are tested with a faked Termux only; nothing was run on a phone. Known gaps: `curl_cffi` (in
`requirements.txt`) has no Android wheel, so the private environment may need to compile it, which can fail on a
phone; whether termux-services' crond inherits a PATH that finds `gnoc` is untested (the cron line uses the
absolute path of the command).
