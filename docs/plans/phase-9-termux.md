# Phase 9: native Termux

## Plan

- One detector, `scripts/gnoc_platform.py` (stdlib only, env and filesystem injectable): `is_termux()`,
  `termux_prefix()`, `on_android()`, `kind()`, `pkg_hint()`, `unavailable()`. `gnoc_engine.on_android()` delegates
  to it with an inline fallback (the engine is copied alone onto a phone), behaviour identical.
- `install.sh`: detect Termux (`TERMUX_VERSION`, or `$PREFIX` ending in `/com.termux/files/usr`), hint
  `pkg install python git` (never sudo or apt), install the command into `$PREFIX/bin` (already on PATH), and a
  `GNOC_INSTALL_DRY_RUN=1` mode that prints every change instead of making it. The Linux/macOS branch is unchanged.
- `gnoc doctor` and `gnoc setup` know Termux: pkg hints, no sudo, a platform row, crond and storage rows, and a
  three-way model choice (paired desktop, cloud, small on-phone model sized by the phone tiers).
- Root/systemd features say so in one line on Termux: the defender's root helper, the vulnwatch systemd timer. The
  defender sweep becomes a reduced read-only set (user-visible listening sockets, Termux sshd config, `~/storage`,
  pending package upgrades) that names what Android hides; `/defender schedule` stays user-only and uses crond.
- Tests in `scripts/test_gnoc_phase9_termux.py`: detector unit tests, install dry runs in a faked Termux and a plain
  Linux environment, a real (sandboxed) Linux install run to pin the old behaviour, and negative cases.

## What was built

- `scripts/gnoc_platform.py`: `is_termux`, `termux_prefix`, `on_android` (the engine's old test, unchanged),
  `kind`, `pkg_hint`, `unavailable`, `crond_state`, `CROND_HELP`. `gnoc_engine.on_android()` delegates, with an
  inline fallback for the engine copy that runs alone on a phone.
- `install.sh`: Termux detection, `pkg` hints, the command in `$PREFIX/bin`, a Termux closing text with the three
  model choices and the crond line, and `GNOC_INSTALL_DRY_RUN=1` on every platform. The Linux/macOS branch was
  checked against the old script in a sandbox (bash and zsh+fish: identical output and identical files) and is
  pinned by a test. `gnoc-launcher`'s venv hint says `pkg install python` inside Termux.
- `gnoc doctor`: platform, root/systemd, crond and shared-storage rows; `pkg` fixes, no `sudo`; the three model
  choices when the lead does not work.
- `gnoc setup`: `machine()` reports `termux` with no usable GPU; `recommend()` uses the phone tiers; the menu on
  Termux offers the paired desktop, a cloud provider and a small on-phone model (default: desktop if paired, else
  cloud), and the first-run skips the automatic local install.
- Defender: `scripts/gnoc_termux.py` reduced read-only sweep; the root helper, `/defender install`, the vulnwatch
  systemd timer and the engine's `@reboot` autostart each say in one line why they are unavailable; `/defender
  schedule` notes when crond is not enabled.
- `scripts/test_gnoc_phase9_termux.py`: 46 tests.

## Security impact

No gate was loosened. `/defender schedule` is still the only path that writes a crontab line and is still
typed-only; on Termux the vulnwatch timer deliberately does NOT fall back to a crontab line, because a model can
reach it through `defend(action=vulnwatch)`. Inside Termux the root helper refuses before `sudo` is ever run, so
no action can be attempted that the platform cannot do. The reduced sweep only reads (`/proc/net`, the sshd
config, `~/storage`, `apt list --upgradable` against cached lists) and its findings carry no actions. A named
remote target still gets the full sweep. Detection is environment-driven: setting `TERMUX_VERSION` on a desktop
makes gnoc behave as on Termux, which only REMOVES capabilities (root actions, the systemd timer) and changes
hints; it grants nothing.

## Rollback

Revert the phase-9 commits. `gnoc_platform.py` and `gnoc_termux.py` are new; every edit to an existing file is a
Termux branch in front of unchanged desktop code, plus the installer's dry-run wrapper.

## What is left

- Not run on a real phone. `curl_cffi` has no Android wheel, so the private environment may not build inside
  Termux; whether it compiles there (and which pkg packages it needs) is unverified.
- Whether termux-services' crond environment runs the scheduled `gnoc chat "/defender sweep"` line end to end is
  unverified.
- The Phase-6 scheduler should import `gnoc_platform.is_termux()` / `crond_state()` rather than re-detect.

## Release note

gnoc chat now installs and runs inside Termux on Android. `install.sh` detects Termux, uses `pkg` (never sudo or
apt) and puts the `gnoc` command in `$PREFIX/bin`; `GNOC_INSTALL_DRY_RUN=1 ./install.sh` lists what the installer
would change on any platform without changing anything. `gnoc doctor` and `gnoc setup` know Termux: the setup
offers your paired desktop, a cloud model, or a small model sized to the phone. Features that need root or
systemd say so in one line, the defender's sweep of a phone is a reduced read-only set that names what Android
hides, and `/defender schedule` uses crond. Development: GreyNOC (Brad), with Claude (Anthropic) as a development
contributor.
