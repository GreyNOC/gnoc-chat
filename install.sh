#!/usr/bin/env bash
# gnoc chat installer for Linux, macOS and Termux on Android (Windows: use install-windows.cmd, which runs this
# inside WSL). Safe to run more than once. It installs nothing system-wide and never touches your keys or model
# config. GNOC_INSTALL_DRY_RUN=1 prints every change it would make and makes none.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PYTHON:-python3}"
DRY="${GNOC_INSTALL_DRY_RUN:-0}"

# Termux: the same test as scripts/gnoc_platform.is_termux(). The Termux app sets TERMUX_VERSION in every shell
# it opens; $PREFIX ending in /com.termux/files/usr covers a shell that kept PREFIX and lost TERMUX_VERSION.
# There is no sudo and no root there, so every hint is `pkg`, and nothing goes to /usr/local or /opt.
is_termux() {
  [ -n "${TERMUX_VERSION:-}" ] && return 0
  case "${PREFIX:-}" in */com.termux/files/usr|*/com.termux/files/usr/) return 0 ;; esac
  return 1
}
TERMUX=0
if is_termux; then
  TERMUX=1
  # $PREFIX/bin is on every Termux shell's PATH, so the command works at once with no shell-file edit
  BIN_DST="${GNOC_BIN:-${PREFIX%/}/bin}"
else
  BIN_DST="${GNOC_BIN:-$HOME/.local/bin}"
fi

say()  { printf '%s\n' "$*"; }
step() { printf '\n>> %s\n' "$*"; }
# act CMD...: run it, or in a dry run print it. Everything that changes the disk goes through here (or through
# append_line), so the dry run is a complete list of what a real run does.
act() {
  if [ "$DRY" = 1 ]; then
    say "  [dry run] $*"
  else
    "$@"
  fi
}
act_quiet() {   # act, with the command's own output dropped (a dry run still prints the action)
  if [ "$DRY" = 1 ]; then
    say "  [dry run] $*"
  else
    "$@" >/dev/null
  fi
}
append_line() {   # append_line FILE TEXT: the shell-file edit, as one printable action
  if [ "$DRY" = 1 ]; then
    say "  [dry run] append to $1: $2"
  else
    printf '\n# added by the gnoc chat installer\n%s\n' "$2" >> "$1"
  fi
}

say "gnoc chat installer  (version $(cat "$HERE/VERSION" 2>/dev/null || echo dev))"
say "  program files:  $HERE"
say "  command:        $BIN_DST/gnoc"
say "  your workspace: ${GNOC_WORKSPACE:-$HOME/.gnoc}"
[ "$TERMUX" = 1 ] && say "  platform:       Termux on Android (packages come from pkg; nothing needs root)"
[ "$DRY" = 1 ] && say "  dry run:        nothing will be changed"

step "Checking Python (3.10 or newer is required)"
if ! command -v "$PY" >/dev/null 2>&1; then
  say "Python 3 was not found."
  if [ "$TERMUX" = 1 ]; then
    say "Install it inside Termux with:  pkg install python git   then run this again."
  else
    case "$(uname -s)" in
      Darwin) say "Install it from python.org (Downloads > macOS) or with Homebrew (brew install python), then run this again." ;;
      *)      say "Install it with your package manager, for example:  sudo apt install python3 python3-venv   then run this again." ;;
    esac
  fi
  exit 1
fi
GNOC_TERMUX="$TERMUX" "$PY" - <<'PY'
import os, sys
if sys.version_info < (3, 10):
    fix = ("Update it inside Termux with:  pkg upgrade python" if os.environ.get("GNOC_TERMUX") == "1"
           else "Install a newer Python")
    sys.exit("gnoc chat needs Python 3.10 or newer, and this one is %d.%d. %s and run this again."
             % (sys.version_info[0], sys.version_info[1], fix))
print("  found Python", sys.version.split()[0])
PY

step "Setting up gnoc's private Python environment (about a minute the first time)"
act chmod +x "$HERE/gnoc-launcher" "$HERE/scripts/gnoc"
if [ "$TERMUX" = 1 ]; then
  if ! act_quiet env PYTHON="$PY" "$HERE/gnoc-launcher" help; then
    say "  The Python environment did not build. Inside Termux, packages without a ready-made Android build"
    say "  compile on the phone: pkg install python git clang   then run this again."
    exit 1
  fi
else
  act_quiet env PYTHON="$PY" "$HERE/gnoc-launcher" help
fi
say "  done"

step "Adding the gnoc command"
act mkdir -p "$BIN_DST"
act ln -sf "$HERE/gnoc-launcher" "$BIN_DST/gnoc"
say "  $BIN_DST/gnoc -> $HERE/gnoc-launcher"

case ":$PATH:" in
  *":$BIN_DST:"*) on_path=1 ;;
  *) on_path=0 ;;
esac
if [ "$on_path" = 0 ]; then
  # .zshrc, not .zprofile: zsh reads .zprofile only in LOGIN shells, and a Linux terminal starts a
  # non-login one, so gnoc was "not found" there; .zshrc is read by every interactive zsh, macOS included
  case "${SHELL:-}" in
    */zsh)  rc="$HOME/.zshrc" ;;
    */bash) if [ "$(uname -s)" = Darwin ]; then rc="$HOME/.bash_profile"; else rc="$HOME/.bashrc"; fi ;;
    *)      rc="$HOME/.profile" ;;
  esac
  case "$BIN_DST" in
    *[\'\"\$\`\\]*) say "  $BIN_DST has a quote, \$, backtick or backslash in it: add it to your PATH yourself"
                   rc="" ;;
  esac
  line="export PATH=\"$BIN_DST:\$PATH\""
  if [ -n "$rc" ] && ! grep -qsF "$line" "$rc"; then
    append_line "$rc" "$line"
    say "  added $BIN_DST to your PATH in $rc"
  fi
  if [ "${SHELL:-}" != "${SHELL%fish}" ] || [ -d "$HOME/.config/fish" ]; then
    # fish never reads ~/.profile: give it its own line
    act mkdir -p "$HOME/.config/fish/conf.d"
    if [ "$DRY" = 1 ]; then
      say "  [dry run] write $HOME/.config/fish/conf.d/gnoc-chat.fish: fish_add_path -g '$BIN_DST'"
    else
      printf 'fish_add_path -g %s\n' "'$BIN_DST'" > "$HOME/.config/fish/conf.d/gnoc-chat.fish"
    fi
    say "  added $BIN_DST to fish's PATH (~/.config/fish/conf.d/gnoc-chat.fish)"
  fi
  say "  open a new terminal window (or run:  $line ) so the gnoc command is found"
fi

if [ "$TERMUX" = 1 ]; then
  cat <<'NEXT'

Installed. Two steps left:

  1. Give gnoc a model to think with. A phone has no GPU for big models, so pick ONE:

     The model server on your desktop (private, uses its GPU). On the desktop:
         gnoc-engine share on        it prints a line like  gnoc pair 192.168.1.20:11434 <key>
     and here, in Termux, run that line, or  gnoc setup  and choose the desktop.

     Or a cloud model you have a key for, for example DeepSeek:
         gnoc chat            then type:   /deepseek api sk-YOUR-KEY
                              and then:    /deepseek on

     Or a small model on this phone (slow, and the phone gets warm under long use):
         gnoc setup           and choose "a small model on this phone"

  2. Start it:
         gnoc chat

  Features that need root or systemd (the defender's firewall actions, packet capture, the systemd
  vulnerability timer) say so and stay off on Termux. Scheduled defender sweeps use crond:
         pkg install cronie termux-services     then restart Termux and run:  sv-enable crond

  gnoc help    lists every command.   README.md has the details and the safety model.
NEXT
  exit 0
fi

cat <<'NEXT'

Installed. Two steps left:

  1. Give gnoc a model to think with. Pick ONE:

     On your own computer (free, private). Just run  gnoc  and say yes to the setup, or by hand:
         gnoc engine install && gnoc engine start
         gnoc engine pull qwen3:8b
         gnoc models use lead qwen3:8b

     Or a cloud model you have a key for, for example DeepSeek:
         gnoc chat            then type:   /deepseek api sk-YOUR-KEY
                              and then:    /deepseek on
     (any OpenAI-compatible service works: type /cloud inside the chat for the list)

  2. Start it:
         gnoc chat

  gnoc help    lists every command.   README.md has the details and the safety model.
NEXT
