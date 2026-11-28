#!/data/data/com.termux/files/usr/bin/bash
# termux-setup.sh - run ONCE inside Termux on the phone. Makes the phone a GNOC server-room machine:
#   * Ollama on 127.0.0.1:11434          (the laptop reaches it at 127.0.0.1:11441 through `adb forward`)
#   * ggml-rpc-server on 127.0.0.1:50052 (the laptop reaches it at 127.0.0.1:50053: a third device for gnoc split)
#   * sshd on 127.0.0.1:8022             (the laptop reaches it at 127.0.0.1:8022: how phone-link revives the loop)
# All three bind to the phone's localhost only: nothing is exposed on WiFi; the USB cable is the only way in.
#
# The RPC protocol is VERSION-LOCKED: the phone must run the same llama.cpp build as the laptop and desktop
# (b11476). Building it here takes 10-20 minutes on a phone. Re-running this script is safe (it skips done steps).
#
# How to run (the laptop pushes this file for you: `gnoc phone setup`):
#   termux-setup-storage            # once, so Termux can read the Download folder
#   bash ~/storage/downloads/greynoc-termux-setup.sh
set -euo pipefail
BUILD="${GNOC_LLAMA_BUILD:-b11476}"
SRC="$HOME/llama.cpp-$BUILD"
BIN="$HOME/.local/bin"
DL="$HOME/storage/downloads"
mkdir -p "$BIN" "$HOME/.termux/boot" "$HOME/.ssh"

echo "== packages"
pkg update -y
pkg install -y git cmake clang make ollama termux-tools openssh

echo "== llama.cpp $BUILD rpc server (CPU backend)"
if [ ! -x "$BIN/ggml-rpc-server" ]; then
  [ -d "$SRC" ] || git clone --depth 1 --branch "$BUILD" https://github.com/ggml-org/llama.cpp "$SRC"
  cmake -S "$SRC" -B "$SRC/build" -DGGML_RPC=ON -DGGML_NATIVE=ON -DBUILD_SHARED_LIBS=OFF \
        -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_CURL=OFF
  cmake --build "$SRC/build" --target ggml-rpc-server -j "$(nproc)"
  cp "$SRC/build/bin/ggml-rpc-server" "$BIN/"
fi
"$BIN/ggml-rpc-server" --help >/dev/null 2>&1 && echo "   ok: $BIN/ggml-rpc-server ($BUILD)"

echo "== sshd on the phone's localhost (the laptop's way back in: see the reviver below)"
# Termux's sshd is key-only in practice; the laptop's public key arrives next to this script
# (`gnoc phone setup` pushes ~/.ssh/gnoc-phone.pub as gnoc-phone-link.pub). Any username works.
SSHD_CONF="$PREFIX/etc/ssh/sshd_config"
if ! grep -q '^ListenAddress 127.0.0.1' "$SSHD_CONF" 2>/dev/null; then
  printf '\n# GreyNOC: USB only. Nothing on WiFi.\nListenAddress 127.0.0.1\nPort 8022\n' >> "$SSHD_CONF"
fi
if [ -r "$DL/gnoc-phone-link.pub" ]; then
  KEY="$(cat "$DL/gnoc-phone-link.pub")"
  touch "$HOME/.ssh/authorized_keys"
  grep -qxF "$KEY" "$HOME/.ssh/authorized_keys" || echo "$KEY" >> "$HOME/.ssh/authorized_keys"
  chmod 600 "$HOME/.ssh/authorized_keys"
  echo "   laptop key authorised"
else
  echo "   NOTE: no $DL/gnoc-phone-link.pub - run \`gnoc phone setup\` on the laptop and re-run this script,"
  echo "         or the laptop can only revive the loop the blunt way (am start on the Termux activity)."
fi

echo "== the serve loop (keeps all three up, holds a wake lock so Android does not sleep them)"
cat > "$HOME/greynoc-phone-serve.sh" <<'SERVE'
#!/data/data/com.termux/files/usr/bin/bash
# keeps Ollama, the RPC server and sshd alive. Start it through greynoc-phone-up.sh, never directly.
LOG="$HOME/greynoc-phone.log"
PIDFILE="$HOME/.greynoc-phone-serve.pid"
# Single instance. A pidfile, not `pgrep -f greynoc-phone-serve.sh`: that pattern also matches the shell
# that is running this very script, and any command line mentioning it, so it can never say "not running".
if [ -r "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then exit 0; fi
echo $$ > "$PIDFILE"
trap 'rm -f "$PIDFILE"' EXIT
termux-wake-lock 2>/dev/null || true
echo "$(date -u +%FT%TZ) serve loop start (pid $$)" >> "$LOG"
while true; do
  if ! pgrep -f "ollama serve" >/dev/null; then
    OLLAMA_HOST=127.0.0.1:11434 nohup ollama serve >> "$LOG" 2>&1 &
    echo "$(date -u +%FT%TZ) started ollama" >> "$LOG"
  fi
  if ! pgrep -x ggml-rpc-server >/dev/null; then
    # -c caches received tensors on the phone, so the next `gnoc split up` does not resend them over USB
    nohup "$HOME/.local/bin/ggml-rpc-server" -H 127.0.0.1 -p 50052 -c -t "$(nproc)" >> "$LOG" 2>&1 &
    echo "$(date -u +%FT%TZ) started ggml-rpc-server" >> "$LOG"
  fi
  if ! pgrep -x sshd >/dev/null; then
    sshd >> "$LOG" 2>&1 && echo "$(date -u +%FT%TZ) started sshd" >> "$LOG"
  fi
  sleep 15
done
SERVE
chmod +x "$HOME/greynoc-phone-serve.sh"

# The idempotent way in. Everything above lives inside the Termux app's process group, so when Android
# kills Termux under memory or thermal pressure all of it dies at once. This launcher is what the laptop,
# the boot hook and the login shell all call to put it back; running it twice is a no-op.
cat > "$HOME/greynoc-phone-up.sh" <<'UP'
#!/data/data/com.termux/files/usr/bin/bash
PIDFILE="$HOME/.greynoc-phone-serve.pid"
if [ -r "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
  echo "serve loop already running (pid $(cat "$PIDFILE"))"
else
  nohup bash "$HOME/greynoc-phone-serve.sh" >/dev/null 2>&1 &
  echo "serve loop started"
fi
UP
chmod +x "$HOME/greynoc-phone-up.sh"

# Termux:Boot (optional app) starts the loop after a reboot
cat > "$HOME/.termux/boot/greynoc-phone" <<'BOOT'
#!/data/data/com.termux/files/usr/bin/bash
bash "$HOME/greynoc-phone-up.sh" >/dev/null 2>&1
BOOT
chmod +x "$HOME/.termux/boot/greynoc-phone"

# ...and the one hook that needs no add-on app: any Termux session, however it was opened, puts the loop
# back. This is what makes `am start` on the Termux activity a working repair from the laptop.
if ! grep -q 'greynoc-phone-up.sh' "$HOME/.bashrc" 2>/dev/null; then
  printf '\n# GreyNOC phone link: restart the serve loop if Android killed it (no-op when it is up)\nbash "$HOME/greynoc-phone-up.sh" >/dev/null 2>&1\n' >> "$HOME/.bashrc"
fi

bash "$HOME/greynoc-phone-up.sh"
echo "== done. The serve loop is running (log: ~/greynoc-phone.log)."
echo "   Optional: a small uncensored model for the phone's rack, e.g.  ollama pull <owner>/<model>:<small tag>"
echo "   Back on the laptop:  gnoc phone status"
