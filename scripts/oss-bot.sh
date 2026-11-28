#!/usr/bin/env bash
set -euo pipefail
cd ${GNOC_WORKSPACE:-$HOME/.gnoc}
export PATH="$HOME/go/bin:$HOME/.local/bin:/usr/bin:/bin"
exec nice -n 10 ionice -c3 /usr/bin/python3 -u scripts/oss-bot/bot.py daemon
