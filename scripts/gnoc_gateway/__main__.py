"""python3 -m gnoc_gateway run | check | install | status (what the systemd unit and the Termux script run)."""
import sys

from .cli import main

sys.exit(main(sys.argv[1:]))
