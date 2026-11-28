"""gnoc gateway run | check | install [--force] | status

    run       start every configured adapter and answer the owners (foreground; the service runs this)
    check     show which adapters are configured and what is missing, without starting anything
    install   write a systemd user unit (or a Termux:Boot script on Android); never enables or starts it
    status    whether the service file exists and what systemd says about it

Settings live in ~/.config/gnoc/secrets.env (or the environment). An adapter is on when its token is set:
    TELEGRAM_BOT_TOKEN   + GNOC_TELEGRAM_OWNERS (numeric user ids)   [+ GNOC_TELEGRAM_CHATS group ids]
    SLACK_APP_TOKEN, SLACK_BOT_TOKEN + GNOC_SLACK_OWNERS (U... ids)  [+ GNOC_SLACK_CHANNELS]
    GNOC_SIGNAL_ACCOUNT  + GNOC_SIGNAL_OWNERS (UUIDs or +numbers)    [+ GNOC_SIGNAL_GROUPS, GNOC_SIGNAL_RPC]
    GNOC_EMAIL_USER, GNOC_EMAIL_PASS, GNOC_EMAIL_IMAP_HOST, GNOC_EMAIL_SMTP_HOST, GNOC_EMAIL_OWNERS,
                         GNOC_EMAIL_AUTHSERV (whose Authentication-Results header to trust)
    GNOC_GATEWAY_APPROVAL_TIMEOUT  seconds an approval waits before it counts as no (default 300)
    GNOC_GATEWAY_CWD               the directory gnoc works in (default: your home)
Discord runs through `gnoc discord` (the operator edition's bot), which uses this same core for its owners.
"""
import os
import signal
import sys
import threading

from . import config, service
from .core import Gateway, Redactor, _log_default


def _adapters():
    """(name, the key that switches it on, from_conf). In the brief's order."""
    from . import email_imap, signal_cli, slack, telegram
    return [("telegram", "TELEGRAM_BOT_TOKEN", telegram.from_conf),
            ("slack", "SLACK_APP_TOKEN", slack.from_conf),
            ("signal", "GNOC_SIGNAL_ACCOUNT", signal_cli.from_conf),
            ("email", "GNOC_EMAIL_USER", email_imap.from_conf)]


def build(conf, log=_log_default):
    """([(adapter, allowlist)], {name: [problems]}, [names that are off])."""
    on, problems, off = [], {}, []
    for name, key, from_conf in _adapters():
        if not conf(key):
            off.append(name)
            continue
        try:
            ad, allow, probs = from_conf(conf, log=log)
        except Exception as e:  # noqa: BLE001 - one broken adapter must not stop the others
            ad, allow, probs = None, None, [f"{type(e).__name__}: {e}"]
        if probs or ad is None:
            problems[name] = probs or ["not usable"]
        else:
            on.append((ad, allow))
    return on, problems, off


def check(conf=None, out=print):
    conf = conf or config.reader()
    on, problems, off = build(conf, log=lambda *a: None)
    for ad, allow in on:
        out(f"  {ad.name:9} ready: {len(allow.owners)} owner(s), {len(allow.chats)} group chat(s)")
    for name, probs in problems.items():
        for p in probs:
            out(f"  {name:9} PROBLEM: {p}")
    for name in off:
        out(f"  {name:9} off (its token is not set)")
    out(f"  service   {service.service_state()}")
    return 0 if on else 1


def run(conf=None):
    conf = conf or config.reader()
    on, problems, _off = build(conf)
    for name, probs in problems.items():
        for p in probs:
            _log_default(f"{name}: not started: {p}")
    if not on:
        print("gnoc gateway: no adapter is configured. `gnoc gateway check` shows what is missing.", file=sys.stderr)
        return 2
    os.chdir(os.path.expanduser(conf("GNOC_GATEWAY_CWD") or "~"))
    import gnoc_agent as G
    from . import runner
    factory = runner.factory(G, config.state_dir())
    try:
        timeout = float(conf("GNOC_GATEWAY_APPROVAL_TIMEOUT") or 300)
    except ValueError:
        timeout = 300.0
    gw = Gateway(factory, redact=Redactor(tokens=config.tokens(conf)), approval_timeout=timeout,
                 interrupt=G.INTERRUPT.set)
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    threads = []
    for ad, allow in on:
        gw.add(ad, allow)
        t = threading.Thread(target=ad.run, args=(gw, stop), name=f"gnoc-gateway-{ad.name}", daemon=True)
        t.start()
        threads.append(t)
        _log_default(f"{ad.name}: started ({len(allow.owners)} owner(s))")
    while not stop.wait(1.0):
        if not any(t.is_alive() for t in threads):
            _log_default("every adapter stopped")
            return 1
    _log_default("stopping")
    return 0


def main(argv):
    argv = list(argv)
    if any(a in ("-s-p", "--skip-perms", "--dangerously-skip-permissions") for a in argv):
        print("refused: the gateway never runs without approvals; there is no skip-perms here.", file=sys.stderr)
        return 2
    cmd = argv[0] if argv else "check"
    if cmd in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    if cmd == "run":
        return run()
    if cmd == "check":
        return check()
    if cmd == "install":
        ok, msg = service.install(force="--force" in argv)
        print(msg)
        return 0 if ok else 1
    if cmd == "status":
        print(service.service_state())
        return 0
    print(__doc__)
    return 2
