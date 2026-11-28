"""Email, Discord, outgoing drafts and untrusted-text tracking."""
from gnoc_core.runtime import bind


def taint(ctx, source):
    """This turn read text written by someone else (an email, a Discord message, a web page). Until the turn ends,
    every tool that acts asks the user first - skip-perms and /auto included - so injected instructions in that text
    cannot drive the shell, files, requests or the desktop."""
    ctx.s.setdefault("_tainted", [])
    if source not in ctx.s["_tainted"]:
        ctx.s["_tainted"].append(source)


def remember_untrusted(ctx, text):
    if ctx is None or not hasattr(ctx, "s"):
        return
    keep = ctx.s.setdefault("_untrusted_text", [])
    keep.append(str(text or "")[:20000])
    del keep[:-6]


def _is_program_note(ctx, path):
    """True for a data file (notes, evidence, a ledger) under the ACTIVE program's own targets/<p>/ tree. Code
    files and anything outside that tree are not notes, whatever they are called."""
    (
        WS, _NOTE_EXT, _inside_ws, os, valid_handle,
    ) = bind(
        "WS", "_NOTE_EXT", "_inside_ws", "os", "valid_handle",
    )
    prog = getattr(ctx, "program", None)
    if not prog or not path or not valid_handle(prog):
        return False
    p = _inside_ws(path)
    if not p:
        return False
    root_p = os.path.realpath(os.path.join(WS, "targets", prog)) + os.sep
    return os.path.realpath(p).startswith(root_p) and os.path.splitext(p)[1].lower() in _NOTE_EXT


def copies_untrusted(ctx, name, args):
    """The first run of _COPY_RUN characters an acting argument shares verbatim with a response read this turn."""
    (
        _COPY_GATED, _COPY_RUN, _is_program_note, json,
    ) = bind(
        "_COPY_GATED", "_COPY_RUN", "_is_program_note", "json",
    )
    texts = (getattr(ctx, "s", None) or {}).get("_untrusted_text") or []
    if not texts or name not in _COPY_GATED:
        return None
    if name in ("write_file", "edit_file") and _is_program_note(ctx, args.get("path")):
        # A NOTES or evidence file under the active program's own targets/ tree is a research RECORD, not an action:
        # quoting a response string into it (a JS global, an error message, a cookie name) is exactly what a hunt
        # log is for, and nothing executes that file. The guard stays on every tool that ACTS on the text (bash,
        # workers, fan-out, patches) and on writes anywhere else. Receipt 2026-10-23 program-101: the lead spent a whole
        # turn refused on write_file / edit_file / bash / fan_out for quoting `window.__NPM_PACKAGE_CONFIG__`
        # into its trust-model notes, and never reached a hypothesis.
        return None
    for field in _COPY_GATED[name]:
        v = args.get(field)
        s = v if isinstance(v, str) else json.dumps(v, default=str) if v else ""
        s = " ".join(s.split())
        for i in range(0, max(0, len(s) - _COPY_RUN) + 1, 6):
            run = s[i:i + _COPY_RUN]
            if len(run.strip()) >= _COPY_RUN - 2 and any(run in " ".join(t.split()) for t in texts):
                return run
    return None


def t_draft_outgoing(ctx, channel, text, to=None, subject=None, reply_to=None, image=None, note=""):
    (
        _inside_ws, gnoc_comms, gnoc_secrets, os,
    ) = bind(
        "_inside_ws", "gnoc_comms", "gnoc_secrets", "os",
    )
    if gnoc_secrets.find(" ".join(str(x) for x in (text, to, subject) if x)):
        return "refused: the draft carries one of the user's credentials"
    if image:
        if bind("gnoc_secrets")[0].is_secret_path(os.path.expanduser(str(image))):
            return "refused: that is a secrets file, never an attachment"
        p = _inside_ws(image) or (os.path.realpath(image) if os.path.isfile(image) else None)
        if not p:
            return f"no image at {image}"
        image = p
    d, problems = gnoc_comms.draft(channel, text, to, subject, reply_to, image, note)
    if problems:
        return "not drafted: " + "; ".join(problems)
    ok, missing = gnoc_comms.configured(channel)
    setup = "" if ok else f"\n(note: {channel} is not set up yet: the user must add {', '.join(missing)} to secrets.env)"
    return (gnoc_comms.show(d) + f"\nDRAFT {d['id']} saved. It is NOT sent: the user reads it and types /send "
            f"{d['id']} themselves. Never say it was sent." + setup)


def t_email_inbox(ctx, action="list", uid=None, query="UNSEEN", n=15):
    (
        EMAIL_DEADLINE_S, _deadline, _net_fail, gnoc_comms, taint,
    ) = bind(
        "EMAIL_DEADLINE_S", "_deadline", "_net_fail", "gnoc_comms", "taint",
    )
    ok, missing = gnoc_comms.configured("email")
    if not ok:
        return f"email is not set up: the user adds {', '.join(missing)} to ~/.config/gnoc/secrets.env"
    if action == "read" and not str(uid or "").strip():
        return "bad arguments: email_inbox action=read needs uid=<the uid number from action=list>"
    taint(ctx, "email")
    try:  # IMAP has no socket timeout of its own: EMAIL_DEADLINE_S caps the whole login + search + fetch
        if action == "list":
            rows = _deadline(lambda: gnoc_comms.email_list(query or "UNSEEN", max(1, min(int(n or 15), 50))),
                             EMAIL_DEADLINE_S, "IMAP list")
            if not rows:
                return f"no messages for {query or 'UNSEEN'} (query=ALL lists read mail too)"
            return gnoc_comms.untrusted("email list", "\n".join(
                f"uid {u}  {d[:25]}  from {f[:60]}  | {sj[:90]}" for u, f, sj, d in rows))
        if action == "read":
            m = _deadline(lambda: gnoc_comms.email_fetch(str(uid).strip()), EMAIL_DEADLINE_S, "IMAP fetch")
            return gnoc_comms.untrusted(f"email uid {uid}", f"From: {m['from']}\nDate: {m['date']}\nSubject: "
                                        f"{m['subject']}\n\n{m['body'][:8000]}")
    except Exception as e:
        return _net_fail(f"email {action}", e)
    return "action is list or read"


def t_discord_read(ctx, action="messages", channel_id=None, n=20):
    (
        _net_fail, gnoc_comms, taint,
    ) = bind(
        "_net_fail", "gnoc_comms", "taint",
    )
    ok, missing = gnoc_comms.configured("discord")
    if not ok:
        return f"discord is not set up: the user adds {', '.join(missing)} to ~/.config/gnoc/secrets.env"
    taint(ctx, "discord")
    try:
        if action == "channels":
            return "\n".join(f"{cid}  {g} #{name}" for cid, g, name in gnoc_comms.discord_channels()) or "no channels"
        if action != "messages":
            return f"action is channels or messages (got {action!r})"
        if not str(channel_id or "").strip():
            return "bad arguments: discord_read action=messages needs channel_id=<id>; action=channels lists the ids"
        rows = gnoc_comms.discord_messages(str(channel_id).strip(), max(1, min(int(n or 20), 100)))
        if not rows:
            return f"no messages in channel {channel_id}"
        return gnoc_comms.untrusted(f"discord channel {channel_id}", "\n".join(
            f"[{mid}] {ts} {who}: {text[:600]}" for mid, who, ts, text in rows))
    except Exception as e:  # each Discord API call is capped at 40s inside gnoc_comms
        return _net_fail(f"discord {action}", e)
