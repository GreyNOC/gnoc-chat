"""The real gnoc agent behind the gateway: one Agent per (adapter, chat, sender), with its approvals sent to chat.

Everything that makes a gateway turn safe is set here on every turn, not once, because a turn could change it:
auto mode off, skip-perms refused, the remote approver bound to the message's own chat, draft_outgoing removed,
the owner's own words recorded as the typed text (which only ever narrows what the turn may do), and the turn
marked tainted when it carries someone else's text.
"""
import contextlib
import io
import os
import threading

# The one tool whose arguments name a recipient. Drafting never sends (only a typed /send does, and /send is
# refused over the gateway), but a gateway session has no business composing mail to anyone from a phone
# message: removing it keeps "the model never chooses a message recipient" true without an argument.
GATEWAY_DENIED_TOOLS = frozenset({"draft_outgoing"})


class _Capture(io.TextIOBase):
    """stdout while a turn runs, handed to the stream callback as it grows. Only the tail is kept: progress shows
    the last lines, the answer itself comes from turn(), and a long tool output must not make every write copy it."""

    KEEP = 8000

    def __init__(self, on_progress):
        super().__init__()
        self.text = ""
        self.on_progress = on_progress
        self._lock = threading.Lock()

    def writable(self):
        return True

    def write(self, s):
        with self._lock:
            self.text = (self.text + str(s))[-self.KEEP:]
            text = self.text
        if self.on_progress is not None:
            try:
                self.on_progress(text)
            except Exception:  # noqa: BLE001 - a broken progress callback must not break the turn
                pass
        return len(s)

    def flush(self):
        return None


def configure(G, state_dir):
    """Point the agent's state at the gateway's own directory, once per process.

    A separate directory, as the Discord bot does: the user's standing /goal and the open `gnoc chat`'s settings
    file are not the gateway's to steer or overwrite. The facade's globals are process-wide, which is one of the
    reasons the core runs one turn at a time.
    """
    import gnoc_goal
    agent_dir = os.path.join(state_dir, "agent")
    for sub in ("", "out", "jobs", "sessions"):
        os.makedirs(os.path.join(agent_dir, sub), exist_ok=True)
    for k, v in {"AGENT_DIR": agent_dir, "OUT_DIR": os.path.join(agent_dir, "out"),
                 "JOBS_DIR": os.path.join(agent_dir, "jobs"),
                 "SESSIONS_DIR": os.path.join(agent_dir, "sessions")}.items():
        setattr(G, k, v)
    gnoc_goal.PATH = os.path.join(agent_dir, "goal.json")
    G.SKIP_PERMS[0] = False   # a messenger never runs with skip-perms, whatever the environment said


class AgentRunner:
    def __init__(self, G, denied=GATEWAY_DENIED_TOOLS, state_dir=None):
        self.G = G
        self.denied = frozenset(denied)
        self.agent = None
        # set when another agent shares this process (the Discord bot's read-only !ask repoints the same facade
        # globals): the directories are re-applied at the start of every turn, under the shared turn lock
        self.state_dir = state_dir

    def _build(self):
        a = self.G.Agent(interactive=False)    # no stdin reader, no local prompt: approvals go to the chat
        a.ctx.remote_denied = self.denied
        return a

    def turn(self, text, typed="", untrusted=(), approver=None, on_progress=None):
        if self.G.SKIP_PERMS[0]:
            # configure() set it off; something turned it back on. Refuse rather than run unasked actions.
            return "refused: skip-perms is on in this process, and a messenger never runs without approvals."
        if self.state_dir:
            configure(self.G, self.state_dir)
        if self.agent is None:
            self.agent = self._build()
        a = self.agent
        a.s["auto"] = False                     # never on from a messenger, not even if a turn switched it on
        a.ctx.remote_denied = self.denied
        a.ctx.remote_approver = approver
        a.s["_typed"] = typed                   # his own words: the "only run" / "only asked" holds read this
        if untrusted:
            self.G.taint(a.ctx, "gateway-forwarded")   # acting tools ask first for the rest of this turn
            for t in untrusted:
                self.G.remember_untrusted(a.ctx, t)    # and an argument copied out of it asks every time
        cap = _Capture(on_progress)
        try:
            with contextlib.redirect_stdout(cap), contextlib.redirect_stderr(cap):
                answer = a.turn(text)
            if not (answer or "").strip():
                answer = next((m.get("content") or "" for m in reversed(a.s.get("history") or [])
                               if m.get("role") == "assistant" and (m.get("content") or "").strip()), "")
            return (answer or "").strip() or "gnoc returned no answer"
        finally:
            a.ctx.remote_approver = None
            a.s["auto"] = False


def factory(G, state_dir, denied=GATEWAY_DENIED_TOOLS):
    configure(G, state_dir)
    return lambda key: AgentRunner(G, denied)
