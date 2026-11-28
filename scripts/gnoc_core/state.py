"""Mutable process/runtime state for the gnoc chat facade.

This is the single source of truth for values that used to be module globals in
``gnoc_agent.py``.  The facade re-exports aliases so existing code and tests that
read or rebind ``gnoc_agent.WS`` (and friends) keep working; extracted modules read
``STATE`` directly.

State is deliberately process-local and mutable:
  * paths (ws/orch/agent_dir/... ) are recomputed by :meth:`reset`
  * mode flags are one-item lists, matching the historical ``FLAG[0]`` protocol
  * caches are dicts/lists mutated in place so every alias sees the same object
"""

import os
import threading

# scripts/gnoc_core/state.py -> scripts/gnoc_core -> scripts -> repository root
DEFAULT_WORKSPACE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class RuntimeState:
    """One mutable state object shared by gnoc_agent and the extracted modules."""

    def __init__(self):
        self._listeners = []
        # threading primitives: created once, never replaced, so aliases stay valid
        self.print_lock = threading.RLock()
        self.interrupt = threading.Event()
        self.cancel_local = threading.local()

        # caches/containers that are mutated in place
        self.ctx_live = {}
        self.route_seen = {}
        self.broken_model = {}
        self.broken_at = {}
        self.host_down = {}
        self.last_http = {}
        self.model_rows_missing = []
        self.sudo_ok = []
        self.ctx_pct = [0, 0.0, None]
        self.learn_notes = []
        self.think_ui = [True]
        self.offline = [os.environ.get("GNOC_OFFLINE") == "1"]
        self.effort = ["medium"]
        self.steps_override = [None]
        self.skip_perms = [False]
        self.plain = [False]
        self.chat_sid = [None]
        self.active_root = [""]
        self.title = [None]
        self.act_n = [0]
        self.act_lock = threading.Lock()

        self.ws = os.environ.get("GNOC_WORKSPACE") or DEFAULT_WORKSPACE
        self._derive()
        self.activity = os.path.join(self.agent_dir, "activity.jsonl")

    # ------------------------------------------------------------------ paths
    def _derive(self):
        self.orch = os.path.join(self.ws, ".claude/state/orch")
        self.agent_dir = os.path.join(self.orch, "agent")
        self.out_dir = os.path.join(self.agent_dir, "out")
        self.jobs_dir = os.path.join(self.agent_dir, "jobs")
        self.sessions_dir = os.path.join(self.agent_dir, "sessions")
        self.tasks = os.path.join(self.orch, "tasks.jsonl")
        self.split_flag = os.path.join(self.orch, "SPLIT.enabled")
        self.broken_log = os.path.join(self.ws, ".claude/state/orch/broken-marks.jsonl")
        self.hunt_state = os.path.join(self.ws, ".claude/state/hunt-loop")
        self.inbox = os.path.join(self.orch, "INBOX.md")
        self.orch_log = os.path.join(self.orch, "orch.log")

    def reset(self, ws=None):
        """Reset the process defaults (called once per gnoc_agent import/reload)."""
        if ws is not None:
            self.ws = ws
        self._derive()
        self.activity = os.path.join(self.agent_dir, "activity.jsonl")
        self.active_root[:] = [self.ws]
        self.offline[:] = [os.environ.get("GNOC_OFFLINE") == "1"]
        self.effort[:] = ["medium"]
        self.steps_override[:] = [None]
        self.skip_perms[:] = [False]
        self.plain[:] = [False]
        self.chat_sid[:] = [None]
        self.think_ui[:] = [True]
        self.title[:] = [None]
        self.ctx_pct[:] = [0, 0.0, None]
        self.act_n[:] = [0]
        self.ctx_live.clear()
        self.route_seen.clear()
        self.broken_model.clear()
        self.broken_at.clear()
        self.host_down.clear()
        self.last_http.clear()
        self.model_rows_missing.clear()
        self.sudo_ok.clear()
        self.learn_notes.clear()
        self.interrupt.clear()
        self._notify()

    def set_workspace(self, ws):
        """A caller rebound ``WS`` directly: change the workspace, not derived paths.

        The historical module only rebound the string; AGENT_DIR and the other
        derived paths kept their old values.  Preserve that exactly.
        """
        self.ws = ws
        self._notify()

    # ----------------------------------------------------------------- aliases
    def set_alias(self, name, value):
        """Apply a facade-level assignment to the corresponding state attribute."""
        mapping = {
            "WS": "ws",
            "ORCH": "orch",
            "AGENT_DIR": "agent_dir",
            "OUT_DIR": "out_dir",
            "JOBS_DIR": "jobs_dir",
            "SESSIONS_DIR": "sessions_dir",
            "TASKS": "tasks",
            "SPLIT_FLAG": "split_flag",
            "BROKEN_LOG": "broken_log",
            "_HUNT_STATE": "hunt_state",
            "INBOX": "inbox",
            "ORCH_LOG": "orch_log",
            "ACTIVITY": "activity",
            "_ACTIVE_ROOT": "active_root",
            "OFFLINE": "offline",
            "EFFORT": "effort",
            "STEPS_OVERRIDE": "steps_override",
            "SKIP_PERMS": "skip_perms",
            "PLAIN": "plain",
            "_CHAT_SID": "chat_sid",
            "THINK_UI": "think_ui",
            "_ROUTE_SEEN": "route_seen",
            "_CTX_PCT": "ctx_pct",
            "_BROKEN_MODEL": "broken_model",
            "_BROKEN_AT": "broken_at",
            "_HOST_DOWN": "host_down",
            "_LEARN_NOTES": "learn_notes",
            "_last_http": "last_http",
            "_TITLE": "title",
            "MODEL_ROWS_MISSING": "model_rows_missing",
            "_SUDO_OK": "sudo_ok",
            "_ACT_N": "act_n",
            "_ACT_LOCK": "act_lock",
            "_CTX_LIVE": "ctx_live",
            "_print_lock": "print_lock",
            "INTERRUPT": "interrupt",
            "_CANCEL": "cancel_local",
        }
        attr = mapping.get(name)
        if attr is None:
            return False
        setattr(self, attr, value)
        self._notify()
        return True

    # --------------------------------------------------------------- listeners
    def subscribe(self, fn):
        self._listeners.append(fn)

    def clear_listeners(self):
        self._listeners.clear()

    def _notify(self):
        for fn in list(self._listeners):
            try:
                fn(self)
            except Exception:  # noqa: BLE001 - a stale reload listener must not break import
                pass


STATE = RuntimeState()
