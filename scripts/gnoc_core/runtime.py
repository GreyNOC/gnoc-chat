"""Lazy access to the gnoc_agent facade for extracted implementations.

Extracted functions must see the *current* facade globals, not a snapshot taken at
import time: tests rebind ``gnoc_agent.WS``/``AGENT_DIR``, commands mutate the state
lists, and sibling modules replace callables.  Each extracted function therefore
binds the globals it needs at call time:

    from .runtime import bind
    say, WS, INTERRUPT = bind("say", "WS", "INTERRUPT")

``bind`` returns the live objects/values from the facade; mutable containers stay
shared, and a rebinding made between calls is visible to the next call.
"""

import importlib
import sys


def facade():
    """The current gnoc_agent module object (imported lazily on first use)."""
    mod = sys.modules.get("gnoc_agent")
    if mod is None:
        mod = importlib.import_module("gnoc_agent")
    return mod


def bind(*names):
    """Return the facade's current values for ``names``, in order."""
    mod = facade()
    values = []
    for name in names:
        try:
            values.append(getattr(mod, name))
        except AttributeError:
            raise AttributeError(
                f"extracted gnoc code needs gnoc_agent.{name}, which is not defined"
            ) from None
    return tuple(values)


# (module name, attribute) -> the value gnoc_core held before a facade assignment replaced it.
# gnoc_agent's module __setattr__ mirrors `gnoc_agent.X = fake` into the gnoc_core modules that hold the
# same object (they call each other directly, never through the facade). A test that patches and never
# restores used to be healed by the next importlib.reload(gnoc_agent); gnoc_core is not reloaded, so the
# facade calls undo_facade_patches() at the top of every (re)load instead.
FACADE_PATCHES = {}


def mirror_facade_patch(name, old, value):
    """Rebind `name` in every loaded gnoc_core module whose global is `old`; remember the first original."""
    for mod_name, mod in list(sys.modules.items()):
        if not mod_name.startswith("gnoc_core.") or mod is None:
            continue
        d = getattr(mod, "__dict__", None)
        if d is not None and name in d and d[name] is old:
            FACADE_PATCHES.setdefault((mod_name, name), old)
            d[name] = value
            if FACADE_PATCHES.get((mod_name, name)) is value:   # restored to the original: nothing to undo
                FACADE_PATCHES.pop((mod_name, name), None)


def undo_facade_patches():
    """Put back every gnoc_core global a facade assignment replaced (called when gnoc_agent (re)loads)."""
    for (mod_name, name), orig in list(FACADE_PATCHES.items()):
        mod = sys.modules.get(mod_name)
        if mod is not None:
            mod.__dict__[name] = orig
    FACADE_PATCHES.clear()
