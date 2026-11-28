"""load_skill and propose_skill: the model's two doors into gnoc_skills. Reading is free; proposing only queues."""
import gnoc_skills
from gnoc_core.paths import root


def t_load_skill(ctx, name, file=""):
    return gnoc_skills.load(root(), name, file=file or "")


def t_propose_skill(ctx, name, description, body, triggers=None, why=""):
    s = getattr(ctx, "s", None)
    s = s if isinstance(s, dict) else {}
    # The turn's taint (web, email, discord, mcp, and anything a worker bot read, handed up by _run_worker) and
    # the response text it read are what decide whether this text may outlive the turn.
    ok, msg, rec = gnoc_skills.propose(name, description, body, triggers=triggers, why=why,
                                       tainted=list(s.get("_tainted") or []),
                                       untrusted_texts=list(s.get("_untrusted_text") or []))
    if ok and rec:
        s.setdefault("_skill_proposed", []).append(rec["id"])   # the end-of-turn hint names it
    return msg
