"""Shared foundation for gnoc chat.

These modules hold the low-coupling primitives extracted from ``gnoc_agent.py``.  The
public compatibility surface is still ``scripts/gnoc_agent.py``, which imports every
name below and re-exports it, so ``gnoc_agent.<name>`` keeps working for sibling
modules, tests and interactive sessions.

Import direction is deliberately one-way: ``gnoc_core`` never imports ``gnoc_agent``.
"""
