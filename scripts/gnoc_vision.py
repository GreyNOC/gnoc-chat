"""gnoc_vision.py - let the agent LOOK at an image file (a UI screenshot, a diagram, a chart) through an
installed vision model, instead of being told "binary file" and guessing.

describe(path, question, find_model) -> (model, text) | None when no vision model is installed.
find_model is the harness's _vision_model() (local Ollama models whose names say they can see).
"""
from __future__ import annotations

import base64
import contextlib
import io
import re

MAX_SIDE = 1280


def _jpeg(path):
    raw = None
    with contextlib.suppress(Exception):
        from PIL import Image
        with Image.open(path) as im:
            im = im.convert("RGB")
            im.thumbnail((MAX_SIDE, MAX_SIDE))
            buf = io.BytesIO()
            im.save(buf, "JPEG", quality=88)
            raw = buf.getvalue()
    if raw is None:
        with open(path, "rb") as fh:
            raw = fh.read()
    return base64.b64encode(raw).decode()


def describe(path, question, find_model, timeout=180):
    got = find_model()
    if not got:
        return None
    model, host = got
    ask = ("Describe this image for a software engineer who cannot see it. Transcribe every piece of visible "
           "text exactly (labels, buttons, error messages, code, numbers). Describe the layout top to bottom, "
           "and anything that looks broken (overlap, cut-off text, misalignment, empty areas). Under 250 words.")
    if question:
        ask += "\nAnswer this question first, directly: " + str(question)[:500]
    try:
        import llm_endpoints
        out = llm_endpoints._post(host, "/api/generate",
                                  {"model": model, "prompt": ask, "images": [_jpeg(path)], "stream": False,
                                   "options": {"num_predict": 600}}, timeout=timeout)
        text = (out or {}).get("response", "") if isinstance(out, dict) else ""
        text = re.sub(r"[ \t]+", " ", str(text)).strip()
        return model, (text[:3000] or "(the vision model returned nothing)")
    except Exception as e:  # noqa: BLE001 - a failed look is reported, never raised into the tool
        return model, f"(the vision model failed: {type(e).__name__}: {str(e)[:160]})"
