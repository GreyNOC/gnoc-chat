"""gnoc_notebook.py - Jupyter notebooks as cells, not as JSON.

read_file on an .ipynb used to show the raw JSON: every source line a quoted string with a trailing "\\n",
outputs as base64 blobs. Editing it with edit_file meant copying that escaping byte for byte. Here a notebook
reads as numbered cells (source plus a short text of each output) and is changed one cell at a time:

    render(path)                                     the cells, numbered from 0
    edit_cell(path, index, source, action, cell_type) replace / insert (before index; index=len appends) / delete
"""
from __future__ import annotations

import json
import os

OUT_CHARS = 600


def load(path):
    with open(path, encoding="utf-8") as f:
        nb = json.load(f)
    if not isinstance(nb, dict) or not isinstance(nb.get("cells"), list):
        raise ValueError("not a Jupyter notebook (no cells list)")
    return nb


def _src(cell):
    s = cell.get("source", "")
    return "".join(s) if isinstance(s, list) else str(s)


def _outputs(cell):
    parts = []
    for o in cell.get("outputs") or []:
        kind = o.get("output_type")
        if kind == "stream":
            t = o.get("text", "")
            parts.append("".join(t) if isinstance(t, list) else str(t))
        elif kind in ("execute_result", "display_data"):
            data = o.get("data") or {}
            if "text/plain" in data:
                t = data["text/plain"]
                parts.append("".join(t) if isinstance(t, list) else str(t))
            others = [k for k in data if k != "text/plain"]
            if others:
                parts.append(f"[{', '.join(others)} output]")
        elif kind == "error":
            parts.append(f"{o.get('ename', 'Error')}: {o.get('evalue', '')}")
    text = "\n".join(p.rstrip() for p in parts if p)
    return text if len(text) <= OUT_CHARS else text[:OUT_CHARS] + f" ...[{len(text) - OUT_CHARS} more chars]"


def render(path):
    nb = load(path)
    lang = ((nb.get("metadata") or {}).get("kernelspec") or {}).get("language") or \
        ((nb.get("metadata") or {}).get("language_info") or {}).get("name") or "?"
    rows = [f"[Jupyter notebook {os.path.basename(path)}: {len(nb['cells'])} cells, language {lang}. "
            "Change a cell with edit_file path=<nb> cell=<index> new=<source> (cell_action=insert|delete).]"]
    for i, c in enumerate(nb["cells"]):
        ct = c.get("cell_type", "?")
        n = c.get("execution_count")
        rows.append(f"--- cell {i} [{ct}{f', run {n}' if n else ''}] ---")
        rows.append(_src(c) or "(empty)")
        out = _outputs(c) if ct == "code" else ""
        if out:
            rows.append("  >>> output:\n" + "\n".join("  " + ln for ln in out.split("\n")))
    return "\n".join(rows)


def _lines(text):
    parts = text.split("\n")
    return [p + "\n" for p in parts[:-1]] + ([parts[-1]] if parts[-1] else [])


def edit_cell(path, index, source=None, action="replace", cell_type=None):
    """Returns (before_text, after_text, message). Raises ValueError on bad input."""
    with open(path, encoding="utf-8") as f:
        before = f.read()
    nb = json.loads(before)
    if not isinstance(nb, dict) or not isinstance(nb.get("cells"), list):
        raise ValueError("not a Jupyter notebook (no cells list)")
    cells = nb["cells"]
    action = str(action or "replace").lower()
    if cell_type is not None and cell_type not in ("code", "markdown", "raw"):
        raise ValueError("cell_type is code, markdown or raw")
    # nbformat 4.5+ requires a unique id on every cell (QAQC r2: inserted cells had none)
    needs_id = (nb.get("nbformat", 4), nb.get("nbformat_minor", 0)) >= (4, 5)
    try:
        i = int(index)
    except (TypeError, ValueError):
        raise ValueError("cell is the 0-based cell number read_file shows")
    if action == "insert":
        if not 0 <= i <= len(cells):
            raise ValueError(f"insert position {i} is outside 0..{len(cells)}")
        ct = cell_type or "code"
        cell = {"cell_type": ct, "metadata": {}, "source": _lines(str(source or ""))}
        if needs_id:
            import uuid
            taken = {c.get("id") for c in cells}
            cid = uuid.uuid4().hex[:8]
            while cid in taken:
                cid = uuid.uuid4().hex[:8]
            cell["id"] = cid
        if ct == "code":
            cell.update({"execution_count": None, "outputs": []})
        cells.insert(i, cell)
        msg = f"inserted a {ct} cell at {i}"
    elif action == "delete":
        if not 0 <= i < len(cells):
            raise ValueError(f"cell {i} does not exist (0..{len(cells) - 1})")
        cells.pop(i)
        msg = f"deleted cell {i}"
    elif action == "replace":
        if not 0 <= i < len(cells):
            raise ValueError(f"cell {i} does not exist (0..{len(cells) - 1})")
        if source is None:
            raise ValueError("replace needs new=<the cell's new source>")
        c = cells[i]
        c["source"] = _lines(str(source))
        if cell_type and cell_type != c.get("cell_type"):
            c["cell_type"] = cell_type
            if cell_type == "code":
                c.setdefault("outputs", [])
                c.setdefault("execution_count", None)
                c.pop("attachments", None)   # the code-cell schema has no attachments
            else:
                c.pop("outputs", None)
                c.pop("execution_count", None)
        if c.get("cell_type") == "code":   # its old outputs describe code that is gone
            c["outputs"], c["execution_count"] = [], None
        msg = f"replaced cell {i}"
    else:
        raise ValueError("cell_action is replace, insert or delete")
    import re
    m = re.search(r"\n( +)\"", before[:400])   # the file's own indent (1, 2 or 4 spaces), so a one-cell edit does
    indent = len(m.group(1)) if m else 1    # not reformat the whole notebook (QAQC r2)
    after = json.dumps(nb, indent=indent, ensure_ascii=False) + "\n"
    return before, after, msg
