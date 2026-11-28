"""Image generation, vision and reference gathering."""
from gnoc_core.runtime import bind


def _vision_model():
    """(model, host) of an installed vision model, or None. Local first: the check should work offline."""
    (
        _VISION_HINT, os,
    ) = bind(
        "_VISION_HINT", "os",
    )
    try:
        import llm_endpoints
    except Exception:
        return None
    pin = os.environ.get("GNOC_VISION_MODEL")
    found = []
    for host in ("local", "desktop"):
        try:
            tags = llm_endpoints._tags(host) or []
        except Exception:
            continue
        # llm_endpoints._tags returns {name: digest}; tolerate a list of dicts too, since this is the
        # kind of shape assumption that fails silently as "no vision model installed" forever.
        if isinstance(tags, dict):
            names = list(tags)
        elif isinstance(tags, list):
            names = [t.get("name") or t.get("model") or "" for t in tags if isinstance(t, dict)]
        else:
            names = []
        if pin and pin in names:
            return pin, host
        found += [(n, host) for n in names if _VISION_HINT.search(n)]
    if not found:
        return None
    # Deterministic preference, not whatever Ollama happened to list first. Measured on the garish
    # green lab render (2026-10-24): llava:7b described it and said OK, qwen2.5vl:7b said WRONG and
    # named the reason ("predominantly green, not near-black"). A weaker judge that approves a bad
    # image is worse than none, because the tool then tells the agent to go ahead.
    rank = ("qwen2.5vl", "qwen2-vl", "llama3.2-vision", "minicpm-v", "llava:13b", "llava", "moondream")
    def score(item):
        n = item[0].lower()
        for i, pref in enumerate(rank):
            if pref in n:
                return (i, n)
        return (len(rank), n)
    return min(found, key=score)


def _image_sanity(path, want_w, want_h):
    """What a pair of eyes catches in the first half second, as numbers. Returns (ok, [finding, ...])."""
    try:
        from PIL import Image
        import numpy as np
    except Exception as e:
        return True, [f"not checked: {type(e).__name__} (PIL and numpy are needed)"]
    bad = []
    try:
        with Image.open(path) as im:
            im.load()
            w, h = im.size
            a = np.asarray(im.convert("RGB"), dtype=np.float32)
    except Exception as e:
        return False, [f"the file does not decode as an image: {type(e).__name__}: {str(e)[:120]}"]
    if (w, h) != (int(want_w), int(want_h)):
        bad.append(f"size is {w}x{h}, not the {int(want_w)}x{int(want_h)} that was asked for")
    lum = a @ np.array([0.2126, 0.7152, 0.0722], dtype=np.float32)
    mean, sd = float(lum.mean()), float(lum.std())
    if sd < 4.0:
        bad.append(f"the frame is flat (luma sd {sd:.1f}): a blank or single-colour render")
    if mean < 12:
        bad.append(f"the frame is almost black (mean luma {mean:.1f})")
    elif mean > 243:
        bad.append(f"the frame is almost white (mean luma {mean:.1f})")
    clipped = float(((lum <= 1) | (lum >= 254)).mean())
    if clipped > 0.6:
        bad.append(f"{clipped * 100:.0f}% of the frame is pure black or pure white")
    # Edge energy separates a real picture from a smooth gradient, which passes the sd test.
    edge = float((np.abs(np.diff(lum, axis=0)).mean() + np.abs(np.diff(lum, axis=1)).mean()) / 2)
    if edge < 0.8:
        bad.append(f"almost no detail in the frame (edge energy {edge:.2f}): a gradient or a smear")
    return (not bad), (bad or [f"{w}x{h}, mean luma {mean:.0f}, sd {sd:.0f}, detail {edge:.1f}"])


def _image_vision(path, brief, refs):
    """Ask an installed vision model whether the image matches what was asked for. None when there is none."""
    (
        _vision_model, contextlib, io, re,
    ) = bind(
        "_vision_model", "contextlib", "io", "re",
    )
    got = _vision_model()
    if not got:
        return None
    model, host = got
    try:
        import base64
        import llm_endpoints
        # A 1536x1024 PNG is ~2 MB and thousands of vision tokens; qwen2.5vl reads a 896-px JPEG just as
        # well in a fraction of the time. The full-size file timed out at 120 s on the first test run
        # (2026-10-25, the laptop model was on the CPU that day, which made it worse, not different).
        raw = None
        with contextlib.suppress(Exception):
            from PIL import Image
            with Image.open(path) as im:
                im = im.convert("RGB")
                im.thumbnail((896, 896))
                buf = io.BytesIO()
                im.save(buf, "JPEG", quality=85)
                raw = buf.getvalue()
        if raw is None:
            with open(path, "rb") as fh:
                raw = fh.read()
        b64 = base64.b64encode(raw).decode()
        # Itemised, not "does it match": asked that way about a two-monitor render against a brief that said
        # three, qwen2.5vl wrote "two monitors ... yes, it matches ... OK" (test 9, 2026-10-25). Made to
        # write PRESENT or MISSING per required item, the miss becomes a word the code can see.
        ask = ("Look at the image. Reply in under 80 words and do not repeat these instructions.\n"
               "A) What is in it, with counts of the main objects (for example 'two monitors').\n"
               "B) The request was: " + (brief or "(none given)") + "\n"
               "   For each thing it requires, one line '<the thing>: PRESENT' or '<the thing>: MISSING' (count first).\n"
               "   For each thing it forbids, one line '<the thing>: ABSENT' or '<the thing>: VIOLATED' (ABSENT is "
               "good; write 'people: ABSENT', never 'no people').\n"
               "C) Defects: deformed hands or faces, garbled text, duplicated limbs, blank or corrupted areas?\n"
               "Last word: OK, or WRONG only if a line says MISSING or VIOLATED or there is a defect.")
        if refs:
            ask += "\nReference material the operator approved: " + "; ".join(refs[:4])
        out = llm_endpoints._post(host, "/api/generate",
                                  {"model": model, "prompt": ask, "images": [b64], "stream": False,
                                   "options": {"num_predict": 320}}, timeout=180)
        text = (out or {}).get("response", "") if isinstance(out, dict) else ""
        text = re.sub(r"\s+", " ", str(text)).strip()
        return (model, text[:900]) if text else None
    except Exception as e:
        return (model, f"(the vision check failed: {type(e).__name__}: {str(e)[:120]})")


def _read_reference(ctx, url, min_chars=0):
    """Read one reference page NOW and record it the way web_fetch does. Returns (ok, note).

    min_chars rejects a page that came back with no readable text. Measured 2026-10-25: a live lookup
    for a fire lookout tower read three stock-photo SEARCH pages whose extracted text was 124, 154 and
    78 characters - they render their results in JavaScript, so the gate was satisfied by pages that
    ground nothing at all. A page that says nothing is not a reference.
    """
    (
        _deadline, _in_active_scope, gnoc_web,
    ) = bind(
        "_deadline", "_in_active_scope", "gnoc_web",
    )
    _off = __import__("gnoc_privacy").why_not("image-lookup")
    if _off:
        return False, f"{url[:70]} (not opened: {_off})"
    try:
        ok, text = _deadline(lambda: gnoc_web.fetch(url, _in_active_scope(ctx)), 60, f"reference {url[:60]}")
    except Exception as e:
        return False, f"{url[:70]} ({type(e).__name__})"
    if not ok:
        return False, f"{url[:70]} ({str(text)[:90]})"
    if min_chars and len(str(text)) < min_chars:
        return False, f"{url[:70]} (only {len(str(text))} chars of text, nothing to ground a prompt in)"
    read = [u for u in (ctx.s.get("fetched_urls") or []) if u != url]
    read.append(url)
    ctx.s["fetched_urls"] = read[-40:]
    return True, f"{url[:70]} ({len(str(text))} chars)"


def _seek_references(ctx, subject, want=3):
    """GO AND FIND what the subject looks like. Returns (urls actually read, note lines).

    The user, 2026-10-25: "we want to be able to prompt for image creation and not have it refuse due to
    no reference. It should seek reference". A missing reference is a LOOKUP, not a refusal: the tool
    runs the search and the fetches it used to tell the agent to go and run by hand. The gate itself is
    unchanged - the image is still grounded in pages that were really read, and a URL nobody opened
    still grounds nothing. What changed is WHO does the reading.
    """
    (
        REFERENCE_MIN_CHARS, _BINARY_REF, _THIN_REF_HOST, _deadline, _read_reference,
        gnoc_web, urllib,
    ) = bind(
        "REFERENCE_MIN_CHARS", "_BINARY_REF", "_THIN_REF_HOST", "_deadline",
        "_read_reference", "gnoc_web", "urllib",
    )
    subject = " ".join(str(subject or "").split()[:14])
    if not subject:
        return [], ["nothing to look up: the prompt is empty"]
    _off = __import__("gnoc_privacy").why_not("image-lookup")
    if _off:
        # his /privacy switch: the picture is drawn from the prompt alone, nothing is searched (2026-11-24)
        return [], [f"no reference lookup: {_off}; drawn from the prompt alone"]
    want = max(1, int(want))
    urls, lines, tried = [], [], 0
    # ONE budget for the whole lookup: two searches at up to 45 s and ten pages at up to 60 s made a red-fox wallpaper
    # take 325 s for a 16 s drawing (image drive, 2026-11-23). Past it, the picture is drawn with what was read.
    import time as _t
    _end = _t.time() + float(__import__("os").environ.get("GNOC_IMAGE_REF_BUDGET") or 60)
    # TWO queries, in order, because one is not reliable. Measured 2026-10-25: "<subject> what it looks
    # like description" for a lighthouse returned 10 results of which 10 were stock-photo search pages,
    # and the lookup came back empty. The same subject with "wikipedia" returned six encyclopedia
    # articles. The descriptive query is still first - it fits subjects an encyclopedia has no entry for
    # - and the second only runs when the first has not filled the quota.
    for query in (subject + " what it looks like description", subject + " wikipedia"):
        if len(urls) >= want or _t.time() > _end:
            break
        try:
            rows, note = _deadline(lambda query=query: gnoc_web.search(query, 10), 45, "reference search")
        except Exception as e:
            lines.append(f"reference search failed: {type(e).__name__}: {str(e)[:120]}")
            continue
        if not rows:
            lines.append(f"no results for {query[:60]!r}: {note}")
            continue
        for _title, url, _sn in rows:
            if len(urls) >= want:
                break
            url = str(url or "")
            if not url.startswith("http") or _BINARY_REF.search(url) or url in urls:
                continue
            host = urllib.parse.urlparse(url).hostname or ""
            if _THIN_REF_HOST.search(host):
                continue  # a stock-photo search page is never a description
            if tried >= 10 or _t.time() > _end:
                lines.append("stopped looking: " + ("10 pages tried" if tried >= 10 else "the lookup's time is up"))
                break
            tried += 1
            ok, why = _read_reference(ctx, url, min_chars=REFERENCE_MIN_CHARS)
            lines.append(("read " if ok else "could not read ") + why)
            if ok:
                urls.append(url)
    if not urls:
        lines.append("no reference page could be read (offline, or every result was blocked)")
    return urls, lines


def _counts(text):
    """{noun: n} for every 'three monitors' / '2 screens' in the text; nouns are singularised crudely."""
    (
        _COUNT_RX, _NUM_WORDS,
    ) = bind(
        "_COUNT_RX", "_NUM_WORDS",
    )
    out = {}
    for num, noun in _COUNT_RX.findall(str(text or "")):
        n = int(num) if num.isdigit() else _NUM_WORDS.get(num.lower())
        noun = noun.lower().rstrip("s") if not noun.lower().endswith("ss") else noun.lower()
        if n and noun not in ("second", "minute", "hour", "word", "step", "time", "round", "line", "page", "char",
                              "pixel", "px", "row"):
            out.setdefault(noun, n)
    return out


def count_mismatch(brief, seen):
    """'three monitors' asked, 'two monitors' seen -> a one-line finding, else ''. qwen2.5vl counted the two
    monitors correctly and still wrote PRESENT for the three that were asked (image test 9, 2026-10-25); the
    numbers it wrote are more honest than its verdict, so the code compares them."""
    (
        _counts,
    ) = bind(
        "_counts",
    )
    want, got = _counts(brief), _counts(seen)
    for noun, n in want.items():
        if noun in got and got[noun] != n:
            return f"count: the brief asks for {n} {noun}(s), the vision model saw {got[noun]}"
    return ""


def _size_from_brief(text):
    """(w, h) the brief asks for, or None. The lead wrote '16:9' into the brief and left width/height at
    their defaults, so a social post came back square (photo 11, 2026-10-25). An explicit WxH wins."""
    (
        _ASPECTS,
    ) = bind(
        "_ASPECTS",
    )
    text = str(text or "")
    for rx, size in _ASPECTS:
        m = rx.search(text)
        if m:
            return (int(m.group(1)), int(m.group(2))) if size is None else size
    return None


import re  # noqa: E402 - the module otherwise binds re per function

# A realistic photo of a real, identifiable person, or a copy of a brand's mark: the 9B asked "which actor?" and "what
# outfit are you wearing?" for "a realistic photo of me with the president" (image drive, 2026-11-23).
_REAL_PERSON = re.compile(r"(?i)\b(?:the\s+)?(?:president|prime\s+minister|chancellor|king|queen|prince|princess|pope|"
                          r"senator|governor|mayor|celebrity|celebrities|famous\s+\w+|movie\s+star|pop\s+star|"
                          r"(?:an?\s+)?(?:actor|actress|singer|rapper|footballer|athlete|politician|ceo\s+of)\b)")
_REALISTIC = re.compile(r"(?i)\b(?:realistic|photo\w*|real\s+looking|lifelike|hyper-?real\w*|deepfake)\b")
_BRAND_MARK = re.compile(r"(?i)\b(?:nike|adidas|apple|google|microsoft|acme|meta|facebook|instagram|tesla|disney|"
                         r"coca[- ]?cola|pepsi|mcdonald'?s|starbucks|puma|gucci|chanel|louis\s+vuitton|ferrari|bmw|"
                         r"mercedes|samsung|sony|netflix|spotify|youtube|twitter|x\.com|tiktok|playstation|xbox|"
                         r"nintendo|marvel|pokemon|pok\u00e9mon|lego|ikea|shell|toyota|honda)\b[^.]{0,20}\b(?:logo|"
                         r"emblem|swoosh|trademark|brand\s+mark|icon)\b|\b(?:logo|emblem|swoosh)\s+(?:of|for|from)\s+"
                         r"(?:nike|adidas|apple|google|microsoft|acme|meta|facebook|tesla|disney|coca[- ]?cola|pepsi|"
                         r"mcdonald'?s|starbucks)\b")


# names asked for most often; any other real name is caught by the turn note (possible_named_person) and the model
_FAMOUS = re.compile(r"(?i)\b(?:elon\s+musk|musk|taylor\s+swift|donald\s+trump|trump|joe\s+biden|biden|barack\s+obama|"
                     r"obama|kamala\s+harris|vladimir\s+putin|putin|zelensk[yi]+|xi\s+jinping|king\s+charles|rishi\s+sunak|"
                     r"keir\s+starmer|emmanuel\s+macron|narendra\s+modi|pope\s+\w+|beyonc[eé]|kim\s+kardashian|"
                     r"kanye(?:\s+west)?|bill\s+gates|mark\s+zuckerberg|zuckerberg|jeff\s+bezos|bezos|oprah|"
                     r"cristiano\s+ronaldo|lionel\s+messi|lebron\s+james|tom\s+cruise|scarlett\s+johansson|"
                     r"rihanna|drake|ariana\s+grande|billie\s+eilish|greta\s+thunberg|sam\s+altman)\b")
# "in the style of a famous coffee brand's logo": a copy of some brand's mark, even unnamed (image drive batch 4)
_BRAND_STYLE = re.compile(r"(?i)\b(?:style|look|copy|version|knock-?off)\s+of\s+(?:a\s+|the\s+|some\s+)?(?:famous|"
                          r"well[- ]known|big|major|popular|real|known)\s+(?:[\w-]+\s+){0,2}(?:brand|company|chain|"
                          r"franchise)(?:'s|s')?\s*(?:logo|mark|emblem|branding|trademark)?")


def possible_named_person(text):
    """The name in a realistic picture request that may be a real person ("elon musk riding a horse, realistic"),
    for the turn note to ask the model about; '' when there is none."""
    t = str(text or "")
    if not _REALISTIC.search(t):
        return ""
    m = re.search(r"(?i)\b(?:of|with|showing)\s+(?!(?:a|an|the|my|our|his|her|their|some|two|three|me)\b)"
                  r"([a-z][a-z'-]+\s+[a-z][a-z'-]+)\s+(?:riding|standing|holding|wearing|at|in|on|eating|drinking|doing|"
                  r"with|shaking|meeting|playing|giving|sitting|walking|running|smoking|kissing|hugging|signing|"
                  r"speaking|getting|being|and)\b", t)
    return m.group(1) if m else ""


def real_person_or_brand(text):
    """'person' for a realistic picture of a real public figure, 'brand' for a copy of a brand's mark, else ''."""
    t = str(text or "")
    if (_REAL_PERSON.search(t) or _FAMOUS.search(t)) and _REALISTIC.search(t):
        return "person"
    if _OFFICIAL_DOC.search(t) and _FORGED.search(t) and (_MAKE_DOC.search(t) or re.match(r"(?i)\W*an?\s", t)) \
            and not _MAKE_DOC_QUESTION.match(t):
        return "document"   # an order to make one; "how do I spot a fake passport" is a defender question
    if _BRAND_MARK.search(t) or _BRAND_STYLE.search(t):
        return "brand"
    return ""


# image batch 11: "make a fake driver's license with my photo" -> five questions (name, state, licence number, DOB)
_OFFICIAL_DOC = re.compile(r"(?i)\b(?:driv\w*'?s?\s+licen[cs]es?|licen[cs]e\s+cards?|passports?|(?:national\s+|state\s+|photo\s+|"
                           r"student\s+|government\s+|military\s+)?id(?:entity|entification)?\s+cards?|social\s+security\s+"
                           r"cards?|birth\s+certificates?|diplomas?|degree\s+certificates?|bank\s+statements?|pay\s*stubs?|"
                           r"payslips?|vaccination\s+(?:cards?|records?)|doctor'?s\s+notes?|sick\s+notes?|police\s+badges?|"
                           r"banknotes?|bank\s+notes?|dollar\s+bills?|counterfeit\s+money|visas?|green\s+cards?|"
                           r"residence\s+permits?|boarding\s+pass(?:es)?|press\s+pass(?:es)?)\b")
_FORGED = re.compile(r"(?i)\b(?:fake|forg\w*|counterfeit|replica|novelty|realistic|real[- ]looking|authentic[- ]looking|"
                     r"copy\s+of\s+(?:a|my|the)|that\s+(?:looks|passes)\s+(?:real|as\s+real)|with\s+my\s+(?:photo|picture|"
                     r"face|name|details))\b")
_MAKE_DOC = re.compile(r"(?i)\b(?:make|create|generate|draw|design|print|produce|forge|photoshop|render|mock\s*up|"
                       r"need\s+an?|want\s+an?|give\s+me|edit)\b")
_MAKE_DOC_QUESTION = re.compile(r"(?i)\W*(?:what|which|how|why|when|where|who|should|is|are|does|do|report|spot|"
                                r"detect|check|verify|someone|i\s+(?:got|received|found|lost))\b(?!\s+you\b)")
DOCUMENT_NO = ("not drawn: a realistic driver's licence, passport, ID card or other official document (or money) is a "
               "forged document, even with their own photo and name, and making or using one is a crime almost "
               "everywhere. Offer a clearly fictional prop instead (a cartoon-style card for an imaginary place, "
               "marked SAMPLE), and say so plainly with no questions first.")
REAL_PERSON_NO = ("not drawn: a realistic picture of a real, identifiable person (a politician, a celebrity, someone "
                  "named) is a fake photo of them, and it misleads. Offer an illustration or a fictional person "
                  "instead, and say so plainly with no questions first.")
BRAND_NO = ("not drawn: a copy of a company's logo or trademark is theirs, not their. Offer an ORIGINAL logo for their "
            "business instead (its name, colours, a symbol of what it does), and say so plainly with no questions first.")


def _edit_target(ctx, text):
    """The existing picture an edit request means: a path the user wrote, "the <word> picture in <Folder>", or (for "it",
    "the last one") the last image this conversation made; '' when none is found."""
    import os   # the module binds os per function: without this the edit path died "NameError: os" (batch 4)
    t = str(text or "")
    m = re.search(r"(~/[\w./ -]*?\.(?:png|jpe?g|webp|gif))\b", t)
    if m and os.path.isfile(os.path.expanduser(m.group(1))):
        return os.path.expanduser(m.group(1))
    fm = re.search(r"(?i)\b(?:in|from|on)\s+(?:my\s+|the\s+)?(desktop|downloads|pictures|documents)\b", t)
    folder = os.path.expanduser("~/" + fm.group(1).capitalize()) if fm else os.path.expanduser("~/Downloads")
    wm = re.search(r"(?i)\bthe\s+([a-z][\w-]{2,})\s+(?:picture|image|photo|png|one)\b", t)
    if wm and os.path.isdir(folder) and wm.group(1).lower() not in ("last", "new", "same", "other", "first"):
        hits = sorted((os.path.join(folder, f) for f in os.listdir(folder)
                       if wm.group(1).lower() in f.lower() and re.search(r"(?i)\.(?:png|jpe?g|webp)$", f)
                       and "-original." not in f), key=os.path.getmtime)
        if hits:
            return hits[-1]
    made = [p for p in (ctx.s.get("_images_made") or []) if os.path.isfile(p)]
    if made and re.search(r"(?i)\b(?:it|that|this|the\s+last\s+one|the\s+(?:picture|image|photo))\b", t):
        return made[-1]
    return ""


# words that say how a picture looks, not what is in it
_STYLE_ONLY = {"bold", "bright", "dark", "colours", "colors", "colour", "color", "landscape", "portrait", "square",
               "illustration", "make", "for", "the", "and", "with", "flat", "digital", "art", "vivid", "style",
               "clean", "simple", "modern", "minimal", "background", "white", "black", "text", "letters", "open",
               "area", "middle", "nice", "cool", "my", "your", "a", "an", "neon", "pastel", "vibrant", "colourful",
               "colorful", "wide", "banner", "cover", "poster"}   # "podcast called NIGHT SHIFT, neon" drew a sunny day


def _looks_like_brief(text):
    """True when the user's own message already covers the media questions: long enough, and at least three
    of the four facets (where it goes, the style, the size or aspect, must / must not) are in it."""
    (
        _BRIEF_FACETS,
    ) = bind(
        "_BRIEF_FACETS",
    )
    text = str(text or "")
    if __import__("re").match(r"(?i)\W*(?:what|which|how|why|when|where|who|should|can|could|would|does|do|is|are)\b(?!\s+you\s+(?:please\s+)?(?:make|draw|create|design|generate|paint|render)\b)", text) \
            or text.rstrip().endswith("?"):
        return False   # "what size should a youtube thumbnail be" asks, it does not order a picture
    n = sum(1 for rx in _BRIEF_FACETS if rx.search(text))
    # "make a birthday card for my mom, flowers, portrait" (49 chars, 2 facets) got four questions (image batch 12):
    # a short message that lists its details after commas is a brief too
    # "a desktop wallpaper of a calm ocean at night, 1920x1080" got five questions (image batch 12): a stated size
    # with one more facet is a brief too
    return len(text) >= 60 and n >= 3 or len(text) >= 35 and n >= 2 and (
        text.count(",") >= 2 or bool(_BRIEF_FACETS[2].search(text)))


def t_generate_image(ctx, prompt="", negative="", width=1024, height=1024, steps=28, seed=None, out_dir=None,
                     brief="", references=None, brand=None, mark="owl-light"):
    (
        os, _write_refusal, MEDIA_QUESTIONS, _image_sanity, _image_vision, _inside_ws, _looks_like_brief,
        _read_reference, _rel, _seek_references, _size_from_brief, contextlib,
        count_mismatch, llm_endpoints, re, role_spec,
    ) = bind(
        "os", "_write_refusal", "MEDIA_QUESTIONS", "_image_sanity", "_image_vision", "_inside_ws",
        "_looks_like_brief", "_read_reference", "_rel", "_seek_references",
        "_size_from_brief", "contextlib", "count_mismatch", "llm_endpoints", "re",
        "role_spec",
    )
    import gnoc_image
    # "mark='none, width=512, seed=-1, negative='": the 9B packed the other arguments into one value and the width
    # fell back to 1024 (image drive, 2026-11-23). key=value pairs inside a string argument are unpacked.
    for _v in (mark, brief, prompt):
        for _k, _val in re.findall(r"\b(width|height|seed|steps|negative|out_dir)\s*=\s*([^,]*)", str(_v or "")):
            _val = _val.strip().strip("'\"")
            if _k in ("width", "height", "steps") and _val.isdigit():
                width, height, steps = (int(_val), height, steps) if _k == "width" else (
                    (width, int(_val), steps) if _k == "height" else (width, height, int(_val)))
            elif _k == "seed" and _val.lstrip("-").isdigit():
                seed = int(_val)
            elif _k == "negative" and _val and not negative:
                negative = _val
            elif _k == "out_dir" and _val and not out_dir:
                out_dir = _val
    if mark and "=" in str(mark):
        mark = str(mark).split(",")[0].strip() or "none"
    _hiswords = str(ctx.s.get("_turn_text") or "")
    import gnoc_draw
    _op = gnoc_draw.edit_plan(_hiswords)
    _target = _edit_target(ctx, _hiswords) if _op else ""
    if _op and _target:
        # an EDIT of a picture that exists: change that file ("make ~/Downloads/cocoa.png black and white" drew a new,
        # different picture, image drive 2026-11-23)
        if not _inside_ws(os.path.dirname(_target)):
            return f"refused: {os.path.dirname(_target)} is outside the active repo"
        _why = _write_refusal(_target)
        if _why:
            return _why
        try:
            done, note = gnoc_draw.edit(_target, _op, _hiswords)
        except Exception as e:  # noqa: BLE001
            return f"not edited: {e}"
        return f"image edited: {_rel(done)}  ({note}; the picture itself was changed, nothing new was generated)"
    _rb = real_person_or_brand(_hiswords + " " + str(prompt or "") + " " + str(brief or ""))
    if _rb:
        return REAL_PERSON_NO if _rb == "person" else DOCUMENT_NO if _rb == "document" else BRAND_NO
    _overlay = __import__("gnoc_draw").scene_with_words(_hiswords)   # a picture WITH exact words on it
    if (__import__("gnoc_draw").plan(_hiswords) == "text" and not _overlay) or \
            __import__("gnoc_draw").plan(_hiswords) == "icon" or \
            re.search(r"(?i)\b(?:exact\w*|precise\w*|test\s+(?:image|pattern|card)|pixel[- ]perfect)\b", _hiswords) \
            and re.search(r"(?i)\b(?:circle|square|triangle|rectangle|line|grid|dot|polygon|shape|stripe|checker\w*|"
                          r"gradient)\b", _hiswords) \
            or re.search(r"(?i)\b(?:bar|pie|line)\s+(?:chart|graph)|\bchart\b[^.]*\d|\bdiagram\b", _hiswords) \
            or (re.search(r"(?i)\b(?:chart|graph|plot|visuali[sz]e)\w*\b", _hiswords)
                and len(__import__("gnoc_draw").pairs(_hiswords)) >= 2):
        # ("graph these sales: january 120, february 95 ..." went to Stable Diffusion twice: garbled text, doubled bars)
        # Stable Diffusion cannot draw exact geometry or a chart: "a black circle centred on a white square, exactly,
        # 512x512" came back 768x384 with no circle at the centre, and the 9B's own SVG chart put Thursday's 8 under
        # an axis that ended at 6 (image drive, 2026-11-23). gnoc_draw draws them exactly, with no extra packages.
        import gnoc_draw
        kind = gnoc_draw.plan(_hiswords) or ("chart" if gnoc_draw.pairs(_hiswords) else "shape")
        try:
            dest = gnoc_draw.target(_hiswords, kind, out_dir)
            if not _inside_ws(os.path.dirname(dest)):   # the same place rules as every image
                return f"refused: {os.path.dirname(dest)} is outside the active repo"
            _why = _write_refusal(dest)
            if _why:
                return _why
            made, note = {"chart": gnoc_draw.chart, "text": gnoc_draw.text,
                          "icon": gnoc_draw.icon}.get(kind, gnoc_draw.shape)(_hiswords, dest)
        except Exception as e:  # noqa: BLE001
            return (f"not drawn: this asks for an exact {kind}, which the image model cannot draw, and the exact "
                    f"drawing failed ({e}). Draw it with write_file as an SVG instead, at the size the user asked.")
        _made = ctx.s.setdefault("_images_made", [])
        _made.append(os.path.realpath(made))
        del _made[:-50]
        return f"image saved: {_rel(made)}  ({note}; no image model: exact shapes and charts are drawn, not generated)"
    brief = str(brief or "").strip()
    # The lead sent brief, size and references and forgot `prompt` in four of ten test runs (2026-10-25);
    # each cost a call to "generate_image needs prompt". The brief describes the picture: it is the prompt.
    _prompt_given = bool(str(prompt or "").strip())
    prompt = str(prompt or "").strip() or brief
    refs = [str(r).strip() for r in (references or []) if str(r or "").strip()]
    brand = str(brand or "").strip().lower() or None
    brief_note = ""
    his = str(ctx.s.get("_turn_text") or "").strip()
    if (len(brief) < 40 or brief.count("?") >= 2) and _looks_like_brief(his):
        # HIS message already answers the questions. Asked for "the Golden Gate Bridge in fog ... for a blog
        # header, photorealistic, 16:9, towers visible through fog, no people, no text", the lead restated
        # all of that in its reply and called the tool with no `brief` three times; the third refusal
        # switched the tool off and the turn ended with no picture (test 7, 2026-10-25). The brief gate is
        # there to make sure his answers exist, and here they do: take them from his own words.
        brief, brief_note = his[:1200], "brief: taken from the user's own message, which already answered the questions"
        if not _prompt_given or len(prompt) < 40:
            # ...and so is the PROMPT: generate_image(brief='blog header') for "a lighthouse on a cliff at sunset ..."
            # drew a bed of flowers from the two words "blog header" (image drive, 2026-11-23)
            prompt = his[:600]
    if re.search(r"(?i)\btransparen\w*\b", his or "") and "white background" not in prompt.lower():
        prompt = re.sub(r"(?i),?\s*transparent\s+background", "", prompt).strip(" ,") + ", isolated on a plain white background"
    if his and len(prompt) < 40 and his.lower()[:60] not in prompt.lower() and len(his) < 400 and not brief_note:
        # his answers ARE this turn's words: asked "a mountain?" and answered "for my phone wallpaper, realistic,
        # portrait, snowy peak, no text", the lead called prompt='a mountain' (image drive, 2026-11-23)
        prompt = (prompt + ", " + his).strip(" ,")[:600]
    if len(brief) < 40 and ctx.s.get("_media_asked"):
        # the ONE round of questions already happened in this conversation: his reply, short or partial, is the
        # brief, with defaults for the rest ("put the last one on my Desktop" was refused "no brief", image drive)
        brief = (brief + ", " + his).strip(" ,")[:600] if his and his.lower() not in brief.lower() else brief
        brief = brief if len(brief) >= 40 else (brief + ", an illustration, square, no text").strip(" ,")
        brief_note = brief_note or "brief: their reply to the picture questions, with defaults for what the user left out"
    if len(brief) < 40 and brief.count("?") < 2:
        # a short brief that still answers the questions: "4K mountain lake at sunset, photo style" (39 characters,
        # subject + style + size) was refused "no brief" three times, then the lead tried the gnoc CLI (image drive
        # batch 4). Two facets in his words or the brief, with a subject, are enough; defaults do the rest.
        (_BRIEF_FACETS,) = bind("_BRIEF_FACETS")
        _both = brief + " " + (his or "")
        if len(re.findall(r"[A-Za-z]{3,}", brief)) >= 3 and sum(1 for rx in _BRIEF_FACETS if rx.search(_both)) >= 2:
            brief = (brief + (", " + his if his and his.lower()[:40] not in brief.lower() else "")).strip(" ,")[:600]
            brief = brief if len(brief) >= 40 else brief + ", no text"
    if len(brief) < 40:
        # Observed on the real 35B lead, 2026-10-24: it tried to ASK the questions BY CALLING this
        # tool, with them typed into `brief` and no prompt. Say where the asking happens.
        return ("refused: no brief. Ask the user IN CHAT - do not call this tool to ask - and come back "
                "with their answers as `brief`: " + MEDIA_QUESTIONS + ". One round of questions in your "
                "reply, then generate when the user answers.")
    if not brief_note and (brief.count("?") >= 2
                           or re.search(r"\bwhat (?:is this for|style|aspect|must (?:not )?appear)\b", brief, re.I)):
        # The length floor let this through: the 35B lead typed the five questions THEMSELVES into brief
        # ("what is this FOR (post, banner...)? what style...?") and generated on them (first image test
        # run, 2026-10-25). A brief made of questions is the asking, not the answers.
        return ("refused: `brief` holds the QUESTIONS, not the user's answers. Ask them IN CHAT, in your reply, in "
                "one round: " + MEDIA_QUESTIONS + ". When the user answers, call this tool with their answers as `brief` "
                "(what it is of, where it goes, style, size, must / must not appear).")
    grounding = ""
    lookup = []  # what the tool itself read, relayed to the agent so "I looked it up" is checkable
    http_refs = [r for r in refs if r.startswith("http://") or r.startswith("https://")]
    if brand:
        # brand SKIPS the reference lookup, and the lead learned that: asked for a red fox in snow for a
        # social post it passed brand=company unasked, and the owl was composited onto a wildlife photo
        # (test run 2, 2026-10-25). The palette and the mark are for pictures he asked to be GreyNOC's.
        asked = (brief + " " + str(ctx.s.get("_turn_text") or "")).lower()
        if not re.search(r"grey-?noc|gnoc|academy|company|campus|brand|logo|owl|website|our (?:site|look|palette)|"
                         r"the (?:public )?site", asked):
            return (f"refused: brand={brand} was passed, but neither the user's words nor the brief ask for a "
                    "The user-branded picture (no the user / academy / company / brand / logo / owl in them). Call "
                    "again WITHOUT brand and mark: the tool looks up references itself. brand is only for pictures "
                    "The user wants in the company or academy look.")
        # GreyNOC's own look is NOT something to go and read about: the authoritative reference is the
        # site's own stylesheet and the mark files it serves, which gnoc_brand reads at call time. That
        # is stronger grounding than any page on the web, so it SATISFIES the reference gate - and the
        # picture still gets the real owl rather than one SDXL invented (GreyNOC, 2026-10-24).
        import gnoc_brand
        if brand not in gnoc_brand.FACES:
            return (f"refused: brand must be one of {', '.join(gnoc_brand.FACES)}. "
                    + "  ".join(gnoc_brand.brief_hint(f) for f in gnoc_brand.FACES)
                    + ". They are different palettes: do not use the green one for the public site.")
        # SUBJECT FIRST, style after. SDXL weights the leading tokens hardest, so putting the palette
        # in front buried the subject: two tests asking for "one centred pyramid" came back as a scree
        # slope and then a field of blue blocks, both perfectly on-palette and neither the thing asked
        # for (2026-10-24).
        prompt = str(prompt or "") + ", " + gnoc_brand.style_prompt(brand)
        negative = (str(negative or "") + ", " + gnoc_brand.NEGATIVE).strip(" ,")
        grounding = gnoc_brand.brief_hint(brand)
    else:
        fetched = {u for u in ctx.s.get("fetched_urls") or []}
        # A URL nobody opened is a citation, not a reference - so OPEN it, here, now. Anything the agent
        # typed without reading is read by the tool before SDXL sees the prompt (GreyNOC, 2026-10-25).
        for u in [r for r in http_refs if r not in fetched]:
            ok, why = _read_reference(ctx, u)
            lookup.append(("read " if ok else "could not read ") + why)
            if not ok:
                http_refs = [r for r in http_refs if r != u]
        if not http_refs:
            # No usable reference was handed over. Go and find one rather than handing the work back.
            found, lines = _seek_references(ctx, prompt)
            lookup += lines
            http_refs = list(found)
            refs = refs + [u for u in found if u not in refs]
        if not http_refs:
            # GreyNOC 2026-10-25: "not have it refuse due to no reference". With no network (or nothing found) a
            # cartoon cat was refused outright (image drive, 2026-11-23): draw from the prompt and say so.
            lookup.append("no reference could be read (offline or nothing found): drawn from the prompt alone")
    _his = str(ctx.s.get("_turn_text") or "")
    _name = ""
    _m = re.search(r"(?i)\b(?:as|to|into|in|at)\s+(~/[\w./ -]*?\.(?:png|jpe?g|webp))\b", _his) if _his else None
    if _m:
        # the FILE he named ("save it as ~/Pictures/apple.png"), whether or not the call passed the folder (it passed
        # out_dir=~/Pictures and the file came out as gnoc-image-....png, image drive 2026-11-23)
        _name = os.path.basename(_m.group(1))
        out_dir = out_dir or os.path.dirname(_m.group(1)) or "~"
    if not out_dir and _his:
        # The folder he named, when the call names none: "put it on my Desktop" went to ~/Downloads (image drive)
        _m = re.search(r"(?i)\b(?:on|to|into|in|at)\s+(?:my\s+|the\s+)?(desktop|downloads|pictures|documents)\b"
                       r"|\b(?:to|into|in|at)\s+(~/[\w./-]+)", _his)
        if _m:
            out_dir = _m.group(2) or "~/" + _m.group(1).capitalize()
    d = None
    if out_dir:
        d = _inside_ws(out_dir)
        if not d:
            return f"refused: {out_dir} is outside the active repo"
        why = _write_refusal(os.path.join(d, "x.png"))   # protected folders (submitted reports, hooks, .git)
        if why:
            return why
    _wanted = _size_from_brief(brief) or _size_from_brief(his)
    _passed = (int(width), int(height))
    if _wanted and 1024 in _passed and _passed != (1024, 1024) and abs(
            (_passed[0] / _passed[1]) - (_wanted[0] / _wanted[1])) > 0.15 * (_wanted[0] / _wanted[1]):
        # ONE side was passed (height=1344 for an iPhone wallpaper, width left at 1024): the shape he asked for wins
        width, height = 1024, 1024
    if (int(width), int(height)) == (1024, 1024):
        wanted = _wanted
        if wanted and wanted != (1024, 1024):
            width, height = wanted
            size_hint = f"size: {width}x{height} taken from the brief's aspect (width/height were not passed)"
        else:
            size_hint = ""
    else:
        size_hint = ""
    # The size SDXL will really render; the check below compares against THIS. Asked for 1920x1080 the tool
    # rendered 1536x1024 and then failed its own picture for being 1536x1024 (first test run, 2026-10-25).
    want_w, want_h = gnoc_image.clamp_dims(width, height)
    size_note = ""
    if (want_w, want_h) != (int(width), int(height)):
        size_note = (f"size: {int(width)}x{int(height)} was asked for, rendered {want_w}x{want_h} (SDXL takes "
                     f"{gnoc_image.SIZE_MIN}-{gnoc_image.SIZE_MAX} a side, multiples of 64: 1344x768 for 16:9, "
                     "768x1344 portrait, 1024x1024 square)")
    # The chat model lives on the same card when the lead is routed to the desktop: hand its name over so the
    # render unloads it first and loads it BACK afterwards, with a retry (see gnoc_image.warm_lead).
    lead = None
    with contextlib.suppress(Exception):
        ln, lh = llm_endpoints.split(role_spec("lead"))
        if lh == "desktop":
            lead = ln
    try:
        if _overlay:
            # the words go on afterwards, exactly: keep them OUT of the model's prompt. "poster ... that says RUN FOR
            # HOPE" still drew its own garbled lettering under the overlay (image batch 7)
            prompt = re.sub(r"(?i)\b(?:that|which)?\s*(?:says|saying|reads|reading|with\s+the\s+words?)\s*[\"'\u201c]?"
                            + re.escape(_overlay) + r"[\"'\u201d]?", " ", prompt)
            prompt = re.sub(re.escape(_overlay), " ", prompt, flags=re.I)
            prompt = re.sub(r"(?i)\b(?:poster|banner|flyer|sign|cover)\b", "illustration", prompt)
            # "thumbnail for my youtube video titled LINUX TIPS" drew two presenters' faces under fake lettering
            # ("Yap Cle ne", "BOL CL"): those words mean a face and a caption to Stable Diffusion (image batch 8)
            prompt = re.sub(r"(?i)\b(?:youtube|yt|video|thumbnail|channel|vlog|podcast|episode|show|titled|called|"
                            r"named)\b", " ", prompt)
            # "a logo for my bakery called Sweet Crumbs" drew "Bakkrey"/"BAKKRY" around the overlay: to Stable
            # Diffusion a logo IS lettering. The name goes on exactly; the drawing is only the mark (image batch 10)
            prompt = re.sub(r"(?i)\b(?:logo(?:type)?|word\s*mark|branding|brand)\b", "simple flat emblem symbol, no "
                            "lettering,", prompt)
            _left = [w for w in re.findall(r"[A-Za-z]{3,}", prompt) if w.lower() not in _STYLE_ONLY]
            if len(_left) < 2:
                # nothing of a subject is left once the words come out: draw the topic itself, as objects
                prompt = (f"symbolic illustration of {_overlay.lower()}, objects and scenery that show the topic, "
                          + prompt).strip(" ,")
            prompt = (re.sub(r"\s{2,}", " ", prompt).strip(" ,") + ", no text, no letters, clean open area in the "
                      "middle").strip(" ,")
            negative = (str(negative or "") + ", text, letters, words, typography, writing, title, caption, "
                        "signature, watermark, logo text, wordmark, monogram, calligraphy, script lettering").strip(" ,")
        _wants_text = not _overlay and bool(re.search(r"(?i)\b(?:text|words?|title|caption|letters?|saying|says|headline|slogan|"
                                     r"name\s+on)\b|[\"\u201c][^\"\u201d]{2,40}[\"\u201d]",
                                     str(ctx.s.get("_turn_text") or "")))
        if not _wants_text and not re.search(r"(?i)\btext\b", str(negative or "")):
            # Stable Diffusion cannot spell: an art-deco jazz poster with no words asked for came back lettered
            # "JIEZZ NIHT NIGT" (image drive, 2026-11-23). No words unless he asks for them.
            negative = (str(negative or "") + ", text, letters, words, signature, watermark").strip(" ,")
        # stock-site watermarks, on every picture: a charity-run poster came back with a faint "dreamstime" across
        # the runner's leg (image batch 8). Stable Diffusion learned them from stock previews; naming them works
        # better than "watermark" alone.
        if "dreamstime" not in str(negative or ""):
            negative = (str(negative or "") + ", watermark, stock photo watermark, dreamstime, shutterstock, "
                        "getty images, istock, alamy, depositphotos, copyright notice, faint overlaid text").strip(" ,")
        if (seed in (None, "", -1, "-1") and ctx.s.get("_last_image_seed") not in (None, -1)
                and re.search(r"(?i)^\s*(?:now\s+|can you\s+|please\s+)?(?:make|turn|change|give)\s+(?:it|the\s+\w+|him|her|"
                              r"them)\b", _hiswords)):
            # a change to the picture just made keeps its seed: "make the fox blue" drew a new random scene
            # (image drive batch 4); the same seed keeps the composition close
            seed = ctx.s["_last_image_seed"]
        path, seed, secs = gnoc_image.generate(prompt, negative, width, height, steps, seed=seed, out_dir=d,
                                               lead=lead)
    except Exception as e:
        # The lookup log goes out with the failure too: it is what the next attempt is grounded in.
        return "\n".join([f"image failed: {type(e).__name__}: {str(e)[:300]}"]
                         + ["reference: " + x for x in lookup]
                         + ([gnoc_image.LAST_GPU_NOTE[0]] if gnoc_image.LAST_GPU_NOTE[0] else []))
    if _name:
        # "save it as ~/Pictures/apple.png": the file gets the name he gave
        _dest = os.path.join(os.path.dirname(path), _name)
        with contextlib.suppress(OSError):
            os.replace(path, _dest)
            path = _dest
    _transp_note = ""
    if re.search(r"(?i)\btransparen\w*\b", str(ctx.s.get("_turn_text") or "")):
        # Stable Diffusion has no alpha: "a rocket icon ... transparent background" was regenerated three times hoping
        # for one (image drive, 2026-11-23). Drawn on plain white, and the white made transparent where ImageMagick is.
        import shutil as _sh
        import subprocess as _sp
        _tool = _sh.which("magick") or _sh.which("convert")
        if _tool:
            _out = os.path.splitext(path)[0] + "-transparent.png"
            _r = _sp.run([_tool, path, "-fuzz", "8%", "-transparent", "white", _out], capture_output=True, timeout=60)
            if _r.returncode == 0 and os.path.isfile(_out):
                with contextlib.suppress(OSError):
                    os.replace(_out, path)
                _transp_note = "transparent background: the plain white around it was made transparent (ImageMagick)"
        if not _transp_note:
            _transp_note = ("transparent background: the image model cannot draw transparency, so it is on plain white. "
                            "`convert in.png -fuzz 8% -transparent white out.png` (ImageMagick) makes the white clear.")
    _ei = getattr(gnoc_image, "LAST_ENGINE_INFO", [{}])[0] or {}
    if _ei.get("width") and _ei.get("height"):
        # gnoc's engine drew it at ITS size (SD 1.5: long side 768): check the picture against that, not SDXL's
        want_w, want_h = int(_ei["width"]), int(_ei["height"])

    # The REAL mark goes on afterwards. SDXL cannot draw this owl: asked for one it invents a
    # different bird every time, and a nearly-right logo reads as a counterfeit of your own brand.
    mark_note = ""
    if brand and str(mark or "").lower() not in ("", "none", "no"):
        import gnoc_brand
        marked, why = gnoc_brand.compose(path, mark=str(mark))
        if marked:
            path, mark_note = marked, f"real mark composited: {why}"
        else:
            mark_note = f"mark NOT composited: {why}"

    # AFTER: the model cannot see the file, so the tool looks for it.
    ok, findings = _image_sanity(path, want_w, want_h)
    _real = ""
    with contextlib.suppress(Exception):
        with open(path, "rb") as _fh:
            _hd = _fh.read(24)
        if _hd[:8] == b"\x89PNG\r\n\x1a\n":
            # the size it REALLY is (SD 1.5 draws 768x438 for a 1344x768 ask): "the image is 1344x768" was the ask
            _real = f"{int.from_bytes(_hd[16:20], 'big')}x{int.from_bytes(_hd[20:24], 'big')}"
    _eng = getattr(gnoc_image, "LAST_ENGINE_INFO", [{}])[0] or {}
    _who = (f", drawn by {_eng.get('label')} on {_eng.get('where')}" if _eng.get("label") else "")
    # what THIS conversation made: "delete the picture you made" in a fresh chat tried rm on an older picture it picked
    _made = ctx.s.setdefault("_images_made", [])
    _made.append(os.path.realpath(path))
    del _made[:-50]
    ctx.s.pop("_media_asked", None)
    with __import__("contextlib").suppress(TypeError, ValueError):
        ctx.s["_last_image_seed"] = int(seed) if int(seed) >= 0 else None
    _laid = False
    if _overlay:
        # the model draws the scene with no lettering; the exact words go on top (it cannot spell: "JIEZZ NIHT")
        with __import__("contextlib").suppress(Exception):
            _laid = __import__("gnoc_draw").overlay_words(path, _overlay)
    lines = [f"image saved: {_rel(path)}  ({_real + ', ' if _real else ''}seed {seed}, {secs}s{_who}; same seed + "
             "prompt reproduces it)"]
    if brief_note:
        lines.append(brief_note)
    if _transp_note:
        lines.append(_transp_note)
    if _overlay:
        lines.append(f'words: "{_overlay}" laid over the picture exactly (the model drew the scene with no lettering)'
                     if _laid else f'words: "{_overlay}" could NOT be added (no ImageMagick here); the picture has '
                     "no lettering: say so, and that with imagemagick installed the exact words can be added")
    if not _overlay and re.search(r"(?i)\b(?:text|words?|title|caption|letters?|saying|headline|slogan)\b|[\"\u201c]"
                                  r"[^\"\u201d]{2,40}[\"\u201d]", str(ctx.s.get("_turn_text") or "")):
        lines.append("text: the image model cannot spell reliably, so any words in the picture may be garbled; say so, "
                     "and offer the picture without words for them to add the text themselves")
    if size_hint:
        lines.append(size_hint)
    if size_note:
        lines.append(size_note)
    for x in lookup:
        lines.append("reference: " + x)
    if gnoc_image.LAST_GPU_NOTE[0]:
        # The render and the chat model share one 16 GB card: say what state it was left in.
        lines.append(gnoc_image.LAST_GPU_NOTE[0])
    if grounding:
        lines.append("brand: " + grounding)
    if mark_note:
        lines.append(mark_note)
    lines.append(("check: PASS  " if ok else "check: FAILED  ") + "; ".join(findings))
    seen = _image_vision(path, brief, http_refs)
    if seen:
        model, text = seen
        lines.append(f"vision ({model}): {text}")
        if re.search(r"\bMISSING\b|\bVIOLATED\b", text):
            ok = False
        elif re.search(r"\bWRONG\b", text):
            # A bare WRONG with every line PRESENT/ABSENT and no defect named is the 7B judge tripping on
            # the brief's own "no people" (it wrote "no people: ABSENT ... WRONG" on photo 13, 2026-10-25,
            # and the retry of a good picture cost a render). The itemised lines are the evidence; the last
            # word only counts when something in them backs it.
            defect = re.search(r"\b(?:deformed|garbled|duplicat\w+|corrupt\w*|blank|extra (?:limb|finger|arm|leg)|"
                               r"missing (?:limb|finger|arm|leg))\b", text, re.I)
            defect_denied = re.search(r"\b(?:no|none|not any|without)\b[^.]{0,30}\b(?:defect|deform|garbled|duplicat|"
                                      r"corrupt|blank)", text, re.I)
            if defect and not defect_denied:
                ok = False
            else:
                lines.append("vision verdict: WRONG was written with every item PRESENT/ABSENT and no defect "
                             "named, so it is read as OK (the judge trips on 'no people' in the brief)")
        miss = count_mismatch(brief, text)
        if miss:
            lines.append(miss)
            ok = False
    else:
        lines.append("vision: NOT CHECKED - no vision model is installed, so nothing has looked at the content. "
                     "Install one (ollama pull llava) or show the user the file before using it.")
    if ok and seen:
        lines.append("Use it in a post with draft_outgoing image=<path>. Tell the user the path anyway so the user looks.")
    else:
        lines.append("DO NOT use this image yet. Tell the user exactly what the check said and the path, or "
                     "regenerate with a corrected prompt.")
    return "\n".join(lines)
