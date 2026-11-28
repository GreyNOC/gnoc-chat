#!/usr/bin/env python3
"""
registry-mine.py - mine public container registries for a target's build artifacts.

WHY THIS EXISTS. On 2026-10-03 a public Docker Hub image shipped `.git` and `.env` and leaked a
live Google service-account key. That was found by hand, on one image, by luck. The technique
generalises: organisations and their vendors push build artifacts to public registries
constantly, and a missing `.dockerignore` puts the whole working tree in a layer. Nobody is
watching this surface because checking it looks expensive.

THE IMPROVEMENT THAT MAKES IT CHEAP. You do not pull the image. The registry serves the image
CONFIG blob separately from the layers, it is a few KB, and it already contains:

  * `config.Env`      every ENV var baked into the image. Leaked secrets land here directly.
  * `history[].created_by`  every Dockerfile line. `COPY . .` or `ADD . /app` with no
                      `.dockerignore` is the tell that the working tree, `.git` and `.env`
                      included, is inside a layer.
  * `config.Labels`   build metadata, often the source repo and commit.

So triage is a few KB per image instead of several hundred MB, and only a scoring hit gets
pulled. One pull of the known-bad image is 499 MB; one config fetch is about 6 KB.

Anonymous pull tokens are free and unauthenticated, which is the whole point: anything this
script can read, anyone can read. Finding it is not the vulnerability, publishing it was.

Usage:
  registry-mine.py --search acme acmecam acmehome       search Docker Hub, rank, triage top hits
  registry-mine.py --repo intelense3600/marriott-updated-be --tag v7     triage one image
  registry-mine.py --program acme                     derive search terms from targets/acme/SCOPE.txt
  registry-mine.py --search wolt --json               machine-readable for a worker

Nothing here authenticates as anyone, pulls a layer, or runs an image.
"""
import argparse, json, os, re, sys, urllib.parse, urllib.request

HUB = "https://hub.docker.com/v2"
AUTH = "https://auth.docker.io/token"
REG = "https://registry-1.docker.io/v2"
UA = {"User-Agent": "bb-registry-mine/1.0"}
MANIFEST_ACCEPT = ", ".join([
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
])

# Dockerfile shapes that put the working tree, and therefore .git and .env, into a layer
# Only a copy of the WHOLE build context risks dragging .git and .env in. `COPY src ./src` is a
# deliberate scoped copy and is good practice - counting it flagged the OFFICIAL initech images as
# leaks on the first run, which is exactly the cry-wolf that gets a scanner ignored.
BULK_COPY = re.compile(r"\b(COPY|ADD)\s+(--\S+\s+)*(\.|\./|\*)\s+\S", re.I)
# secret-shaped ENV names, checked on the NAME so no value is ever printed
SECRET_ENV = re.compile(
    r"(PASSW|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE_KEY|CREDENTIAL|_KEY$|^KEY$|AUTH|SESSION|"
    r"SALT|DSN|CONN(ECTION)?_?STR)", re.I)
# names that merely CONTAIN a scary word but are ordinary config. PRIVATE_HOSTNAME flagged the
# program-36 product images; GPG_KEY is the public verification key in every official node image.
SECRET_ENV_EXCLUDE = re.compile(
    r"(_HOSTNAME$|_HOST$|_DIR$|_PATH$|_FILE$|_URL$|_PORT$|^GPG_KEY$|_ENABLED$|_MODE$)", re.I)
# a value that is itself obviously a credential, matched so we can SAY it is there
SECRET_VALUE = re.compile(
    r"(-----BEGIN|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.|"
    r"ATCTT3|sk_live_|ghp_|xox[baprs]-|AIza[0-9A-Za-z_-]{20,})")


def get(url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def token_for(repo):
    q = urllib.parse.urlencode({"service": "registry.docker.io", "scope": f"repository:{repo}:pull"})
    return get(f"{AUTH}?{q}")["token"]


def image_config(repo, tag):
    """Fetch ONLY the config blob. A few KB, no layers, no pull."""
    if "/" not in repo:
        repo = "library/" + repo
    tok = token_for(repo)
    h = {"Authorization": f"Bearer {tok}", "Accept": MANIFEST_ACCEPT}
    man = get(f"{REG}/{repo}/manifests/{urllib.parse.quote(tag)}", h)
    if "manifests" in man:                       # multi-arch index, take the first amd64
        pick = next((m for m in man["manifests"]
                     if m.get("platform", {}).get("architecture") == "amd64"), man["manifests"][0])
        man = get(f"{REG}/{repo}/manifests/{pick['digest']}", h)
    digest = man["config"]["digest"]
    cfg = get(f"{REG}/{repo}/blobs/{digest}", {"Authorization": f"Bearer {tok}"})
    layers = man.get("layers", [])
    return cfg, sum(l.get("size", 0) for l in layers), len(layers)


def triage(repo, tag):
    """Score one image from its config alone. Never prints a secret VALUE."""
    try:
        cfg, size, nlayers = image_config(repo, tag)
    except Exception as e:
        return {"repo": repo, "tag": tag, "error": f"{type(e).__name__}: {str(e)[:90]}"}

    env = (cfg.get("config") or {}).get("Env") or []
    labels = (cfg.get("config") or {}).get("Labels") or {}
    hist = [h.get("created_by", "") for h in cfg.get("history", [])]

    secret_names, valued = [], 0
    for e in env:
        name = e.split("=", 1)[0]
        val = e.split("=", 1)[1] if "=" in e else ""
        if SECRET_ENV.search(name) and not SECRET_ENV_EXCLUDE.search(name):
            secret_names.append(name)
        if SECRET_VALUE.search(val):
            valued += 1

    bulk = [h.strip()[:110] for h in hist if BULK_COPY.search(h)]
    # CALIBRATED 2026-10-03 against ground truth. Two images with a CONFIRMED live Google key
    # (intelense3600/marriott-updated-be:v7 and ken-v2-be-sheraton-test:latest) scored 33 on the
    # first weighting and fell below the pull threshold. Their secrets live in a .env FILE inside
    # a layer, not in an ENV instruction, so the ENV signals never fired. The signal that did fire
    # on both, and that actually predicts the leak, is a bulk COPY into a fat application image:
    # the working tree went in whole, .git and .env included. Weighted accordingly.
    score = 0
    score += 40 if valued else 0                      # a credential literally in ENV
    score += 12 * min(len(secret_names), 3)           # secret-shaped ENV names
    score += 35 if bulk else 0                        # COPY . . = the whole tree is in a layer
    score += 10 if (bulk and size > 300 * 1024 * 1024) else 0   # fat AND unpruned, the real tell

    return {
        "repo": repo, "tag": tag, "score": score,
        "size_mb": round(size / 1048576, 1), "layers": nlayers,
        "bulk_copy": bulk[:3],
        "secret_env_names": secret_names[:8],
        "env_values_that_look_like_credentials": valued,
        "source_label": labels.get("org.opencontainers.image.source") or labels.get("source"),
        "revision": labels.get("org.opencontainers.image.revision"),
        "verdict": ("PULL AND INSPECT" if score >= 40 else
                    "worth a look" if score >= 20 else "low signal"),
    }


def search(terms, pages=1):
    out = {}
    for t in terms:
        for p in range(1, pages + 1):
            q = urllib.parse.urlencode({"query": t, "page": p, "page_size": 25})
            try:
                d = get(f"{HUB}/search/repositories/?{q}")
            except Exception:
                continue
            for r in d.get("results", []):
                name = r.get("repo_name")
                if name and name not in out:
                    out[name] = {"repo": name, "stars": r.get("star_count", 0),
                                 "pulls": r.get("pull_count", 0),
                                 "desc": (r.get("short_description") or "")[:70],
                                 "matched": t}
    return list(out.values())


def tags_for(repo):
    try:
        d = get(f"{HUB}/repositories/{repo}/tags/?page_size=10")
        return [t["name"] for t in d.get("results", [])]
    except Exception:
        return []


def terms_from_program(prog):
    """Derive search terms from a program's scope file: brand labels out of its hostnames."""
    p = fos.path.join(os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "targets/{prog}/SCOPE.txt")
    if not os.path.exists(p):
        return [prog]
    hosts = set()
    for line in open(p, errors="replace"):
        if line.startswith("#") or not line.strip():
            continue
        m = re.match(r"^\w+\s+(\S+)", line)
        if m:
            h = re.sub(r"^https?://", "", m.group(1)).split("/")[0].lstrip("*.")
            if "." in h:
                hosts.add(h)
    labels = set()
    for h in hosts:
        parts = h.split(".")
        if len(parts) >= 2:
            labels.add(parts[-2])          # the registrable label
    labels.discard("com"); labels.discard("co")
    return [prog] + sorted(labels)[:6]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--search", nargs="+")
    ap.add_argument("--program")
    ap.add_argument("--repo")
    ap.add_argument("--tag", default="latest")
    ap.add_argument("--top", type=int, default=12, help="how many search hits to triage")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    if a.repo:
        res = [triage(a.repo, a.tag)]
    else:
        terms = a.search or terms_from_program(a.program or "")
        if not terms:
            ap.error("need --search, --program or --repo")
        print(f"search terms: {' '.join(terms)}", file=sys.stderr)
        hits = search(terms)
        # RELEVANCE GATE. A search for "visa" returns kongedu/kongair and 1337kavin/bg-helper,
        # which belong to nobody we are hunting. An image is only worth triaging when a search
        # term appears in its NAMESPACE or its repository name.
        def relevant(r):
            ns, _, nm = r["repo"].partition("/")
            return any(t.lower() in ns.lower() or t.lower() in nm.lower() for t in terms)
        dropped = [r for r in hits if not relevant(r)]
        hits = [r for r in hits if relevant(r)]
        if dropped:
            print(f"relevance gate dropped {len(dropped)} unrelated namespaces", file=sys.stderr)
        hits.sort(key=lambda r: -(r["pulls"] or 0))
        print(f"{len(hits)} candidate repositories, triaging top {a.top} by pulls",
              file=sys.stderr)
        res = []
        for h in hits[:a.top]:
            tags = tags_for(h["repo"]) or ["latest"]
            r = triage(h["repo"], tags[0])
            r["pulls"] = h["pulls"]
            r["matched_term"] = h["matched"]
            res.append(r)

    res.sort(key=lambda r: -(r.get("score") or 0))
    if a.json:
        print(json.dumps(res, indent=1)); return
    for r in res:
        if r.get("error"):
            print(f"  --   {r['repo']}:{r['tag']}  {r['error']}"); continue
        print(f"\n[{r['score']:3d}] {r['repo']}:{r['tag']}   {r['verdict']}")
        print(f"      {r['size_mb']} MB, {r['layers']} layers, pulls={r.get('pulls','?')}")
        if r["bulk_copy"]:
            print(f"      bulk copy, so the working tree is in a layer:")
            for b in r["bulk_copy"]:
                print(f"        {b}")
        if r["secret_env_names"]:
            print(f"      secret-shaped ENV names: {', '.join(r['secret_env_names'])}")
        if r["env_values_that_look_like_credentials"]:
            print(f"      *** {r['env_values_that_look_like_credentials']} ENV value(s) match a "
                  f"credential pattern, baked into the image ***")
        if r["source_label"]:
            print(f"      source: {r['source_label']} @ {r.get('revision')}")


if __name__ == "__main__":
    main()
