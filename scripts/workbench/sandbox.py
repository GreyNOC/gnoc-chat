#!/usr/bin/env python3
"""sandbox - emulated surfaces for the hunt rig: test what is not a live web host.

  sandbox oss <program> <repo-url|image> [--version X] [--name N] [--port CPORT ...] [--env K=V ...]
                                         [--lab-only] [--cmd "..."]
        start an in-scope open-source product (container) bound to 127.0.0.1 only
  sandbox evm <program> [--chain <id|name>] [--block N] [--rpc URL] [--no-fork] [--name evm]
        anvil on 127.0.0.1 forking the program's chain + a forge test skeleton
  sandbox evm test <program> [--name evm] [-- forge args]   guard + forge test against the local anvil
  sandbox evm guard <program> [--name evm]                  fail if any lab file names a non-local RPC
  sandbox electron <program> <path|url> [--name N] [--headless] [--block-oos] [--env K=V ...]
        run an Electron app: DevTools on 127.0.0.1, traffic through mitmdump -> flows.jsonl, asar dump
  sandbox ext <program> <crx|dir> [--name N] [--headless] [--block-oos] [--url START]
        load an unpacked extension in a throwaway Chrome profile, proxied; EXT.md trust surface
  sandbox ls                                  every lab and its live state
  sandbox down all | <program> [<name>]       tear down (files are kept, processes/containers go)
  sandbox <kind> ls | sandbox <kind> down <program> [<name>] | all
  sandbox selftest [--image REF]              local-only proof of every surface (no target traffic)

Labs live in targets/<program>/labs/<name>/ with LAB.md + lab.json. Nothing listens on anything
but 127.0.0.1; no lab ever broadcasts to a real chain. A lab proves the SINK; a filable finding also
needs the production leg (Manual T-239). Full doc: scripts/workbench/README-sandbox.md.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import sb_common as C  # noqa: E402

KINDS = ("oss", "evm", "electron", "ext")


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", s.lower()).strip("-")[:40] or "lab"


def _kv(items):
    out = {}
    for it in items or []:
        if "=" not in it:
            C.die(f"--env wants K=V, got {it!r}")
        k, v = it.split("=", 1)
        out[k] = v
    return out


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


# ================================================================ OSS LAB ======================
def _pw():
    return "lab-" + secrets.token_urlsafe(12)


# Known products: repo -> image, plus the first-run env that seeds a real admin. The creds are
# generated per lab and are the LAB'S OWN (never a vendor or real-user credential).
PRESETS = {
    "gatewayco": {"repos": ["gatewayco/gatewayco"], "image": "docker.io/library/gatewayco", "ports": [8000, 8001],
             "env": {"KONG_DATABASE": "off", "KONG_PROXY_LISTEN": "0.0.0.0:8000",
                     "KONG_ADMIN_LISTEN": "0.0.0.0:8001", "KONG_ADMIN_GUI_LISTEN": "off",
                     "KONG_PROXY_ACCESS_LOG": "/dev/stdout", "KONG_ADMIN_ACCESS_LOG": "/dev/stdout"},
             "note": "DB-less. Admin API on the 8001 mapping has NO auth by design (it is the lab's)."},
    "grafana": {"repos": ["grafana/grafana"], "image": "docker.io/grafana/grafana", "ports": [3000],
                "env": {"GF_SECURITY_ADMIN_USER": "admin", "GF_SECURITY_ADMIN_PASSWORD": "{pw}"}},
    "gitea": {"repos": ["go-gitea/gitea"], "image": "docker.io/gitea/gitea", "ports": [3000],
              "env": {"GITEA__security__INSTALL_LOCK": "true", "GITEA__database__DB_TYPE": "sqlite3"},
              "post": ["su", "git", "-c", "gitea admin user create --admin --username labadmin "
                       "--password {pw} --email lab@example.invalid --must-change-password=false"],
              "user": "labadmin"},
    "keycloak": {"repos": ["keycloak/keycloak"], "image": "quay.io/keycloak/keycloak", "ports": [8080],
                 "cmd": ["start-dev"],
                 "env": {"KC_BOOTSTRAP_ADMIN_USERNAME": "admin", "KC_BOOTSTRAP_ADMIN_PASSWORD": "{pw}"}},
    "nextcloud": {"repos": ["nextcloud/server"], "image": "docker.io/library/nextcloud", "ports": [80],
                  "env": {"NEXTCLOUD_ADMIN_USER": "admin", "NEXTCLOUD_ADMIN_PASSWORD": "{pw}",
                          "SQLITE_DATABASE": "nextcloud", "NEXTCLOUD_TRUSTED_DOMAINS": "127.0.0.1 localhost"}},
    "minio": {"repos": ["minio/minio"], "image": "docker.io/minio/minio", "ports": [9000, 9001],
              "cmd": ["server", "/data", "--console-address", ":9001"],
              "env": {"MINIO_ROOT_USER": "labadmin", "MINIO_ROOT_PASSWORD": "{pw}"}},
    "jenkins": {"repos": ["jenkinsci/jenkins"], "image": "docker.io/jenkins/jenkins", "ports": [8080],
                "tag_default": "lts",
                "creds_cmd": ["cat", "/var/jenkins_home/secrets/initialAdminPassword"],
                "note": "Initial admin password is read from the container after start."},
}


def _preset_for(src: str) -> tuple[str, dict] | tuple[None, None]:
    s = src.lower()
    for name, p in PRESETS.items():
        if any(r in s for r in p["repos"]) or p["image"].split("/", 1)[-1].replace("library/", "") in s:
            return name, p
    return None, None


def _gh_repo(src: str):
    m = re.match(r"(?:https?://)?(?:www\.)?github\.com/([^/]+)/([^/#?]+)", src)
    return (m.group(1), m.group(2).removesuffix(".git")) if m else None


def _gh_latest(owner, repo) -> str | None:
    try:
        req = urllib.request.Request(f"https://api.github.com/repos/{owner}/{repo}/releases/latest",
                                     headers={"Accept": "application/vnd.github+json",
                                              "User-Agent": "gnoc-sandbox"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.load(r).get("tag_name")
    except Exception:
        return None


def _pull(ref: str) -> bool:
    if _run([C.CONTAINER, "image", "exists", ref]).returncode == 0:
        return True
    print(f"  pulling {ref} ...")
    return _run([C.CONTAINER, "pull", "-q", ref], timeout=1800).returncode == 0


def _image_meta(ref: str) -> dict:
    r = _run([C.CONTAINER, "image", "inspect", ref])
    if r.returncode != 0:
        return {}
    j = json.loads(r.stdout)[0]
    cfg = j.get("Config") or {}
    labels = cfg.get("Labels") or {}
    ver = labels.get("org.opencontainers.image.version") or ""
    # a product *_VERSION env (KONG_VERSION=3.15.0.6) beats a CI build-id label
    env_ver = next((e.split("=", 1)[1] for e in cfg.get("Env") or []
                    if re.match(r"^[A-Z][A-Z0-9_]*_VERSION=v?\d+\.\d+", e)
                    and not e.startswith(("PYTHON", "GPG", "NODE", "LUA", "OPENRESTY", "GOLANG"))), "")
    if env_ver and not re.match(r"^v?\d+\.\d+", ver):
        ver = env_ver
    return {"id": j.get("Id", "")[:12], "digest": j.get("Digest", ""),
            "repo_digests": j.get("RepoDigests") or [], "version": ver,
            "exposed": sorted(int(k.split("/")[0]) for k in (cfg.get("ExposedPorts") or {})),
            "source": labels.get("org.opencontainers.image.source", "")}


def oss_up(a):
    C.program_dir(a.program, create=a.program.startswith("_"))
    preset_name, preset = _preset_for(a.src)
    gh = _gh_repo(a.src)
    version = a.version
    image = None
    if gh and not preset:
        version = version or _gh_latest(*gh)
        cands = [f"ghcr.io/{gh[0]}/{gh[1]}".lower(), f"docker.io/{gh[0]}/{gh[1]}".lower()]
        for base in cands:
            for tag in ([version, version.lstrip("v")] if version else ["latest"]):
                if tag and _pull(f"{base}:{tag}"):
                    image = f"{base}:{tag}"
                    break
            if image:
                break
        if not image:
            C.die(f"no published image for {gh[0]}/{gh[1]} at {version or 'latest'} on ghcr.io or "
                  "docker.io. Build it yourself and pass the local image ref "
                  "(podman build -t localhost/<name>:<ver> <clone>), then `sandbox oss` it.")
    elif preset and (gh or "/" not in a.src.split(":")[0] or a.src.lower() in preset["repos"]):
        tag = version or (gh and _gh_latest(*gh) or "").lstrip("v") or preset.get("tag_default", "latest")
        image = f"{preset['image']}:{tag}"
        if not _pull(image):
            C.die(f"could not pull {image}")
        version = tag
    else:
        image = a.src  # an image ref (name:tag, name@sha256:..., or a local image id)
        if not _pull(image):
            C.die(f"image {image} not present and pull failed")

    meta = _image_meta(image)
    if not preset:  # a bare image id: resolve the product from the image's own metadata
        preset_name, preset = _preset_for(" ".join([meta.get("source") or ""] + meta.get("repo_digests", [])))
    version = version or meta.get("version") or "unknown"
    name = _slug(a.name or (preset_name or (gh[1] if gh else image.split("/")[-1].split(":")[0].split("@")[0])))
    d = C.lab_dir(a.program, name)
    st = C.load_state(d)
    if st and C.lab_live(st):
        C.die(f"lab {a.program}/{name} is already up; `sandbox down {a.program} {name}` first")

    # T-239: does the program list this asset? No row = lab-only ceiling, refused unless asked for.
    needles = [f"{gh[0]}/{gh[1]}" if gh else "", (meta.get("source") or "").split("github.com/")[-1],
               image.split("@")[0].rsplit(":", 1)[0].split("/")[-1]]
    scope_row = next((n for n in needles if n and C.scope_text_mentions(n, a.program)), None)
    if not scope_row and not a.lab_only:
        C.die(f"no SCOPE.txt row for {a.src} in targets/{a.program}/. A lab for an asset the program "
              "does not list has no production leg (T-239). Re-run with --lab-only to build it anyway.")

    ports = a.port or (preset or {}).get("ports") or meta.get("exposed") or []
    if not ports:
        C.die("image exposes no port and none given; pass --port <container-port>")
    pw = _pw()
    env = {k: v.replace("{pw}", pw) for k, v in ((preset or {}).get("env") or {}).items()}
    env.update(_kv(a.env))
    cmd = a.cmd.split() if a.cmd else (preset or {}).get("cmd") or []
    cname = f"sbx-{_slug(a.program)}-{name}"
    mapping = {p: C.free_port() for p in ports}
    for hp in mapping.values():
        assert hp > 0
    d.mkdir(parents=True, exist_ok=True)

    # compose file (the declarative record; podman run below is the launcher so no socket is needed)
    lines = ["# generated by scripts/workbench/sandbox.py - loopback-only lab", "services:",
             f"  {name}:", f"    image: {image}", f"    container_name: {cname}", "    ports:"]
    lines += [f'      - "127.0.0.1:{hp}:{cp}"' for cp, hp in mapping.items()]
    if env:
        lines.append("    environment:")
        lines += [f'      {k}: "{v}"' for k, v in env.items()]
    if cmd:
        lines.append(f"    command: {json.dumps(cmd)}")
    (d / "compose.yaml").write_text("\n".join(lines) + "\n")
    os.chmod(d / "compose.yaml", 0o600)

    run = [C.CONTAINER, "run", "-d", "--name", cname, "--label", f"gnoc_sandbox={a.program}/{name}"]
    for cp, hp in mapping.items():
        run += ["-p", f"127.0.0.1:{hp}:{cp}"]
    for k, v in env.items():
        run += ["-e", f"{k}={v}"]
    run += [image] + cmd
    _run([C.CONTAINER, "rm", "-f", cname])
    r = _run(run)
    if r.returncode != 0:
        C.die(f"container start failed: {r.stderr.strip()[:400]}")

    # hard check: every published binding is loopback, else tear down at once
    pr = _run([C.CONTAINER, "port", cname]).stdout
    bad = [ln for ln in pr.splitlines() if ln.strip() and "127.0.0.1:" not in ln]
    if bad:
        _run([C.CONTAINER, "rm", "-f", cname])
        C.die(f"non-loopback binding detected, lab destroyed: {bad}")

    up = {cp: C.wait_port(hp, a.wait) for cp, hp in mapping.items()}
    creds = {}
    p = preset or {}
    if any(k.endswith(("PASSWORD", "PASS")) for k in env):
        u = next((v for k, v in env.items() if k.endswith(("USER", "USERNAME"))), p.get("user", "admin"))
        creds = {"user": u, "password": pw}
    if p.get("post"):
        time.sleep(3)
        pr = _run([C.CONTAINER, "exec", cname] + [x.replace("{pw}", pw) for x in p["post"]])
        creds = {"user": p.get("user"), "password": pw, "post_rc": pr.returncode}
    if p.get("creds_cmd"):
        for _ in range(30):
            pr = _run([C.CONTAINER, "exec", cname] + p["creds_cmd"])
            if pr.returncode == 0 and pr.stdout.strip():
                creds = {"user": "admin", "password": pr.stdout.strip()}
                break
            time.sleep(2)

    st = {"kind": "oss", "program": a.program, "name": name, "status": "up", "created": C.now(),
          "image": image, "version": version, "digest": meta.get("digest"),
          "repo_digests": meta.get("repo_digests"), "containers": [cname],
          "ports": {str(cp): hp for cp, hp in mapping.items()}, "pids": {},
          "scope_row": scope_row, "lab_only": not bool(scope_row), "preset": preset_name}
    C.save_state(d, st)
    if creds:
        (d / "CREDS.lab").write_text(json.dumps(creds, indent=2) + "\n")
        os.chmod(d / "CREDS.lab", 0o600)
    urls = [f"http://127.0.0.1:{hp}/  (container :{cp}, {'UP' if up[cp] else 'not answering yet'})"
            for cp, hp in mapping.items()]
    md = [f"# LAB {a.program}/{name} (oss)", "",
          f"- Created: {st['created']}", f"- Image: `{image}`", f"- Version: {version}",
          f"- Digest: `{meta.get('digest')}`", f"- Repo digests: `{meta.get('repo_digests')}`",
          f"- Image source label: {meta.get('source') or '(none)'}",
          f"- Container: `{cname}`", f"- Compose (record): `{d / 'compose.yaml'}`", "",
          "## Reach it (loopback only, never published)", ""] + [f"- {u}" for u in urls]
    if creds:
        md += ["", f"- Lab admin credentials: `{d / 'CREDS.lab'}` (generated for THIS lab; they are the "
               "lab's own first-run creds, not a vendor or user credential)"]
    if p.get("note"):
        md += ["", f"- Note: {p['note']}"]
    md += ["", "## Production leg (Manual T-239)", "",
           (f"- SCOPE.txt row matched: `{scope_row}`. A lab proves the SINK only; the filable finding also "
            "needs the production leg (vendor-hosted deployment, the released package the program lists, "
            "or an owned deployment on the vendor platform).") if scope_row else
           "- NO SCOPE.txt row: LAB-ONLY. Ceiling is a local-lab report; do not open ahead of a lane "
           "that holds its production leg.",
           "", "## Commands", "",
           f"- logs: `podman logs -f {cname}`", f"- shell: `podman exec -it {cname} sh`",
           f"- down: `gnoc sandbox down {a.program} {name}`", ""]
    (d / "LAB.md").write_text("\n".join(md))
    print(f"oss lab {a.program}/{name} up: " + "; ".join(urls))
    print(f"  LAB.md {d / 'LAB.md'}")


# ================================================================ EVM FORK =====================
CHAIN_IDS = {"ethereum": 1, "mainnet": 1, "optimism": 10, "bsc": 56, "gnosis": 100, "polygon": 137,
             "base": 8453, "arbitrum": 42161, "celo": 42220, "avalanche": 43114, "linea": 59144,
             "ink": 57073, "berachain": 80094, "blast": 81457, "scroll": 534352, "local": 31337}


def _explorer_rpcs() -> dict:
    p = C.WS / "scripts/immunefi-fetch.py"
    try:
        spec = importlib.util.spec_from_file_location("immunefi_fetch", p)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return {chain: rpc for chain, rpc in m.EXPLORER.values()}
    except Exception:
        return {}


def _scope_evm(program: str):
    """(chains, {chain: rpc_host}, [(addr, chain, label)]) parsed from the immunefi-scope.sh layout."""
    sf = C.scope_file(program)
    chains, rpcs, addrs, sect = [], {}, [], ""
    if not sf.exists():
        return chains, rpcs, addrs
    for line in sf.read_text(errors="replace").splitlines():
        s = line.strip()
        if s.startswith("# ---"):
            sect = s.lower()
            continue
        if not s or s.startswith("#"):
            continue
        body, _, com = s.partition("#")
        tok = body.split()[0] if body.split() else ""
        if "in-scope chains" in sect:
            chains.append(tok.lower())
        elif "fork rpc" in sect:
            rpcs[com.strip().split()[0].lower() if com.strip() else ""] = tok
        m = re.search(r"0x[a-fA-F0-9]{40}", tok)
        if m:
            parts = com.strip().split(None, 1)
            addrs.append((m.group(0), parts[0].lower() if parts else "", parts[1] if len(parts) > 1 else ""))
    return chains, rpcs, addrs


def _rpc(port, method, params=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}", data=json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode(),
        headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r).get("result")


FORK_TEST = """// SPDX-License-Identifier: UNLICENSED
// Generated by scripts/workbench/sandbox.py for {program}. FORK-ONLY: every call goes to the local
// anvil (rpc_endpoints.sandbox in foundry.toml). Never add --broadcast against a real RPC
// (Immunefi: mainnet or public-testnet testing is a permanent ban).
pragma solidity ^0.8.20;

interface Vm {{
    function rpcUrl(string calldata) external view returns (string memory);
    function createSelectFork(string calldata) external returns (uint256);
    function createSelectFork(string calldata, uint256) external returns (uint256);
    function deal(address, uint256) external;
    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
    function label(address, string calldata) external;
    function warp(uint256) external;
    function roll(uint256) external;
}}

contract SandboxBase {{
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant FORK_BLOCK = {block};
    uint256 internal constant CHAIN_ID = {chain_id};
{consts}
    address internal attacker = address(0xA77AC4E2);

    function _isLocal(string memory u) internal pure returns (bool) {{
        bytes memory b = bytes(u);
        bytes memory p1 = bytes("http://127.0.0.1:");
        bytes memory p2 = bytes("http://localhost:");
        return _startsWith(b, p1) || _startsWith(b, p2);
    }}

    function _startsWith(bytes memory b, bytes memory p) internal pure returns (bool) {{
        if (b.length < p.length) return false;
        for (uint256 i = 0; i < p.length; i++) if (b[i] != p[i]) return false;
        return true;
    }}

    function setUp() public virtual {{
        string memory url = vm.rpcUrl("sandbox");
        require(_isLocal(url), "SANDBOX GUARD: rpc is not the local anvil");
        vm.createSelectFork(url{fork_arg});
        require(block.chainid == CHAIN_ID, "SANDBOX GUARD: unexpected chain id");
        vm.label(attacker, "attacker");
        vm.deal(attacker, 100 ether);
    }}
}}

contract SandboxForkTest is SandboxBase {{
    function test_sandbox_is_local() public view {{
        require(block.chainid == CHAIN_ID, "chain");
        require(block.number >= FORK_BLOCK, "block");
    }}

    // CLASS HUNTERS: copy this function per hypothesis. State the invariant, take the attacker
    // action through the real in-scope contract (constants above), assert the terminal balance /
    // ownership / state delta. The test must FAIL on a fixed build and PASS here (the PoC).
    function test_hypothesis_TODO() public {{
        vm.startPrank(attacker);
        // uint256 before = IERC20(TOKEN).balanceOf(attacker);
        // ... attacker actions against in-scope contracts ...
        // assertGt(IERC20(TOKEN).balanceOf(attacker), before);
        vm.stopPrank();
    }}
}}
"""


def evm_up(a):
    C.program_dir(a.program, create=a.program.startswith("_"))
    anvil = C.WB_BIN / "anvil"
    if not anvil.exists():
        C.die("anvil missing: see README-sandbox.md (Foundry is installed under "
              "~/.local/opt/gnoc-workbench via the @foundry-rs npm packages)")
    chains, rpcs, addrs = _scope_evm(a.program)
    rpc = None
    if a.no_fork:
        chain, chain_id = "local", 31337
    else:
        want = (a.chain or "").lower()
        if want.isdigit():
            chain = next((k for k, v in CHAIN_IDS.items() if v == int(want)), want)
        else:
            chain = want or (chains[0] if len(chains) == 1 else "")
        if not chain:
            C.die(f"pick a chain with --chain; SCOPE.txt lists {chains or 'none'}")
        chain_id = CHAIN_IDS.get(chain)
        rpc = a.rpc or (("https://" + rpcs[chain]) if rpcs.get(chain) else _explorer_rpcs().get(chain))
        if not rpc:
            C.die(f"no fork RPC known for chain {chain}; pass --rpc <archive-rpc> (must be in SCOPE.txt)")
        C.require_scope(rpc, a.program, "fork RPC")
    name = _slug(a.name)
    d = C.lab_dir(a.program, name)
    st = C.load_state(d)
    if st and C.lab_live(st):
        C.die(f"lab {a.program}/{name} already up on 127.0.0.1:{st['ports'].get('rpc')}")
    port = C.free_port()
    cmd = [str(anvil), "--host", "127.0.0.1", "--port", str(port), "--silent"]
    if rpc:
        cmd += ["--fork-url", rpc]
        if a.block:
            cmd += ["--fork-block-number", str(a.block)]
    else:
        cmd += ["--chain-id", "31337"]
    d.mkdir(parents=True, exist_ok=True)
    pid = C.spawn(cmd, d / "anvil.log")
    if not C.wait_port(port, 90):
        C.kill_group(pid)
        C.die(f"anvil did not start, see {d / 'anvil.log'}")
    got_chain = int(_rpc(port, "eth_chainId"), 16)
    block = int(_rpc(port, "eth_blockNumber"), 16)
    chain_id = chain_id or got_chain
    if chain_id != got_chain:
        C.kill_group(pid)
        C.die(f"fork chain id {got_chain} != expected {chain_id} for {chain}")
    bad = C.assert_loopback_listeners(pid)
    if bad:
        C.kill_group(pid)
        C.die(f"anvil listening off-loopback {bad}; killed")

    mine = [x for x in addrs if not x[1] or x[1] == chain]
    consts = "".join(f"    address internal constant C{i}_{_slug(lbl or 'contract').replace('-', '_').upper()[:28]}"
                     f" = {_checksum(addr)}; // {lbl}\n" for i, (addr, _c, lbl) in enumerate(mine[:60]))
    (d / "src").mkdir(exist_ok=True)
    (d / "test").mkdir(exist_ok=True)
    (d / "src/.keep").write_text("")
    (d / "foundry.toml").write_text(
        "[profile.default]\nsrc = 'src'\ntest = 'test'\nout = 'out'\nlibs = ['lib']\n"
        "auto_detect_solc = true\noffline = false\n\n"
        f"[rpc_endpoints]\nsandbox = 'http://127.0.0.1:{port}'\n")
    test_f = d / "test/Fork.t.sol"
    if not test_f.exists() or a.reset_test:
        test_f.write_text(FORK_TEST.format(program=a.program, block=block, chain_id=chain_id, consts=consts,
                                           fork_arg="" if not rpc else ", FORK_BLOCK"))
    (d / "lab.env").write_text(f"export ETH_RPC_URL=http://127.0.0.1:{port}\n"
                               f"export FOUNDRY_ETH_RPC_URL=http://127.0.0.1:{port}\n"
                               f"export SANDBOX_CHAIN_ID={chain_id}\nexport SANDBOX_FORK_BLOCK={block}\n")
    st = {"kind": "evm", "program": a.program, "name": name, "status": "up", "created": C.now(),
          "chain": chain, "chain_id": chain_id, "fork_rpc_host": C.extract_host(rpc) if rpc else None,
          "fork_block": block, "ports": {"rpc": port}, "pids": {"anvil": pid}, "containers": [],
          "anvil_version": _run([str(anvil), "--version"]).stdout.split("\n")[0]}
    C.save_state(d, st)
    md = [f"# LAB {a.program}/{name} (evm)", "",
          f"- Created: {st['created']}", f"- {st['anvil_version']}",
          f"- Chain: {chain} (id {chain_id})",
          f"- Fork: {'NONE (local chain)' if not rpc else C.extract_host(rpc)} at block **{block}**",
          f"- Local RPC: `http://127.0.0.1:{port}` (the ONLY RPC any lab script may use)",
          f"- Env: `source {d / 'lab.env'}` sets ETH_RPC_URL for cast / forge", "",
          "## In-scope contracts on this chain (from SCOPE.txt)", ""]
    md += [f"- `{addr}` {lbl}" for addr, _c, lbl in mine] or ["- (none listed for this chain)"]
    md += ["", "## Forge skeleton", "",
           f"- `{test_f}`: SandboxBase guards setUp (RPC must be 127.0.0.1, chain id must match), forks "
           "the local anvil at FORK_BLOCK, funds an attacker. Class hunters (defi-accounting, oracle, "
           "contract-authz, evm-execution, ...) copy `test_hypothesis_TODO` per hypothesis.",
           f"- Run: `gnoc sandbox evm test {a.program}` (guard first, then forge test -vvv).",
           "- No transaction is ever broadcast to a real network: `sandbox evm guard` fails on any "
           "non-loopback RPC URL or `--broadcast` against one in this directory.",
           "- Immunefi report PoC = this forge test (runnable fork PoC), never a live tx.", "",
           f"- down: `gnoc sandbox down {a.program} {name}`", ""]
    (d / "LAB.md").write_text("\n".join(md))
    print(f"evm lab {a.program}/{name} up: http://127.0.0.1:{port} chain {chain_id} block {block}")
    print(f"  LAB.md {d / 'LAB.md'}")


def _checksum(addr: str) -> str:
    """EIP-55 via cast if present (solc rejects a non-checksummed address literal)."""
    r = _run([str(C.WB_BIN / "cast"), "to-check-sum-address", addr])
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else addr


URL_RE = re.compile(r"(?:https?|wss?)://([A-Za-z0-9.\-\[\]:]+)")


def evm_guard(program: str, name: str, quiet=False) -> int:
    d = C.lab_dir(program, name)
    if not d.is_dir():
        C.die(f"no lab {program}/{name}")
    bad = []
    for f in d.rglob("*"):
        if not f.is_file() or any(p in f.parts for p in ("out", "cache", "lib", "broadcast")) \
                or f.suffix not in (".sol", ".toml", ".sh", ".env", ".py", ".js", ".ts", ".json", ".md"):
            continue
        if f.name in ("lab.json", "LAB.md"):
            continue
        txt = f.read_text(errors="replace")
        for m in URL_RE.finditer(txt):
            host = m.group(1).split(":")[0].strip("[]")
            if not C.LOOPBACK(host) and "--fork-url" not in txt[max(0, m.start() - 40):m.start()]:
                line = txt.count("\n", 0, m.start()) + 1
                bad.append(f"{f.relative_to(d)}:{line} {m.group(0)}")
        if re.search(r"--broadcast", txt) and re.search(r"--rpc-url\s+(?!http://(127\.|localhost))", txt):
            bad.append(f"{f.relative_to(d)}: --broadcast with a non-local --rpc-url")
    st = C.load_state(d) or {}
    port = (st.get("ports") or {}).get("rpc")
    if not port or not C.wait_port(port, 2):
        bad.append(f"local anvil not answering on 127.0.0.1:{port}")
    if bad:
        print("SANDBOX GUARD FAIL:\n  " + "\n  ".join(bad))
        return 1
    if not quiet:
        print(f"guard ok: only 127.0.0.1:{port} in {d}")
    return 0


def evm_test(a):
    name = _slug(a.name)
    if evm_guard(a.program, name):
        sys.exit(1)
    d = C.lab_dir(a.program, name)
    st = C.load_state(d)
    env = dict(os.environ, ETH_RPC_URL=f"http://127.0.0.1:{st['ports']['rpc']}")
    env.pop("FOUNDRY_FORK_URL", None)
    cmd = [str(C.WB_BIN / "forge"), "test", "-vvv", "--root", str(d)] + (a.forge_args or [])
    print("+ " + " ".join(cmd))
    r = subprocess.run(cmd, env=env)
    sys.exit(r.returncode)


# ================================================================ ELECTRON =====================
def _download(url: str, program: str, dest_dir: Path) -> Path:
    C.require_scope(url, program, "app download")
    dest_dir.mkdir(parents=True, exist_ok=True)
    fn = dest_dir / (re.sub(r"[?#].*$", "", url).rstrip("/").split("/")[-1] or "download.bin")
    print(f"  downloading {url} -> {fn}")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 gnoc-sandbox"})
    with urllib.request.urlopen(req, timeout=600) as r, open(fn, "wb") as fh:
        shutil.copyfileobj(r, fh)
    return fn


def _is_elf(p: Path) -> bool:
    try:
        with open(p, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def _find_electron_exe(root: Path) -> tuple[Path | None, Path | None]:
    """(executable, app.asar or app dir) inside an extracted Electron distribution."""
    for asar in sorted(root.rglob("resources/app.asar")) + sorted(root.rglob("resources/app")):
        base = asar.parent.parent
        exes = [f for f in base.iterdir() if f.is_file() and os.access(f, os.X_OK) and _is_elf(f)
                and not f.name.startswith(("chrome", "crashpad", "lib"))]
        if exes:
            exes.sort(key=lambda f: -f.stat().st_size)
            return exes[0], asar
    return None, None


def _resolve_electron(src: str, program: str, d: Path):
    """-> (argv prefix, asar path or None, description)."""
    if re.match(r"https?://", src):
        p = _download(src, program, d / "download")
    else:
        p = Path(src).expanduser().resolve()
        if not p.exists():
            C.die(f"{p} does not exist")
    app = d / "app"
    if p.is_dir():
        if (p / "package.json").exists() and not _find_electron_exe(p)[0]:
            return [str(C.ELECTRON_BIN), str(p)], None, f"source app dir run with workbench electron ({p})"
        exe, asar = _find_electron_exe(p)
        if exe:
            return [str(exe)], asar, f"distribution dir {p}"
        C.die(f"{p}: no Electron executable with resources/app.asar and no package.json")
    name = p.name.lower()
    if name.endswith(".appimage"):
        os.chmod(p, 0o755)
        app.mkdir(parents=True, exist_ok=True)
        r = subprocess.run([str(p), "--appimage-extract"], cwd=app, capture_output=True)
        if r.returncode != 0:
            C.die(f"AppImage extract failed: {r.stderr[-300:]!r}")
    elif name.endswith(".deb"):
        app.mkdir(parents=True, exist_ok=True)
        subprocess.run(["dpkg-deb", "-x", str(p), str(app)], check=True)
    elif name.endswith((".tar.gz", ".tgz", ".tar.xz", ".zip")):
        app.mkdir(parents=True, exist_ok=True)
        shutil.unpack_archive(str(p), str(app))
    elif name.endswith(".asar"):
        return [str(C.ELECTRON_BIN), str(p)], p, f"bare asar run with workbench electron ({p})"
    elif _is_elf(p):
        exe, asar = _find_electron_exe(p.parent)
        return [str(p)], asar, f"executable {p}"
    else:
        C.die(f"unsupported input {p} (dir, AppImage, deb, tar/zip, asar, or ELF)")
    exe, asar = _find_electron_exe(app)
    if not exe:
        C.die(f"no Electron executable found under {app}")
    return [str(exe)], asar, f"extracted {p.name} -> {exe}"


def _asar_extract(asar: Path | None, d: Path) -> str:
    if not asar:
        return "no app.asar (source dir or unpacked resources/app)"
    if asar.is_dir():
        return f"resources/app is already unpacked: {asar}"
    out = d / "asar"
    r = _run(["node", str(C.ASAR_JS), "extract", str(asar), str(out)])
    if r.returncode != 0:
        return f"asar extract FAILED: {r.stderr.strip()[:300]}"
    n = sum(1 for _ in out.rglob("*") if _.is_file())
    return f"{n} files extracted to {out}"


def _devtools_version(port: int) -> dict:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=5) as r:
            return json.load(r)
    except Exception:
        return {}


def _devtools_list(port: int) -> list:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=5) as r:
            return json.load(r)
    except Exception:
        return []


def electron_up(a):
    C.program_dir(a.program, create=a.program.startswith("_"))
    if not C.ELECTRON_BIN.exists():
        C.die("workbench electron missing (npm i electron in ~/.local/opt/gnoc-workbench/npm)")
    base = a.name or (Path(a.src).stem if not re.match(r"https?://", a.src) else a.src.rstrip("/").split("/")[-1])
    name = "electron-" + _slug(base)
    d = C.lab_dir(a.program, name)
    st = C.load_state(d)
    if st and C.lab_live(st):
        C.die(f"lab {a.program}/{name} already up")
    d.mkdir(parents=True, exist_ok=True)
    argv, asar, desc = _resolve_electron(a.src, a.program, d)
    asar_note = _asar_extract(asar, d)
    extra = ["--set", "ssl_insecure=true"] if a.insecure_upstream else []
    mpid, mport = C.start_mitm(d, a.program, a.block_oos, extra)
    dport = C.free_port()
    iport = C.free_port()
    proxy = f"http://127.0.0.1:{mport}"
    env = C.gui_env()
    env.update({"HTTPS_PROXY": proxy, "HTTP_PROXY": proxy, "https_proxy": proxy, "http_proxy": proxy,
                "NO_PROXY": "", "no_proxy": "", "NODE_USE_ENV_PROXY": "1",
                "NODE_EXTRA_CA_CERTS": str(C.MITM_CA), "ELECTRON_ENABLE_LOGGING": "1",
                "ELECTRON_DISABLE_SECURITY_WARNINGS": "1"})
    env.update(_kv(a.env))
    flags = [f"--remote-debugging-port={dport}", "--remote-debugging-address=127.0.0.1",
             f"--inspect=127.0.0.1:{iport}",
             f"--proxy-server={proxy}", "--proxy-bypass-list=<-loopback>", "--ignore-certificate-errors",
             f"--user-data-dir={d / 'profile'}", "--no-sandbox"]
    xvfb = shutil.which("xvfb-run")
    display_note = f"DISPLAY {env.get('DISPLAY')}"
    if a.ozone_headless:
        # Electron 38.8.6 SEGFAULTS (exit 139) with ozone headless on this host, measured 2026-10-20;
        # kept as an opt-in for other Electron builds.
        flags += ["--ozone-platform=headless", "--disable-gpu"]
        display_note = "ozone headless"
    elif a.headless and xvfb:
        argv = [xvfb, "-a"] + argv
        display_note = "xvfb-run"
    elif a.headless:
        display_note += " (no Xvfb on this host: --headless falls back to the real display)"
    if a.no_inspect:
        flags = [f for f in flags if not f.startswith("--inspect")]
    if argv[0] == xvfb:
        cmd = argv[:3] + flags + argv[3:] + (a.app_args or [])
    else:
        cmd = argv[:1] + flags + argv[1:] + (a.app_args or [])
    apid = C.spawn(cmd, d / "app.log", env=env)
    ok = C.wait_port(dport, a.wait)
    ver = _devtools_version(dport) if ok else {}
    bad = C.assert_loopback_listeners(apid) + C.assert_loopback_listeners(mpid)
    if bad:
        C.kill_group(apid)
        C.kill_group(mpid)
        C.die(f"off-loopback listener {bad}; lab killed")
    st = {"kind": "electron", "program": a.program, "name": name, "status": "up", "created": C.now(),
          "source": a.src, "argv": cmd, "pids": {"app": apid, "mitmdump": mpid},
          "ports": {"devtools": dport, "node_inspect": None if a.no_inspect else iport, "mitm": mport},
          "containers": [], "browser": ver.get("Browser"), "block_oos": a.block_oos}
    C.save_state(d, st)
    md = [f"# LAB {a.program}/{name} (electron)", "", f"- Created: {st['created']}",
          f"- Input: `{a.src}` ({desc})", f"- Runtime: {ver.get('Browser') or 'DevTools not answering (see app.log)'} on {display_note}",
          f"- DevTools (renderer, CDP): `http://127.0.0.1:{dport}/json/list`",
          f"- Node inspector (main process): {'off' if a.no_inspect else f'127.0.0.1:{iport} (ignored if the app disabled the EnableNodeCliInspectArguments fuse)'}",
          f"- Proxy: mitmdump on `{proxy}`, CA `{C.MITM_CA}` trusted via NODE_EXTRA_CA_CERTS + "
          "--ignore-certificate-errors (THIS LAB ONLY)",
          f"- Flows: `{d / 'flows.jsonl'}` (one line per request, `in_scope` from SCOPE.txt; "
          f"{'out-of-scope requests answered 451 locally' if a.block_oos else 'out-of-scope requests recorded, not blocked'})",
          f"- Raw flows: `{d / 'flows.mitm'}` (replay: `python3 -s /usr/bin/mitmdump -nr flows.mitm`)",
          f"- asar: {asar_note}",
          f"- Command: `{' '.join(cmd)}`", "",
          "## Static review starting points", "",
          "- grep the asar for `nodeIntegration`, `contextIsolation: false`, `webSecurity: false`, "
          "`sandbox: false`, `shell.openExternal`, `ipcMain.handle`, `setWindowOpenHandler`, "
          "`will-navigate`, custom protocol handlers (`setAsDefaultProtocolClient`), `preload`.",
          "- deep links: the registered protocol is a remote entry point (argv / open-url handler).", "",
          f"- down: `gnoc sandbox down {a.program} {name}`", ""]
    (d / "LAB.md").write_text("\n".join(md))
    print(f"electron lab {a.program}/{name} up: devtools 127.0.0.1:{dport} mitm 127.0.0.1:{mport} "
          f"({'ok' if ok else 'DevTools NOT answering, see app.log'})")
    print(f"  LAB.md {d / 'LAB.md'}")


# ================================================================ EXTENSION ====================
def ext_up(a):
    import sb_extdump
    C.program_dir(a.program, create=a.program.startswith("_"))
    src = Path(a.src).expanduser().resolve()
    if not src.exists():
        C.die(f"{src} does not exist (the Chrome Web Store CRX host is scope-gate blocked: fetch the "
              "CRX by hand or from a mirror the program lists, then pass the local file)")
    name = "ext-" + _slug(a.name or src.stem)
    d = C.lab_dir(a.program, name)
    st = C.load_state(d)
    if st and C.lab_live(st):
        C.die(f"lab {a.program}/{name} already up")
    d.mkdir(parents=True, exist_ok=True)
    ext = sb_extdump.unpack(src, d)
    md_ext, summ = sb_extdump.analyse(ext, a.program)
    extra = ["--set", "ssl_insecure=true"] if a.insecure_upstream else []
    mpid, mport = C.start_mitm(d, a.program, a.block_oos, extra)
    dport = C.free_port()
    proxy = f"http://127.0.0.1:{mport}"
    cmd = [str(C.CHROME), f"--user-data-dir={d / 'profile'}", f"--load-extension={ext}",
           f"--disable-extensions-except={ext}", f"--remote-debugging-port={dport}",
           "--remote-debugging-address=127.0.0.1", f"--proxy-server={proxy}",
           "--proxy-bypass-list=<-loopback>", "--ignore-certificate-errors", "--no-first-run",
           "--no-default-browser-check", "--disable-background-networking", "--disable-component-update",
           "--disable-sync", "--disable-default-apps",
           "--disable-features=DisableLoadExtensionCommandLineSwitch"]
    if a.headless:
        cmd += ["--headless=new", "--disable-gpu"]
    cmd.append(a.url or "about:blank")
    cpid = C.spawn(cmd, d / "chrome.log", env=C.gui_env())
    ok = C.wait_port(dport, a.wait)
    ext_id = sb_extdump.extension_id(ext)
    ext_targets = []
    for _ in range(20):
        ext_targets = [t for t in _devtools_list(dport)
                       if str(t.get("url", "")).startswith(f"chrome-extension://{ext_id}/")]
        if ext_targets:
            break
        time.sleep(0.5)
    # an idle MV3 service worker drops out of /json/list; the id itself is deterministic
    bad = C.assert_loopback_listeners(cpid) + C.assert_loopback_listeners(mpid)
    if bad:
        C.kill_group(cpid)
        C.kill_group(mpid)
        C.die(f"off-loopback listener {bad}; lab killed")
    ver = _devtools_version(dport)
    st = {"kind": "ext", "program": a.program, "name": name, "status": "up", "created": C.now(),
          "source": str(src), "unpacked": str(ext), "extension_id": ext_id,
          "pids": {"chrome": cpid, "mitmdump": mpid}, "ports": {"devtools": dport, "mitm": mport},
          "containers": [], "browser": ver.get("Browser"), "summary": summ, "block_oos": a.block_oos}
    C.save_state(d, st)
    head = [f"- Lab: `{d}`", f"- Loaded in: {ver.get('Browser')} (throwaway profile `{d / 'profile'}`)",
            f"- Extension id: `{ext_id}` (computed; {'live target seen over CDP' if ext_targets else 'no live target yet: an idle MV3 worker leaves /json/list, open chrome-extension://' + ext_id + '/manifest.json to wake it'})",
            f"- Extension targets: {[(t.get('type'), t.get('url')) for t in ext_targets]}",
            f"- DevTools: `http://127.0.0.1:{dport}/json/list`",
            f"- Proxy: mitmdump `{proxy}`; flows `{d / 'flows.jsonl'}` (in_scope per SCOPE.txt)", ""]
    lines = md_ext.split("\n")
    (d / "EXT.md").write_text("\n".join(lines[:2] + head + lines[2:]))
    (d / "LAB.md").write_text("\n".join([f"# LAB {a.program}/{name} (ext)", "", f"- Created: {st['created']}",
                                          f"- Input: `{src}`"] + head +
                                         [f"- Trust surface: `{d / 'EXT.md'}`",
                                          f"- Command: `{' '.join(cmd)}`", "",
                                          f"- down: `gnoc sandbox down {a.program} {name}`", ""]))
    print(f"ext lab {a.program}/{name} up: id {ext_id} devtools 127.0.0.1:{dport} mitm 127.0.0.1:{mport} "
          f"({'ok' if ok else 'DevTools NOT answering'})")
    print(f"  EXT.md {d / 'EXT.md'}")


# ================================================================ LS / DOWN ====================
def lab_down(d: Path, st: dict):
    for nm, pid in (st.get("pids") or {}).items():
        C.kill_group(pid)
    for c in st.get("containers", []):
        _run([C.CONTAINER, "rm", "-f", "-t", "5", c])
    st["status"] = "down"
    st["down_at"] = C.now()
    C.save_state(d, st)
    print(f"down {st['program']}/{st['name']} ({st['kind']})")


def cmd_ls(kind=None):
    rows = [(d, st) for d, st in C.all_labs() if not kind or st.get("kind") == kind]
    if not rows:
        print("no labs")
        return
    print(f"{'PROGRAM':22} {'LAB':26} {'KIND':9} {'STATE':6} ENDPOINTS")
    for d, st in rows:
        live = C.lab_live(st)
        state = "UP" if live else ("down" if st.get("status") == "down" else "DEAD")
        ports = st.get("ports") or {}
        ep = " ".join(f"{k}=127.0.0.1:{v}" for k, v in ports.items() if v)
        extra = st.get("version") or st.get("fork_block") or st.get("extension_id") or st.get("browser") or ""
        print(f"{st['program'][:22]:22} {st['name'][:26]:26} {st['kind']:9} {state:6} {ep} {extra}")


def cmd_down(args, kind=None):
    if not args:
        C.die("down all | down <program> [<name>]")
    labs = C.all_labs()
    if args[0] == "all":
        sel = [(d, st) for d, st in labs if (not kind or st["kind"] == kind)]
    else:
        sel = [(d, st) for d, st in labs if st["program"] == args[0]
               and (len(args) < 2 or st["name"] in (args[1], _slug(args[1]), "electron-" + _slug(args[1]),
                                                    "ext-" + _slug(args[1])))
               and (not kind or st["kind"] == kind)]
    if not sel:
        print("nothing to take down")
    for d, st in sel:
        if st.get("status") != "down" or C.lab_live(st):
            lab_down(d, st)
    stray = _run([C.CONTAINER, "ps", "-a", "--filter", "label=gnoc_sandbox", "--format", "{{.Names}}"]).stdout.split()
    if args[0] == "all" and not kind and stray:
        _run([C.CONTAINER, "rm", "-f"] + stray)
        print(f"removed stray sandbox containers: {stray}")


# ================================================================ SELFTEST =====================
def selftest(a):
    """Local-only proof: oss (an image already pulled), evm (no fork), electron + ext (own fixtures)."""
    import http.server
    import threading
    prog = "program-08"
    pd = C.program_dir(prog, create=True)
    (pd / "SCOPE.txt").write_text("# local selftest program for scripts/workbench/sandbox.py\n"
                                  "127.0.0.1\nlocalhost\n")
    hits = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            body = (b"<html><body><h1>sandbox selftest</h1></body></html>" if self.path.startswith("/page")
                    else b'{"pong":"' + self.path.encode() + b'"}')
            self.send_response(200)
            self.send_header("content-type", "text/html" if self.path.startswith("/page") else "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *x):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    hp = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    fx = HERE / "selftest"
    res = {}
    me = [sys.executable, str(Path(__file__).resolve())]

    def step(nm, argv, check):
        print(f"\n== {nm}: {' '.join(argv)}")
        r = subprocess.run(me + argv, capture_output=True, text=True)
        print(r.stdout.strip()[-1200:] + ("\n" + r.stderr.strip()[-800:] if r.stderr.strip() else ""))
        ok = r.returncode == 0 and check()
        res[nm] = "PASS" if ok else "FAIL"
        return ok

    if "oss" in a.only:
        img = a.image
        def oss_check():
            st = C.load_state(C.lab_dir(prog, "selftest-oss")) or {}
            port = list((st.get("ports") or {}).values())
            if not port:
                return False
            for _ in range(60):
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port[-1]}/", timeout=3) as r:
                        b = r.read(400)
                        (C.lab_dir(prog, "selftest-oss") / "curl-root.txt").write_bytes(
                            f"GET http://127.0.0.1:{port[-1]}/ -> {r.status}\n".encode() + b)
                        return True
                except Exception:
                    time.sleep(1)
            return False
        if img:
            step("oss", ["oss", prog, img, "--name", "selftest-oss", "--lab-only"] + (a.oss_args or []), oss_check)
            subprocess.run(me + ["down", prog, "selftest-oss"])
            res["oss_container_gone"] = "PASS" if not C.container_running("sbx-" + _slug(prog) + "-selftest-oss") else "FAIL"

    if "evm" in a.only:
        def evm_check():
            r = subprocess.run(me + ["evm", "test", prog, "--name", "evm"], capture_output=True, text=True)
            (C.lab_dir(prog, "evm") / "forge-test.txt").write_text(r.stdout + r.stderr)
            print(r.stdout[-800:])
            return r.returncode == 0 and "test_sandbox_is_local" in r.stdout
        step("evm", ["evm", prog, "--no-fork", "--name", "evm", "--reset-test"], evm_check)
        subprocess.run(me + ["down", prog, "evm"])

    if "electron" in a.only:
        d = C.lab_dir(prog, "electron-selftest-app")
        if (d / "flows.jsonl").exists():
            (d / "flows.jsonl").unlink()

        def el_check():
            for _ in range(40):
                if (d / "flows.jsonl").exists() and "/electron-ping" in (d / "flows.jsonl").read_text():
                    return True
                time.sleep(0.5)
            return False
        step("electron", ["electron", prog, str(fx / "electron-app"), "--name", "selftest-app", "--headless",
                          "--env", f"SB_SELFTEST_URL=http://127.0.0.1:{hp}"], el_check)
        subprocess.run(me + ["down", prog, "selftest-app"])

    if "ext" in a.only:
        d = C.lab_dir(prog, "ext-selftest-ext")
        if (d / "flows.jsonl").exists():
            (d / "flows.jsonl").unlink()

        def ext_check():
            for _ in range(40):
                if (d / "flows.jsonl").exists() and "/ext-ping" in (d / "flows.jsonl").read_text():
                    st = C.load_state(d) or {}
                    return bool(st.get("extension_id")) and st["extension_id"] in (d / "flows.jsonl").read_text()
                time.sleep(0.5)
            return False
        step("ext", ["ext", prog, str(fx / "extension"), "--name", "selftest-ext", "--headless",
                     "--url", f"http://127.0.0.1:{hp}/page.html"], ext_check)
        subprocess.run(me + ["down", prog, "selftest-ext"])

    srv.shutdown()
    print("\nSELFTEST " + json.dumps(res) + f"  (local server saw: {hits})")
    (pd / "SELFTEST.json").write_text(json.dumps({"ts": C.now(), "results": res, "server_hits": hits}, indent=2))
    sys.exit(0 if res and all(v == "PASS" for v in res.values()) else 1)


# ================================================================ CLI ==========================
def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return
    k = argv[0]
    if k == "ls":
        return cmd_ls()
    if k == "down":
        return cmd_down(argv[1:])
    if k in KINDS and len(argv) > 1 and argv[1] == "ls":
        return cmd_ls(k)
    if k in KINDS and len(argv) > 1 and argv[1] == "down":
        return cmd_down(argv[2:], k)
    if k == "evm" and len(argv) > 1 and argv[1] in ("test", "guard"):
        ap = argparse.ArgumentParser(prog=f"sandbox evm {argv[1]}")
        ap.add_argument("program")
        ap.add_argument("--name", default="evm")
        rest = argv[2:]
        fa = []
        if "--" in rest:
            i = rest.index("--")
            rest, fa = rest[:i], rest[i + 1:]
        a = ap.parse_args(rest)
        a.forge_args = fa
        if argv[1] == "guard":
            sys.exit(evm_guard(a.program, _slug(a.name)))
        return evm_test(a)

    ap = argparse.ArgumentParser(prog="sandbox")
    sp = ap.add_subparsers(dest="kind", required=True)
    o = sp.add_parser("oss")
    o.add_argument("program")
    o.add_argument("src")
    o.add_argument("--version")
    o.add_argument("--name")
    o.add_argument("--port", type=int, action="append")
    o.add_argument("--env", action="append")
    o.add_argument("--cmd")
    o.add_argument("--lab-only", action="store_true")
    o.add_argument("--wait", type=float, default=60)
    e = sp.add_parser("evm")
    e.add_argument("program")
    e.add_argument("--chain")
    e.add_argument("--block", type=int)
    e.add_argument("--rpc")
    e.add_argument("--no-fork", action="store_true")
    e.add_argument("--name", default="evm")
    e.add_argument("--reset-test", action="store_true")
    for nm in ("electron", "ext"):
        x = sp.add_parser(nm)
        x.add_argument("program")
        x.add_argument("src")
        x.add_argument("--name")
        x.add_argument("--headless", action="store_true")
        x.add_argument("--block-oos", action="store_true")
        x.add_argument("--insecure-upstream", action="store_true",
                       help="mitm skips UPSTREAM cert checks (local self-signed servers only)")
        x.add_argument("--wait", type=float, default=30)
        if nm == "electron":
            x.add_argument("--env", action="append")
            x.add_argument("--no-inspect", action="store_true")
            x.add_argument("--ozone-headless", action="store_true",
                           help="Chromium ozone headless (segfaults on Electron 38 here)")
            x.add_argument("--app-arg", dest="app_args", action="append")
        else:
            x.add_argument("--url")
    s = sp.add_parser("selftest")
    s.add_argument("--image", help="a LOCAL image for the oss leg (e.g. one from `podman images`)")
    s.add_argument("--oss-arg", dest="oss_args", action="append")
    s.add_argument("--only", default="oss,evm,electron,ext")
    a = ap.parse_args(argv)
    if a.kind == "oss":
        oss_up(a)
    elif a.kind == "evm":
        evm_up(a)
    elif a.kind == "electron":
        electron_up(a)
    elif a.kind == "ext":
        ext_up(a)
    elif a.kind == "selftest":
        a.only = set(a.only.split(","))
        selftest(a)


if __name__ == "__main__":
    main(sys.argv[1:])
