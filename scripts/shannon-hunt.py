#!/usr/bin/env python3
"""Authorization-aware Shannon launcher for the the user hunt workspace.

Shannon is an active pentester. This wrapper defaults to planning only and
requires program-policy, source-trust, scope, and path decisions to be explicit.
Remote targets, including production, are permitted when the operator confirms
that the exact target and automation are authorized. Exploit mode requires a
separate acknowledgement of live side effects.

Examples:
  scripts/shannon-hunt.py doctor
  scripts/shannon-hunt.py plan --program globex \
    --url http://host.docker.internal:3000 --repo targets/globex/recon/app \
    --config scripts/shannon/greynoc-analysis.yaml \
    --policy-reviewed --trusted-source
  scripts/shannon-hunt.py run ...same arguments...

  scripts/shannon-hunt.py plan --program customer-bbp \
    --url https://authorized.example --repo targets/customer-bbp/recon/app \
    --config scripts/shannon/greynoc-authorized-live.yaml \
    --policy-reviewed --trusted-source --authorized-target --path-reviewed \
    --allow-live-exploit
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent.parent
SHANNON = ROOT / "tools" / "shannon"
SHANNON_CLI = SHANNON / "shannon"
POLICY_TERMS = re.compile(r"automated|scanner|scanning|fuzz|rate|\bAI\b", re.IGNORECASE)
MODEL_ENV_NAMES = (
    "SHANNON_AI_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "XAI_API_KEY",
    "AWS_BEARER_TOKEN_BEDROCK",
    "CLAUDE_CODE_OAUTH_TOKEN",
)
LOCAL_HOSTS = {"host.docker.internal", "gateway.docker.internal"}
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class GateError(RuntimeError):
    pass


def capture(*command: str, cwd: Path | None = None) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)
    return proc.returncode, proc.stdout.strip()


def one_line(command: str, *args: str) -> str:
    rc, output = capture(command, *args)
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    last = ANSI_ESCAPE.sub("", lines[-1]) if lines else "unavailable"
    return f"{last} (rc={rc})"


def credential_sources() -> list[str]:
    sources = [name for name in MODEL_ENV_NAMES if os.environ.get(name)]
    if os.environ.get("SHANNON_USE_PI_AUTH") == "1":
        sources.append("SHANNON_USE_PI_AUTH")
    env_file = SHANNON / ".env"
    if env_file.is_file():
        text = env_file.read_text(encoding="utf-8", errors="replace")
        if any(re.search(rf"^\s*{re.escape(name)}\s*=\s*\S+", text, re.MULTILINE) for name in MODEL_ENV_NAMES):
            sources.append("tools/shannon/.env")
    return sources


def doctor() -> int:
    print(f"workspace: {ROOT}")
    if not (SHANNON / ".git").is_dir():
        print("shannon: MISSING (expected tools/shannon)")
        return 2
    rc, revision = capture("git", "rev-parse", "HEAD", cwd=SHANNON)
    print(f"shannon revision: {revision if rc == 0 else 'unknown'}")
    if SHANNON_CLI.is_file():
        print(f"shannon cli: {one_line(str(SHANNON_CLI), 'version')}")
    else:
        print("shannon cli: missing")
    print(f"node: {one_line('node', '--version')}")
    print(f"pnpm: {one_line('pnpm', '--version')}")
    docker_line = one_line("docker", "--version")
    print(f"container cli: {docker_line}")
    print(f"compose: {one_line('docker', 'compose', 'version')}")
    if "podman" in docker_line.lower():
        image_rc, image_id = capture("docker", "image", "inspect", "shannon-worker:latest", "--format", "{{.Id}}")
        if image_rc == 0:
            print(f"worker image: present ({ANSI_ESCAPE.sub('', image_id).removeprefix('sha256:')[:12]})")
            print("container compatibility: worker build VERIFIED on Podman; full scan runtime still unverified")
        else:
            print("container compatibility: UNVERIFIED Podman shim; Shannon documents native Docker")
    else:
        print("container compatibility: Docker CLI detected")
    sources = credential_sources()
    print("model credential source(s): " + (", ".join(sources) if sources else "none configured"))
    return 0


def config_exploit_mode(path: Path) -> bool:
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"^\s*exploit\s*:\s*['\"]?(true|false)['\"]?\s*(?:#.*)?$", text, re.MULTILINE | re.IGNORECASE)
    # Shannon defaults to exploit=true when the key is absent.
    return True if match is None else match.group(1).lower() == "true"


def policy_hits(program_file: Path) -> list[str]:
    hits: list[str] = []
    for number, line in enumerate(program_file.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if POLICY_TERMS.search(line):
            hits.append(f"{number}: {line.strip()}")
    return hits


def remote_host_in_scope(host: str, scope_file: Path) -> bool:
    sys.path.insert(0, str(ROOT / "scripts" / "bbtools"))
    from lib_scope import host_in_scope  # type: ignore

    return bool(host_in_scope(host, str(scope_file)))


def remote_authorization_label(args: argparse.Namespace) -> str:
    """Return the authorized remote class or fail closed.

    --authorized-staging remains as a compatibility alias for existing commands;
    new work should use --authorized-target because authorization, not an
    environment name, is the relevant boundary.
    """
    if getattr(args, "authorized_target", False):
        return "authorized remote/live (production permitted by program)"
    if getattr(args, "authorized_staging", False):
        return "authorized staging (legacy flag)"
    raise GateError(
        "remote targets require --authorized-target after confirming written program/customer authorization"
    )


def enforce_exploit_authorization(exploit: bool, local: bool, args: argparse.Namespace) -> None:
    if not exploit:
        return
    if local:
        if not args.allow_local_exploit:
            raise GateError("local exploit mode requires --allow-local-exploit")
        return
    if not args.allow_live_exploit:
        raise GateError(
            "authorized remote exploit mode requires --allow-live-exploit after reviewing permitted side effects, "
            "test-account/data boundaries, and cleanup"
        )


def build_command(args: argparse.Namespace) -> tuple[list[str], list[str]]:
    if not SHANNON_CLI.is_file():
        raise GateError("Shannon is not built; run 'cd tools/shannon && pnpm install && pnpm build'.")

    target_dir = ROOT / "targets" / args.program
    program_file = target_dir / "PROGRAM.md"
    scope_file = target_dir / "SCOPE.txt"
    if not target_dir.is_dir() or not program_file.is_file() or not scope_file.is_file():
        raise GateError(f"program needs targets/{args.program}/PROGRAM.md and SCOPE.txt")
    if not args.policy_reviewed:
        raise GateError("pass --policy-reviewed only after reading PROGRAM.md and resolving its automation/rate rules")
    if not args.trusted_source:
        raise GateError("pass --trusted-source only after reviewing the repository for prompt-injection risk")

    repo = Path(args.repo).expanduser().resolve()
    config = Path(args.config).expanduser().resolve()
    if not repo.is_dir():
        raise GateError(f"repository does not exist: {repo}")
    if not config.is_file():
        raise GateError(f"configuration does not exist: {config}")

    parsed = urlparse(args.url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise GateError("--url must be an http(s) URL with a hostname")
    host = parsed.hostname.lower().rstrip(".")
    local = host in LOCAL_HOSTS
    if host in {"localhost", "127.0.0.1", "::1"}:
        raise GateError("containers cannot reach host localhost; use host.docker.internal")
    target_class = "local/disposable"
    if not local:
        target_class = remote_authorization_label(args)
        if not remote_host_in_scope(host, scope_file):
            raise GateError(f"OUT_OF_SCOPE {host} according to {scope_file}")
        if not args.path_reviewed:
            raise GateError(
                "remote testing requires --path-reviewed after checking path-level and finding-class scope; "
                "SCOPE.txt host matching is insufficient"
            )

    exploit = config_exploit_mode(config)
    enforce_exploit_authorization(exploit, local, args)

    hits = policy_hits(program_file)
    notes = [
        f"target class: {target_class}",
        f"mode: {'exploit' if exploit else 'analysis-only'}",
        f"policy keywords: {len(hits)} hit(s) in {program_file}",
    ]
    notes.extend(f"  {line}" for line in hits[:12])

    command = [
        str(SHANNON_CLI),
        "start",
        "--url",
        args.url,
        "--repo",
        str(repo),
        "--config",
        str(config),
        "--workspace",
        args.workspace,
    ]
    if args.output:
        command.extend(("--output", str(Path(args.output).expanduser().resolve())))
    if args.follow:
        command.append("--follow")
    if args.validate_model:
        command.append("--validate-model")
    if args.validate_auth:
        command.append("--validate-auth")
    return command, notes


def plan_or_run(args: argparse.Namespace, execute: bool) -> int:
    command, notes = build_command(args)
    for note in notes:
        print(note)
    print("command:")
    print("  " + shlex.join(command))
    if not execute:
        print("PLAN ONLY: no target request was sent")
        return 0

    docker_line = one_line("docker", "--version")
    if "podman" in docker_line.lower() and not args.allow_podman:
        raise GateError(
            "this host uses a Podman compatibility shim; the worker image builds, but full runtime is unverified. "
            "Pass --allow-podman to proceed"
        )
    if not credential_sources():
        raise GateError("no model credential source found; configure one outside the workspace report artifacts")
    return subprocess.run(command, cwd=SHANNON, check=False).returncode


def add_run_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--program", required=True, help="directory name under targets/")
    parser.add_argument("--url", required=True, help="local or explicitly authorized remote URL, including production")
    parser.add_argument("--repo", required=True, help="trusted source repository path")
    parser.add_argument("--config", required=True, help="Shannon YAML configuration")
    parser.add_argument("--workspace", default="greynoc-shannon", help="Shannon workspace name")
    parser.add_argument("--output", help="optional final report copy directory")
    parser.add_argument("--policy-reviewed", action="store_true")
    parser.add_argument("--trusted-source", action="store_true")
    parser.add_argument(
        "--authorized-target",
        action="store_true",
        help="confirm written authorization for this exact remote target and automated testing",
    )
    parser.add_argument("--authorized-staging", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--path-reviewed", action="store_true")
    parser.add_argument("--allow-local-exploit", action="store_true")
    parser.add_argument(
        "--allow-live-exploit",
        action="store_true",
        help="permit exploit-mode testing on the authorized remote target, including production",
    )
    parser.add_argument("--allow-podman", action="store_true")
    parser.add_argument("--follow", action="store_true")
    parser.add_argument("--validate-model", action="store_true")
    parser.add_argument("--validate-auth", action="store_true")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="check the local installation without contacting a target")
    plan = sub.add_parser("plan", help="run all gates and print the Shannon command")
    run = sub.add_parser("run", help="run all gates, then execute Shannon")
    add_run_arguments(plan)
    add_run_arguments(run)
    args = parser.parse_args()

    try:
        if args.command == "doctor":
            return doctor()
        return plan_or_run(args, execute=args.command == "run")
    except GateError as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
