#!/usr/bin/env python3
"""faraday-ci-bot merge gate (FARADAY-CI-BOT-HARDENING-001).

Deterministic, stdlib-only. Decides whether ``cli-approve-merge.yml`` may merge
one PR at one exact head SHA. It never merges by itself.

Subcommands
  validate   check workflow inputs (run before any token is minted)
  collect    read PR evidence through the GitHub API with a READ-ONLY token
  evaluate   apply the policy to collected evidence; exit 0 only on ALLOW

A merge is allowed only when ALL of these hold for the input head SHA:
  * PR open, not draft, same-repo head (no forks), base == default branch,
    head.sha == input head_sha;
  * the PR does not touch the merge gate itself (never self-merge the gate); in the
    gate repository only allowlisted documentation may change, so nothing that can
    execute, configure or decide the gate can be merged by the bot;
  * every check run at the head is completed with success/skipped, at least one
    exists, every commit status is success, and policy-required contexts pass;
  * Codex: a chatgpt-codex-connector receipt names this head as clean, Codex
    left no review at this head, and no unresolved, non-outdated review thread;
  * independent review evidence for this head: verdict PASS, 0 critical/high/medium;
  * authorization: an SSH signature by the founder key (namespace
    faraday-merge-go) over the exact decision message. That is the only authority.
    Policy mode (Faraday Review A0/A1) is disabled: a check run is not authority,
    because any workflow's GITHUB_TOKEN can create one, so every non-founder
    mode refuses (policy_mode_disabled).
Anything missing, unreadable or ambiguous is REFUSE.

Run only as ``python3 -I scripts/merge_gate.py``. Without isolated mode the script
directory is sys.path[0] and a repository file such as scripts/json.py would shadow
the standard library, so the gate refuses before importing anything from sys.path.
"""
from __future__ import annotations

import sys


def _require_isolated_interpreter() -> None:
    flags = sys.flags
    if not (flags.isolated and flags.ignore_environment and flags.no_user_site
            and getattr(flags, "safe_path", False)):
        sys.stdout.write('{"decision": "REFUSE", "code": "interpreter_not_isolated", '
                         '"detail": "run python3 -I"}\n')
        raise SystemExit(4)


if __name__ == "__main__":
    _require_isolated_interpreter()  # before any import that searches sys.path

import argparse
import base64
import fnmatch
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

GATE_VERSION = "1"
CODEX_BOT = "chatgpt-codex-connector[bot]"
FOUNDER_LOGIN = "tomrivera-PSE"
SIGNATURE_NAMESPACE = "faraday-merge-go"
SIGNER_IDENTITY = "founder"
OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PR_RE = re.compile(r"^[1-9][0-9]{0,6}$")
MODES = ("founder",)  # policy mode is disabled; see _require_founder_mode
METHODS = ("squash", "merge", "rebase")
OK_CONCLUSIONS = {"success", "skipped"}
TRUSTED_CHECK_APP = "github-actions"  # user tokens can forge commit statuses, not Actions check runs
INDEPENDENT_RE = re.compile(r"<!--\s*independent-review:v1\s+(\{.*?\})\s*-->", re.S)


GATE_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


class Refuse(Exception):
    """A deterministic refusal with a stable reason code."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _inside_gate_root(path: str) -> bool:
    real = os.path.realpath(path)
    return real == GATE_ROOT or real.startswith(GATE_ROOT + os.sep)


def assert_trusted_modules() -> None:
    """Refuse if any repository directory is importable or any module came from the repository."""
    for entry in sys.path:
        if entry in ("", ".") or _inside_gate_root(entry):
            raise Refuse("untrusted_import_path", entry or "<cwd>")
    own = os.path.realpath(__file__)
    for name, module in list(sys.modules.items()):
        origin = getattr(module, "__file__", None)
        if isinstance(origin, str) and os.path.realpath(origin) != own and _inside_gate_root(origin):
            raise Refuse("untrusted_module_loaded", name)


# ---- inputs -------------------------------------------------------------------------


def validate_inputs(owner: str, repo: str, pr: str, sha: str, mode: str, method: str) -> dict[str, Any]:
    if not OWNER_RE.fullmatch(owner or ""):
        raise Refuse("invalid_owner")
    full = repo or ""
    if "/" in full:
        o, _, name = full.partition("/")
        if o != owner:
            raise Refuse("repo_owner_mismatch", f"{full} is not under {owner}")
    else:
        name = full
    if not REPO_RE.fullmatch(name) or name in (".", ".."):
        raise Refuse("invalid_repo")
    if not PR_RE.fullmatch(pr or ""):
        raise Refuse("invalid_pr_number")
    if not SHA_RE.fullmatch(sha or ""):
        raise Refuse("invalid_head_sha", "a full 40-hex lowercase SHA is required")
    _require_founder_mode(mode)
    if method not in METHODS:
        raise Refuse("invalid_merge_method")
    return {"owner": owner, "repo": name, "pr": int(pr), "head_sha": sha, "mode": mode, "method": method}


def _require_founder_mode(mode: Any) -> None:
    if isinstance(mode, str) and mode.strip().lower() == "policy":
        raise Refuse("policy_mode_disabled", "only a founder signature authorizes a merge")
    if mode not in MODES:
        raise Refuse("invalid_mode")


def decision_message(owner: str, repo: str, pr: int, sha: str, method: str) -> bytes:
    return f"faraday-merge-decision:v1\n{owner}/{repo}#{pr}\n{sha}\n{method}\n".encode()


# ---- evidence collection (read-only token) -----------------------------------------------


def _api(token: str, url: str, method: str = "GET", body: dict | None = None) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "faraday-merge-gate"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read() or b"null")


def _paged(token: str, url: str, key: str | None = None, cap: int = 2000) -> list:
    out: list = []
    page = 1
    while len(out) < cap:
        sep = "&" if "?" in url else "?"
        data = _api(token, f"{url}{sep}per_page=100&page={page}")
        items = data.get(key, []) if key else data
        out.extend(items)
        if len(items) < 100:
            return out
        page += 1
    raise Refuse("evidence_too_large", url)


def collect(token: str, owner: str, repo: str, pr: int, sha: str) -> dict[str, Any]:
    base = f"https://api.github.com/repos/{owner}/{repo}"
    threads_query = {
        "query": """query($o:String!,$r:String!,$n:Int!){repository(owner:$o,name:$r){
          pullRequest(number:$n){reviewThreads(first:100){totalCount nodes{isResolved isOutdated}}}}}""",
        "variables": {"o": owner, "r": repo, "n": pr}}
    return {
        "repo": _api(token, base),
        "pr": _api(token, f"{base}/pulls/{pr}"),
        "files": _paged(token, f"{base}/pulls/{pr}/files"),
        "check_runs": _paged(token, f"{base}/commits/{sha}/check-runs", key="check_runs"),
        "statuses": _paged(token, f"{base}/commits/{sha}/statuses"),
        "issue_comments": _paged(token, f"{base}/issues/{pr}/comments"),
        "reviews": _paged(token, f"{base}/pulls/{pr}/reviews"),
        "threads": _api(token, "https://api.github.com/graphql", "POST", threads_query),
    }


# ---- evaluation ----------------------------------------------------------------------------


def _check_pr(ev: dict, inp: dict) -> None:
    pr, repo = ev["pr"], ev["repo"]
    if pr.get("state") != "open" or pr.get("merged"):
        raise Refuse("pr_not_open")
    if pr.get("draft"):
        raise Refuse("pr_is_draft")
    if (pr.get("head") or {}).get("sha") != inp["head_sha"]:
        raise Refuse("stale_head", "PR head is not the SHA named in the decision")
    head_repo = ((pr.get("head") or {}).get("repo") or {}).get("full_name")
    base_repo = ((pr.get("base") or {}).get("repo") or {}).get("full_name")
    if not head_repo or head_repo != base_repo:
        raise Refuse("fork_or_unknown_head_repo")
    if (pr.get("base") or {}).get("ref") != repo.get("default_branch"):
        raise Refuse("base_not_default_branch")
    if pr.get("mergeable") is False:
        raise Refuse("not_mergeable")


def _changed_paths(ev: dict) -> list[str]:
    names = []
    for f in ev["files"]:
        names.append(f.get("filename", ""))
        if f.get("previous_filename"):
            names.append(f["previous_filename"])
    if not names or any(not n for n in names):
        raise Refuse("files_unreadable")
    return names


def _match(path: str, patterns: list[str]) -> bool:
    """Case-insensitive glob match (``*`` also crosses ``/``); stricter than case-sensitive."""
    low = path.lower()
    return any(fnmatch.fnmatchcase(low, p.lower()) for p in patterns)


def _patterns(policy: dict, key: str) -> list[str]:
    value = policy.get(key)
    if not isinstance(value, list) or not value or not all(isinstance(p, str) and p for p in value):
        raise Refuse("policy_invalid", key)
    return value


def _canonical_repo(ev: dict, inp: dict) -> str:
    """GitHub's own full_name for the target, compared case-insensitively.

    Owner and repo names are case-insensitive on GitHub, so input spelling must
    never decide which rules apply.
    """
    name = (ev.get("repo") or {}).get("full_name")
    if not isinstance(name, str) or name.lower() != f"{inp['owner']}/{inp['repo']}".lower():
        raise Refuse("repo_identity_mismatch", "collected repository does not match the inputs")
    return name.lower()


def _check_gate_self(ev: dict, inp: dict, paths: list[str], policy: dict) -> None:
    gate_repo = policy.get("gate_repository")
    if not isinstance(gate_repo, str) or "/" not in gate_repo:
        raise Refuse("policy_invalid", "gate_repository")
    gate_paths = _patterns(policy, "gate_paths")
    mergeable = _patterns(policy, "gate_repository_mergeable_paths")
    if _canonical_repo(ev, inp) != gate_repo.lower():
        return
    hits = [p for p in paths if _match(p, gate_paths)]
    if hits:
        raise Refuse("gate_self_modification", f"the gate never merges changes to itself: {hits[0]}")
    # Deny by default: in the gate repository the bot merges allowlisted documentation only.
    others = [p for p in paths if not _match(p, mergeable)]
    if others:
        raise Refuse("gate_repository_path_not_allowlisted", others[0])


def _check_ci(ev: dict, inp: dict, policy: dict) -> None:
    runs = ev["check_runs"]
    if not runs:
        raise Refuse("no_checks_at_head")
    for run in runs:
        if run.get("head_sha") not in (None, inp["head_sha"]):
            raise Refuse("check_for_other_head", run.get("name", ""))
        if run.get("status") != "completed":
            raise Refuse("check_not_completed", run.get("name", ""))
        if run.get("conclusion") not in OK_CONCLUSIONS:
            raise Refuse("check_failed", f"{run.get('name')}={run.get('conclusion')}")
    latest: dict[str, str] = {}
    for st in ev["statuses"]:  # newest first per GitHub
        latest.setdefault(st.get("context", ""), st.get("state", ""))
    for ctx, state in latest.items():
        if state != "success":
            raise Refuse("status_not_success", f"{ctx}={state}")
    # Required contexts count only when produced by GitHub Actions check runs.
    trusted = {r.get("name") for r in runs if (r.get("app") or {}).get("slug") == TRUSTED_CHECK_APP}
    key = _canonical_repo(ev, inp)
    required = {k.lower(): v for k, v in policy.get("required_contexts", {}).items()}
    for ctx in required.get(key, []):
        if ctx not in trusted:
            raise Refuse("required_context_missing", ctx)


def _check_codex(ev: dict, inp: dict) -> None:
    sha = inp["head_sha"]
    for review in ev["reviews"]:
        if (review.get("user") or {}).get("login") == CODEX_BOT and review.get("commit_id") == sha:
            raise Refuse("codex_findings_at_head")
    clean = False
    for c in ev["issue_comments"]:
        if (c.get("user") or {}).get("login") != CODEX_BOT:
            continue
        body = c.get("body") or ""
        m = re.search(r"Reviewed commit:\*\*\s*`([0-9a-f]{7,40})`", body)
        if m and sha.startswith(m.group(1)) and len(m.group(1)) >= 10 \
                and "Didn't find any major issues" in body:
            clean = True
    if not clean:
        raise Refuse("codex_clean_receipt_missing_at_head")
    threads = (((ev.get("threads") or {}).get("data") or {}).get("repository") or {}).get("pullRequest")
    if not threads or "reviewThreads" not in threads:
        raise Refuse("review_threads_unreadable")
    rt = threads["reviewThreads"]
    if rt.get("totalCount", 0) > len(rt.get("nodes") or []):
        raise Refuse("review_threads_truncated")
    for node in rt.get("nodes") or []:
        if not node.get("isResolved") and not node.get("isOutdated"):
            raise Refuse("unresolved_review_thread")


def _check_independent(ev: dict, inp: dict) -> dict:
    found = None
    for c in ev["issue_comments"]:
        m = INDEPENDENT_RE.search(c.get("body") or "")
        if not m:
            continue
        try:
            data = json.loads(m.group(1))
        except ValueError:
            continue
        if data.get("head_sha") == inp["head_sha"]:
            found = data
    if found is None:
        raise Refuse("independent_review_missing_at_head")
    if found.get("verdict") != "PASS" or any(int(found.get(k, 1)) != 0 for k in ("critical", "high", "medium")):
        raise Refuse("independent_review_not_clean")
    return found


def verify_founder_signature(signature_b64: str, inp: dict, allowed_signers: Path) -> None:
    if not signature_b64:
        raise Refuse("founder_signature_missing")
    try:
        armored = base64.b64decode(signature_b64, validate=True)
    except ValueError as exc:
        raise Refuse("founder_signature_malformed") from exc
    if not armored.startswith(b"-----BEGIN SSH SIGNATURE-----"):
        raise Refuse("founder_signature_malformed")
    with tempfile.TemporaryDirectory() as d:
        sig = Path(d) / "decision.sig"
        sig.write_bytes(armored)
        done = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", str(allowed_signers), "-I", SIGNER_IDENTITY,
             "-n", SIGNATURE_NAMESPACE, "-s", str(sig)],
            input=decision_message(inp["owner"], inp["repo"], inp["pr"], inp["head_sha"], inp["method"]),
            capture_output=True, timeout=30, check=False)
    if done.returncode != 0:
        raise Refuse("founder_signature_invalid")


def evaluate(ev: dict, inp: dict, policy: dict, *, signature_b64: str = "",
             allowed_signers: Path | None = None) -> dict[str, Any]:
    _require_founder_mode(inp.get("mode"))  # again here: callers cannot bypass validate_inputs
    _check_pr(ev, inp)
    paths = _changed_paths(ev)
    _check_gate_self(ev, inp, paths, policy)
    _check_ci(ev, inp, policy)
    _check_codex(ev, inp)
    independent = _check_independent(ev, inp)
    verify_founder_signature(signature_b64, inp, allowed_signers or Path(policy["allowed_signers"]))
    authority = {"type": "founder_signature", "namespace": SIGNATURE_NAMESPACE}
    return {"gate_version": GATE_VERSION, "decision": "ALLOW", **inp, "files": len(paths),
            "independent_review": {k: independent.get(k) for k in ("reviewer", "verdict")},
            "authority": authority}


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="merge_gate.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("validate", "collect", "evaluate"):
        p = sub.add_parser(name)
        p.add_argument("--evidence", default="evidence.json")
        p.add_argument("--policy", default="policy/merge-policy.json")
        p.add_argument("--decision", default="decision.json")
    args = ap.parse_args(argv)
    env = os.environ
    try:
        assert_trusted_modules()
        inp = validate_inputs(env.get("IN_OWNER", ""), env.get("IN_REPO", ""), env.get("IN_PR", ""),
                              env.get("IN_SHA", ""), env.get("IN_MODE", ""), env.get("IN_METHOD", ""))
        if args.cmd == "validate":
            print(json.dumps({"valid": True, **inp}))
            return 0
        if args.cmd == "collect":
            ev = collect(env["GATE_READ_TOKEN"], inp["owner"], inp["repo"], inp["pr"], inp["head_sha"])
            Path(args.evidence).write_text(json.dumps(ev))
            return 0
        policy = json.loads(Path(args.policy).read_text())
        ev = json.loads(Path(args.evidence).read_text())
        decision = evaluate(ev, inp, policy, signature_b64=env.get("IN_SIGNATURE", ""))
    except Refuse as r:
        print(json.dumps({"decision": "REFUSE", "code": r.code, "detail": r.detail}))
        return 3
    except Exception as exc:  # noqa: BLE001 - anything unexpected refuses
        print(json.dumps({"decision": "REFUSE", "code": "gate_error", "detail": type(exc).__name__}))
        return 4
    Path(args.decision).write_text(json.dumps(decision, sort_keys=True))
    print(json.dumps(decision, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
