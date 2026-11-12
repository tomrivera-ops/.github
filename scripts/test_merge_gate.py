"""Negative-first tests for the faraday-ci-bot merge gate (stdlib unittest, no network).

Founder signatures are real ssh-keygen signatures made with a throwaway key per run.
"""
from __future__ import annotations

import base64
import copy
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATE_FILE = ROOT / "scripts" / "merge_gate.py"


def _load_gate():
    """Load the gate from its absolute path; never put a repository directory on sys.path."""
    sys.dont_write_bytecode = True  # never leave a __pycache__ in the repository
    spec = importlib.util.spec_from_file_location("merge_gate", GATE_FILE)
    module = importlib.util.module_from_spec(spec)
    sys.modules["merge_gate"] = module
    spec.loader.exec_module(module)
    return module


mg = _load_gate()

SHA = "a" * 40
OLD = "b" * 40
SHIPPED_POLICY = json.loads((ROOT / "policy" / "merge-policy.json").read_text())
# The other tests exercise the gate as if a ratified ADR had activated it; KillSwitch tests the shipped file.
POLICY = copy.deepcopy(SHIPPED_POLICY)
POLICY["activation"]["enabled"] = True
ACCEPTED_ADR = "# ADR-0014: risk-tiered merge authority\n\n## Status\nAccepted (2026-12-01)\n\n## Decision\n...\n"


def inputs(**kw):
    base = dict(owner="tomrivera-ops", repo="ecosystem-audit", pr="7", sha=SHA, mode="founder", method="squash")
    base.update(kw)
    return mg.validate_inputs(base["owner"], base["repo"], base["pr"], base["sha"], base["mode"], base["method"])


def evidence(**over):
    ev = {
        "governing_adr": ACCEPTED_ADR,
        "repo": {"default_branch": "main", "full_name": "tomrivera-ops/ecosystem-audit"},
        "pr": {"state": "open", "merged": False, "draft": False, "mergeable": True,
               "head": {"sha": SHA, "repo": {"full_name": "tomrivera-ops/ecosystem-audit"}},
               "base": {"ref": "main", "repo": {"full_name": "tomrivera-ops/ecosystem-audit"}}},
        "files": [{"filename": "docs/readme.md"}],
        "check_runs": [{"name": "ci", "head_sha": SHA, "status": "completed", "conclusion": "success",
                        "app": {"slug": "github-actions"}}],
        "statuses": [],
        "issue_comments": [
            {"user": {"login": mg.CODEX_BOT},
             "body": f"Codex Review: Didn't find any major issues.\n**Reviewed commit:** `{SHA[:10]}`"},
            {"user": {"login": "tomrivera-PSE"},
             "body": "<!-- independent-review:v1 " + json.dumps(
                 {"head_sha": SHA, "verdict": "PASS", "critical": 0, "high": 0, "medium": 0,
                  "reviewer": "claude-subagent"}) + " -->"},
        ],
        "reviews": [],
        "threads": {"data": {"repository": {"pullRequest": {"reviewThreads": {"totalCount": 0, "nodes": []}}}}},
    }
    for k, v in over.items():
        ev[k] = v
    return ev


class Keys:
    """A throwaway signing key plus an allowed-signers file for it."""

    def __init__(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.key = self.dir / "k"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)], check=True)
        pub = (self.dir / "k.pub").read_text().split()
        self.allowed = self.dir / "allowed"
        self.allowed.write_text(f'founder namespaces="{mg.SIGNATURE_NAMESPACE}" {pub[0]} {pub[1]}\n')

    def sign(self, message: bytes, namespace: str = mg.SIGNATURE_NAMESPACE) -> str:
        done = subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(self.key), "-n", namespace],
                              input=message, capture_output=True, check=True)
        return base64.b64encode(done.stdout).decode()


KEYS = Keys()
OTHER = Keys()


def good_sig(inp, keys=KEYS, namespace=mg.SIGNATURE_NAMESPACE):
    return keys.sign(mg.decision_message(inp["owner"], inp["repo"], inp["pr"], inp["head_sha"], inp["method"]),
                     namespace)


def run(ev, inp, sig=None, policy=POLICY):
    return mg.evaluate(ev, inp, policy, signature_b64=good_sig(inp) if sig is None else sig,
                       allowed_signers=KEYS.allowed)


class Allow(unittest.TestCase):
    def test_founder_mode_allows_complete_evidence(self):
        inp = inputs()
        out = run(evidence(), inp)
        self.assertEqual(out["decision"], "ALLOW")
        self.assertEqual(out["authority"]["type"], "founder_signature")


class Refusals(unittest.TestCase):
    def refuse(self, code, ev=None, inp=None, sig=None):
        inp = inp or inputs()
        with self.assertRaises(mg.Refuse) as caught:
            run(ev or evidence(), inp, sig)
        self.assertEqual(caught.exception.code, code)

    # stale SHAs
    def test_stale_head(self):
        ev = evidence()
        ev["pr"]["head"]["sha"] = OLD
        self.refuse("stale_head", ev)

    def test_check_for_other_head(self):
        ev = evidence(check_runs=[{"name": "ci", "head_sha": OLD, "status": "completed",
                                   "conclusion": "success", "app": {"slug": "github-actions"}}])
        self.refuse("check_for_other_head", ev)

    def test_codex_clean_only_at_older_head(self):
        ev = evidence()
        ev["issue_comments"][0]["body"] = f"Didn't find any major issues **Reviewed commit:** `{OLD[:10]}`"
        self.refuse("codex_clean_receipt_missing_at_head", ev)

    def test_independent_review_for_older_head(self):
        ev = evidence()
        ev["issue_comments"][1]["body"] = ev["issue_comments"][1]["body"].replace(SHA, OLD)
        self.refuse("independent_review_missing_at_head", ev)

    def test_signature_for_another_sha(self):
        inp = inputs()
        sig = good_sig(dict(inp, head_sha=OLD))
        self.refuse("founder_signature_invalid", inp=inp, sig=sig)

    # missing reviews
    def test_codex_missing(self):
        ev = evidence()
        del ev["issue_comments"][0]
        self.refuse("codex_clean_receipt_missing_at_head", ev)

    def test_codex_receipt_from_impersonator(self):
        ev = evidence()
        ev["issue_comments"][0]["user"]["login"] = "tomrivera-PSE"
        self.refuse("codex_clean_receipt_missing_at_head", ev)

    def test_codex_findings_at_head(self):
        ev = evidence(reviews=[{"user": {"login": mg.CODEX_BOT}, "commit_id": SHA, "state": "COMMENTED"}])
        self.refuse("codex_findings_at_head", ev)

    def test_unresolved_thread(self):
        ev = evidence(threads={"data": {"repository": {"pullRequest": {"reviewThreads": {
            "totalCount": 1, "nodes": [{"isResolved": False, "isOutdated": False}]}}}}})
        self.refuse("unresolved_review_thread", ev)

    def test_truncated_threads(self):
        ev = evidence(threads={"data": {"repository": {"pullRequest": {"reviewThreads": {
            "totalCount": 101, "nodes": []}}}}})
        self.refuse("review_threads_truncated", ev)

    def test_independent_review_missing(self):
        ev = evidence()
        del ev["issue_comments"][1]
        self.refuse("independent_review_missing_at_head", ev)

    def test_independent_review_with_findings(self):
        ev = evidence()
        ev["issue_comments"][1]["body"] = ev["issue_comments"][1]["body"].replace('"high": 0', '"high": 1')
        self.refuse("independent_review_not_clean", ev)

    # failed checks
    def test_failed_check(self):
        ev = evidence(check_runs=[{"name": "ci", "head_sha": SHA, "status": "completed", "conclusion": "failure",
                                   "app": {"slug": "github-actions"}}])
        self.refuse("check_failed", ev)

    def test_neutral_check_is_not_success(self):
        ev = evidence(check_runs=[{"name": "ci", "head_sha": SHA, "status": "completed", "conclusion": "neutral",
                                   "app": {"slug": "github-actions"}}])
        self.refuse("check_failed", ev)

    def test_pending_check(self):
        ev = evidence(check_runs=[{"name": "ci", "head_sha": SHA, "status": "in_progress", "conclusion": None,
                                   "app": {"slug": "github-actions"}}])
        self.refuse("check_not_completed", ev)

    def test_no_checks(self):
        self.refuse("no_checks_at_head", evidence(check_runs=[]))

    def test_failing_status(self):
        self.refuse("status_not_success", evidence(statuses=[{"context": "x", "state": "failure"}]))

    def test_required_context_cannot_be_faked_with_a_status(self):
        policy = copy.deepcopy(POLICY)
        policy["required_contexts"] = {"tomrivera-ops/ecosystem-audit": ["tests"]}
        ev = evidence(statuses=[{"context": "tests", "state": "success"}])
        with self.assertRaises(mg.Refuse) as caught:
            run(ev, inputs(), policy=policy)
        self.assertEqual(caught.exception.code, "required_context_missing")

    # unauthorized dispatch / authorization
    def test_founder_mode_without_signature(self):
        self.refuse("founder_signature_missing", sig="")

    def test_signature_from_another_key(self):
        inp = inputs()
        self.refuse("founder_signature_invalid", inp=inp, sig=good_sig(inp, keys=OTHER))

    def test_signature_in_wrong_namespace(self):
        inp = inputs()
        self.refuse("founder_signature_invalid", inp=inp, sig=good_sig(inp, namespace="other-namespace"))

    def test_signature_for_another_repo_or_method(self):
        inp = inputs()
        self.refuse("founder_signature_invalid", inp=inp, sig=good_sig(dict(inp, repo="other")))
        self.refuse("founder_signature_invalid", inp=inp, sig=good_sig(dict(inp, method="merge")))

    def test_garbage_signature(self):
        self.refuse("founder_signature_malformed", sig=base64.b64encode(b"not a signature").decode())

    # protected paths / privilege escalation
    def test_gate_never_merges_changes_to_itself_even_with_founder_signature(self):
        inp = inputs(repo=".github")
        ev = evidence(files=[{"filename": "scripts/merge_gate.py"}])
        ev["repo"]["full_name"] = "tomrivera-ops/.github"
        self.refuse("gate_self_modification", ev, inp)

    def test_gate_self_modification_cannot_hide_behind_owner_case(self):
        """Codex finding at 6d404fa: GitHub names are case-insensitive."""
        for owner in ("Tomrivera-ops", "TOMRIVERA-OPS"):
            inp = inputs(owner=owner, repo=".github")
            ev = evidence(files=[{"filename": "scripts/merge_gate.py"}])
            ev["repo"]["full_name"] = "tomrivera-ops/.github"
            self.refuse("gate_self_modification", ev, inp)

    def test_collected_repository_must_match_inputs(self):
        ev = evidence()
        ev["repo"]["full_name"] = "someone-else/ecosystem-audit"
        self.refuse("repo_identity_mismatch", ev)

    def test_required_contexts_apply_regardless_of_owner_case(self):
        policy = copy.deepcopy(POLICY)
        policy["required_contexts"] = {"tomrivera-ops/ecosystem-audit": ["tests"]}
        with self.assertRaises(mg.Refuse) as caught:
            run(evidence(), inputs(owner="TOMRIVERA-OPS"), policy=policy)
        self.assertEqual(caught.exception.code, "required_context_missing")

    def test_fork_head(self):
        ev = evidence()
        ev["pr"]["head"]["repo"]["full_name"] = "attacker/ecosystem-audit"
        self.refuse("fork_or_unknown_head_repo", ev)

    def test_base_not_default_branch(self):
        ev = evidence()
        ev["pr"]["base"]["ref"] = "release"
        self.refuse("base_not_default_branch", ev)

    def test_draft_and_closed(self):
        ev = evidence()
        ev["pr"]["draft"] = True
        self.refuse("pr_is_draft", ev)
        ev = evidence()
        ev["pr"]["state"] = "closed"
        self.refuse("pr_not_open", ev)


class InputValidation(unittest.TestCase):
    def test_bad_inputs_refuse_before_any_token(self):
        cases = [dict(owner="a;b"), dict(owner="tomrivera-ops", repo="orbitconsole/orbit-console"),
                 dict(repo="../x"), dict(pr="0"), dict(pr="7; rm -rf"), dict(sha=SHA[:12]),
                 dict(sha=SHA.upper()), dict(mode="admin"), dict(method="--admin")]
        for case in cases:
            with self.assertRaises(mg.Refuse, msg=case):
                inputs(**case)


class WorkflowStatic(unittest.TestCase):
    """Token-safety properties of the workflow file (text-level, no YAML dependency)."""

    wf = "\n".join(line for line in (ROOT / ".github" / "workflows" / "cli-approve-merge.yml")
                    .read_text().splitlines() if not line.lstrip().startswith("#")) + "\n"

    def test_only_workflow_dispatch(self):
        on_block = self.wf.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        triggers = re.findall(r"^  ([a-z_]+):", on_block, re.M)
        self.assertEqual(triggers, ["workflow_dispatch"])
        self.assertNotIn("pull_request_target", self.wf)

    def test_founder_and_main_only(self):
        self.assertIn("github.ref == 'refs/heads/main'", self.wf)
        self.assertIn("github.actor == 'tomrivera-PSE'", self.wf)
        self.assertIn("github.triggering_actor == 'tomrivera-PSE'", self.wf)

    def test_default_permissions_none_and_scoped_tokens(self):
        self.assertIn("\npermissions: {}\n", self.wf)
        # gate read token, merge-job live-recheck read token, merge write token
        self.assertEqual(self.wf.count("repositories: ${{"), 3)
        self.assertIn("permission-contents: read", self.wf)
        self.assertIn("permission-contents: write", self.wf)
        self.assertNotIn("permission-administration", self.wf)
        self.assertNotIn("permission-workflows", self.wf)

    def test_merge_needs_gate_and_environment(self):
        merge = self.wf.split("\n  merge:\n", 1)[1]
        self.assertIn("needs: gate", merge)
        self.assertIn("environment: faraday-merge", merge)
        self.assertIn('-f sha="${IN_SHA}"', merge)
        gate = self.wf.split("\n  gate:\n", 1)[1].split("\n  merge:\n", 1)[0]
        self.assertIn("environment: faraday-merge", gate)

    def test_no_approval_no_admin_no_pr_checkout(self):
        self.assertNotIn("--approve", self.wf)
        self.assertNotIn("--admin", self.wf)
        self.assertNotIn("pull_request.head", self.wf)
        # gate job + merge job (live recheck); both check out this gate repo only, never the PR
        self.assertEqual(self.wf.count("actions/checkout@"), 2)
        self.assertEqual(self.wf.count("persist-credentials: false"), 2)

    def test_actions_pinned_to_full_shas(self):
        for use in re.findall(r"^\s*(?:-\s+)?uses:\s*(\S+)", self.wf, re.M):
            self.assertRegex(use, r"@[0-9a-f]{40}$", use)

    def test_inputs_never_interpolated_into_shell(self):
        for block in re.findall(r"run: \|\n((?:\s{10,}.*\n)+)", self.wf):
            self.assertNotIn("${{", block)


GATE_REPO = "tomrivera-ops/.github"
# Every file PR #12 changes (FARADAY-CI-BOT-HARDENING-001): the bot must never merge it.
PR12_FILES = [".github/workflows/cli-approve-merge.yml", ".github/workflows/required-checks.yml",
              "docs/MERGE-GATE.md", "policy/founder-allowed-signers", "policy/merge-policy.json",
              "scripts/merge_gate.py", "scripts/test_merge_gate.py"]


def gate_repo_case(files):
    inp = inputs(repo=".github")
    ev = evidence(files=files)
    ev["repo"]["full_name"] = GATE_REPO
    for side in ("head", "base"):
        ev["pr"][side]["repo"]["full_name"] = GATE_REPO
    return ev, inp


class GateRepositoryIntegrity(unittest.TestCase):
    """Codex finding at 82d5e17: an unprotected file in the gate repository (scripts/json.py)
    could be merged and then execute inside later gate runs. In the gate repository the bot
    may only merge allowlisted documentation; anything that can execute, configure or decide
    the gate refuses, even with a valid founder signature."""

    def refuse_in_gate_repo(self, files, codes):
        ev, inp = gate_repo_case(files)
        sig = good_sig(inp)
        with self.assertRaises(mg.Refuse, msg=files) as caught:
            mg.evaluate(ev, inp, POLICY, signature_b64=sig, allowed_signers=KEYS.allowed)
        self.assertIn(caught.exception.code, codes, files)

    def test_module_shadowing_files_cannot_be_merged(self):
        for path in ("scripts/json.py", "scripts/re.py", "scripts/subprocess.py", "json.py",
                     "sitecustomize.py", "usercustomize.py", "lib/evil.pth", "scripts/__pycache__/json.cpython-312.pyc",
                     "Scripts/json.py", "SCRIPTS/JSON.PY", "docs/json.py"):
            self.refuse_in_gate_repo([{"filename": "README.md"}, {"filename": path}],
                                     {"gate_self_modification", "gate_repository_path_not_allowlisted"})

    def test_script_substitution_cannot_be_merged(self):
        for path in ("scripts/merge_gate.py", "scripts/test_merge_gate.py", "scripts/check-approval-policy.sh",
                     "scripts/new_helper.sh", "scripts/sub/dir/tool.py", "scripts/README.md"):
            self.refuse_in_gate_repo([{"filename": path}], {"gate_self_modification"})

    def test_rename_or_delete_of_gate_files_cannot_be_merged(self):
        self.refuse_in_gate_repo([{"filename": "docs/old-gate.md", "previous_filename": "scripts/merge_gate.py"}],
                                 {"gate_self_modification"})
        self.refuse_in_gate_repo([{"filename": "docs/x.md", "previous_filename": "policy/merge-policy.json",
                                   "status": "renamed"}], {"gate_self_modification"})
        self.refuse_in_gate_repo([{"filename": "policy/founder-allowed-signers", "status": "removed"}],
                                 {"gate_self_modification"})

    def test_policy_and_signer_changes_cannot_be_merged(self):
        for path in ("policy/merge-policy.json", "policy/founder-allowed-signers", "policy/new-override.json",
                     "Policy/merge-policy.json"):
            self.refuse_in_gate_repo([{"filename": path}], {"gate_self_modification"})

    def test_workflow_and_action_changes_cannot_be_merged(self):
        for path in (".github/workflows/cli-approve-merge.yml", ".github/workflows/required-checks.yml",
                     ".github/workflows/steal-env-secrets.yml", ".github/actions/x/action.yml",
                     ".github/CODEOWNERS", ".GitHub/workflows/x.yml"):
            self.refuse_in_gate_repo([{"filename": path}], {"gate_self_modification"})

    def test_checkout_and_workspace_config_cannot_be_merged(self):
        for path in (".gitattributes", ".gitmodules", "evidence.json", "decision.json", "validated.json",
                     "Makefile", "tools/run.sh", "pyproject.toml", "CODEOWNERS", "docs/MERGE-GATE.md"):
            self.refuse_in_gate_repo([{"filename": path}], {"gate_self_modification",
                                                            "gate_repository_path_not_allowlisted"})

    def test_pr12_itself_cannot_be_merged_by_the_bot(self):
        self.refuse_in_gate_repo([{"filename": f} for f in PR12_FILES], {"gate_self_modification"})

    def test_documentation_only_pr_to_gate_repository_is_still_allowed(self):
        ev, inp = gate_repo_case([{"filename": "prompts/repo-audit.md"}, {"filename": "CLAUDE.md.template"},
                                  {"filename": "ISSUE_TEMPLATE/bug_report.md"}])
        self.assertEqual(run(ev, inp)["decision"], "ALLOW")

    def test_missing_or_malformed_gate_policy_refuses(self):
        for key, value in (("gate_paths", None), ("gate_paths", "scripts/*"), ("gate_paths", []),
                           ("gate_repository_mergeable_paths", None), ("gate_repository", None)):
            policy = copy.deepcopy(POLICY)
            if value is None:
                policy.pop(key, None)
            else:
                policy[key] = value
            ev, inp = gate_repo_case([{"filename": "README.md"}])
            with self.assertRaises(mg.Refuse, msg=(key, value)) as caught:
                run(ev, inp, policy=policy)
            self.assertEqual(caught.exception.code, "policy_invalid", (key, value))

    def test_policy_file_protects_the_whole_gate_surface(self):
        lowered = [p.lower() for p in POLICY["gate_paths"]]
        for needed in (".github/*", "scripts/*", "policy/*", "*.py", "*.pth"):
            self.assertIn(needed, lowered)
        self.assertEqual(sorted(POLICY["gate_repository_mergeable_paths"]), ["*.md", "*.template"])


def _isolated_copy():
    """A throwaway copy of the gate with attacker files planted next to it."""
    d = Path(tempfile.mkdtemp())
    (d / "scripts").mkdir()
    (d / "policy").mkdir()
    shutil.copy2(GATE_FILE, d / "scripts" / "merge_gate.py")
    (d / "policy" / "merge-policy.json").write_text(json.dumps(POLICY))
    marker = d / "PWNED"
    payload = f"open({str(marker)!r}, 'a').write(__name__ + '\\n')\n"
    for rel in ("scripts/json.py", "scripts/re.py", "scripts/argparse.py", "scripts/subprocess.py",
                "scripts/tempfile.py", "scripts/base64.py", "scripts/fnmatch.py", "json.py", "re.py",
                "sitecustomize.py", "usercustomize.py"):
        (d / rel).write_text(payload)
    return d, marker


GATE_ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "IN_OWNER": "tomrivera-ops", "IN_REPO": "ecosystem-audit",
            "IN_PR": "7", "IN_SHA": SHA, "IN_MODE": "founder", "IN_METHOD": "squash",
            "IN_ACTIVATION": "true"}


class InterpreterIsolation(unittest.TestCase):
    """Negative tests: planted modules never execute inside the gate."""

    def gate(self, d, *py_flags, extra_env=None, args=("validate",)):
        env = dict(GATE_ENV, **(extra_env or {}))
        return subprocess.run([sys.executable, *py_flags, "scripts/merge_gate.py", *args], cwd=d, env=env,
                              capture_output=True, text=True, timeout=60)

    def test_non_isolated_invocation_refuses_before_any_planted_module_runs(self):
        d, marker = _isolated_copy()
        done = self.gate(d)
        self.assertEqual(done.returncode, 4, done.stdout + done.stderr)
        self.assertIn('"interpreter_not_isolated"', done.stdout)
        self.assertFalse(marker.exists(), marker.read_text() if marker.exists() else "")

    def test_environment_cannot_reintroduce_repository_paths(self):
        d, marker = _isolated_copy()
        done = self.gate(d, "-I", extra_env={"PYTHONPATH": str(d / "scripts") + os.pathsep + str(d),
                                             "PYTHONSTARTUP": str(d / "json.py"), "PYTHONSAFEPATH": ""})
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(json.loads(done.stdout)["valid"], True)
        self.assertFalse(marker.exists(), marker.read_text() if marker.exists() else "")

    def test_isolated_evaluate_ignores_planted_modules(self):
        d, marker = _isolated_copy()
        (d / "evidence.json").write_text(json.dumps(evidence()))
        done = self.gate(d, "-I", args=("evaluate", "--evidence", "evidence.json", "--decision", "decision.json"))
        # Real founder key is not available here, so the decision must REFUSE on the signature, not crash.
        self.assertEqual(done.returncode, 3, done.stdout + done.stderr)
        self.assertEqual(json.loads(done.stdout)["code"], "founder_signature_missing")
        self.assertFalse(marker.exists(), marker.read_text() if marker.exists() else "")

    def test_workflow_inline_python_ignores_planted_modules(self):
        d, marker = _isolated_copy()
        (d / "validated.json").write_text(json.dumps({"repo": "ecosystem-audit", "adr_repo": "agent-contracts"}))
        for line in _workflow_python_lines():
            if " -c " not in line:
                continue
            cmd = line.strip().split(" >> ", 1)[0]
            done = subprocess.run(["bash", "-c", cmd], cwd=d, env=GATE_ENV, capture_output=True, text=True, timeout=60)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(done.stdout.strip(), "repo_name=ecosystem-audit\nadr_repo=agent-contracts")
        self.assertFalse(marker.exists(), marker.read_text() if marker.exists() else "")

    def test_module_loaded_from_repository_refuses(self):
        fake = type(sys)("json_shadow")
        fake.__file__ = str(ROOT / "scripts" / "json.py")
        sys.modules["json_shadow"] = fake
        try:
            with self.assertRaises(mg.Refuse) as caught:
                mg.assert_trusted_modules()
            self.assertEqual(caught.exception.code, "untrusted_module_loaded")
        finally:
            del sys.modules["json_shadow"]

    def test_repository_directory_on_sys_path_refuses(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        try:
            with self.assertRaises(mg.Refuse) as caught:
                mg.assert_trusted_modules()
            self.assertEqual(caught.exception.code, "untrusted_import_path")
        finally:
            sys.path.remove(str(ROOT / "scripts"))


def _workflow_python_lines():
    lines = []
    for wf in sorted((ROOT / ".github" / "workflows").glob("*.y*ml")):
        for line in wf.read_text().splitlines():
            if not line.lstrip().startswith("#") and re.search(r"\bpython3?\b", line):
                lines.append(line)
    return lines


class WorkflowPythonIsolation(unittest.TestCase):
    def test_every_workflow_python_invocation_is_isolated(self):
        lines = _workflow_python_lines()
        self.assertGreaterEqual(len(lines), 5)
        for line in lines:
            self.assertRegex(line, r"\bpython3 -I ", line)

    def test_gate_never_submits_an_approving_review(self):
        wf = WorkflowStatic.wf  # comments stripped
        for forbidden in ("/reviews", "APPROVE", "--approve", "gh pr review", "gh pr merge", "--admin",
                          "auto-merge", "enablePullRequestAutoMerge", "--auto"):
            self.assertNotIn(forbidden, wf, forbidden)

    def test_evidence_collection_is_read_only(self):
        """collect() issues only GETs plus one GraphQL *query*: it can never approve or merge."""
        calls = []

        def fake_api(token, url, method="GET", body=None):
            calls.append((method, url, body))
            if url.endswith("/check-runs?per_page=100&page=1"):
                return {"check_runs": []}
            return [] if "per_page=" in url else {}

        real = mg._api
        mg._api = fake_api
        try:
            mg.collect("t", "tomrivera-ops", "ecosystem-audit", 7, SHA)
        finally:
            mg._api = real
        for method, url, body in calls:
            if method == "GET":
                continue
            self.assertEqual((method, url), ("POST", "https://api.github.com/graphql"))
            self.assertTrue(body["query"].lstrip().startswith("query("), body["query"])
            self.assertNotIn("mutation", body["query"])


FORGED_FR_CHECK = "faraday-review / governed-summary"


def forged_authorization_evidence(**over):
    """A successful Faraday Review check run that any workflow GITHUB_TOKEN could create."""
    ev = evidence(**over)
    auth = {"head_sha": SHA, "merge_authorized": True, "risk_class": "green", "approval_class": "A0"}
    ev["check_runs"].append({"name": FORGED_FR_CHECK, "head_sha": SHA, "status": "completed",
                             "conclusion": "success", "app": {"slug": "github-actions", "id": 15368},
                             "output": {"title": "A0 merge authorized",
                                        "text": "faraday-merge-authorization:v1 " + json.dumps(auth)}})
    return ev


class PolicyModeDisabled(unittest.TestCase):
    """Independent review at c6a4043 (High): policy-mode authorization could be forged with a
    check run. Policy mode is removed; only a founder signature authorizes a merge."""

    def test_policy_mode_refused_at_validation_before_any_token(self):
        with self.assertRaises(mg.Refuse) as caught:
            inputs(mode="policy")
        self.assertEqual(caught.exception.code, "policy_mode_disabled")

    def test_every_non_founder_mode_spelling_refuses(self):
        for mode in ("Policy", "POLICY", " policy", "policy ", "policy\n", "policy\x00", "a0", "A1", "auto",
                     "faraday-review", "founder,policy", "founder policy", "Founder", "", "admin"):
            with self.assertRaises(mg.Refuse, msg=repr(mode)) as caught:
                inputs(mode=mode)
            self.assertIn(caught.exception.code, {"policy_mode_disabled", "invalid_mode"}, repr(mode))

    def test_forged_faraday_review_check_cannot_authorize_even_if_validation_is_bypassed(self):
        inp = dict(inputs(), mode="policy")
        for sig in ("", None):
            with self.assertRaises(mg.Refuse) as caught:
                if sig is None:
                    run(forged_authorization_evidence(), inp)  # even with a valid founder signature
                else:
                    mg.evaluate(forged_authorization_evidence(), inp, POLICY)
            self.assertEqual(caught.exception.code, "policy_mode_disabled")

    def test_forged_check_does_not_replace_the_founder_signature(self):
        with self.assertRaises(mg.Refuse) as caught:
            mg.evaluate(forged_authorization_evidence(), inputs(), POLICY, signature_b64="",
                        allowed_signers=KEYS.allowed)
        self.assertEqual(caught.exception.code, "founder_signature_missing")
        with self.assertRaises(mg.Refuse) as caught:
            run(forged_authorization_evidence(), inputs(), sig=good_sig(inputs(), keys=OTHER))
        self.assertEqual(caught.exception.code, "founder_signature_invalid")

    def test_founder_allow_records_only_founder_authority(self):
        out = run(forged_authorization_evidence(), inputs())
        self.assertEqual(out["authority"], {"type": "founder_signature", "namespace": mg.SIGNATURE_NAMESPACE})
        self.assertEqual(out["mode"], "founder")

    def test_unexpected_policy_configuration_cannot_reenable_policy_mode(self):
        policy = copy.deepcopy(POLICY)
        policy.update({"faraday_review_check": FORGED_FR_CHECK, "policy_mode": True, "policy_mode_enabled": True,
                       "modes": ["founder", "policy"], "allowed_modes": ["policy"], "protected_paths": []})
        inp = dict(inputs(), mode="policy")
        with self.assertRaises(mg.Refuse) as caught:
            mg.evaluate(forged_authorization_evidence(), inp, policy)
        self.assertEqual(caught.exception.code, "policy_mode_disabled")
        for key in ("faraday_review_check", "protected_paths"):
            self.assertNotIn(key, POLICY)

    def test_no_policy_authorization_code_path_remains(self):
        self.assertEqual(mg.MODES, ("founder",))
        self.assertFalse(hasattr(mg, "_check_policy_authorization"))
        self.assertFalse(hasattr(mg, "FR_AUTH_RE"))
        src = GATE_FILE.read_text()
        for gone in ("faraday-merge-authorization", "merge_authorized", "approval_class", "faraday_review"):
            self.assertNotIn(gone, src, gone)

    def test_entry_point_refuses_policy_mode_for_every_subcommand(self):
        d, marker = _isolated_copy()
        (d / "evidence.json").write_text(json.dumps(forged_authorization_evidence()))
        for cmd in ("validate", "collect", "evaluate"):
            env = dict(GATE_ENV, IN_MODE="policy", GATE_READ_TOKEN="x")
            done = subprocess.run([sys.executable, "-I", "scripts/merge_gate.py", cmd], cwd=d, env=env,
                                  capture_output=True, text=True, timeout=60)
            self.assertEqual(done.returncode, 3, (cmd, done.stdout, done.stderr))
            self.assertEqual(json.loads(done.stdout)["code"], "policy_mode_disabled", cmd)
        self.assertFalse((d / "decision.json").exists())
        self.assertFalse(marker.exists())

    def test_workflow_offers_founder_mode_only(self):
        wf = WorkflowStatic.wf
        mode_block = wf.split("\n      mode:\n", 1)[1].split("\n      merge_method:\n", 1)[0]
        self.assertIn("options: [founder]", mode_block)
        self.assertIn("default: founder", mode_block)
        self.assertNotIn("policy", mode_block)
        self.assertNotIn("faraday-review", wf)
        self.assertNotIn("A0", wf)


class KillSwitch(unittest.TestCase):
    """P5 corrective: ADR-0012 section 1 forbids bot merges until a ratified ADR-0014 says otherwise.
    The shipped policy and an unset repository variable must each refuse on their own."""

    def refuse(self, code, fn):
        with self.assertRaises(mg.Refuse) as caught:
            fn()
        self.assertEqual(caught.exception.code, code)

    def test_shipped_policy_is_disabled(self):
        self.assertIs(SHIPPED_POLICY["activation"]["enabled"], False)
        self.assertEqual(SHIPPED_POLICY["activation"]["governing_adr"]["required_status"], "Accepted")

    def test_shipped_policy_refuses_even_with_complete_evidence_and_a_founder_signature(self):
        inp = inputs()
        self.refuse("bot_merge_not_activated", lambda: mg.evaluate(
            evidence(), inp, SHIPPED_POLICY, signature_b64=good_sig(inp), allowed_signers=KEYS.allowed))
        self.refuse("bot_merge_not_activated", lambda: mg.require_activation(SHIPPED_POLICY, "true", "tomrivera-ops"))

    def test_policy_flag_must_be_literally_true(self):
        for value in ("true", 1, "yes", None):
            policy = copy.deepcopy(POLICY)
            policy["activation"]["enabled"] = value
            self.refuse("bot_merge_not_activated", lambda: mg.require_activation(policy, "true", "tomrivera-ops"))
        policy = copy.deepcopy(POLICY)
        del policy["activation"]
        self.refuse("bot_merge_not_activated", lambda: mg.require_activation(policy, "true", "tomrivera-ops"))

    def test_repository_variable_must_be_exactly_true(self):
        for var in ("", "True", "1", "yes", " true", "true\n"):
            self.refuse("bot_merge_not_activated", lambda: mg.require_activation(POLICY, var, "tomrivera-ops"))
        self.assertEqual(mg.require_activation(POLICY, "true", "TOMRIVERA-OPS")["repository"],
                         "tomrivera-ops/agent-contracts")

    def test_governing_adr_must_be_accepted(self):
        inp = inputs()
        for text in (ACCEPTED_ADR.replace("Accepted", "Proposed"), "## Status\nNot Accepted\n",
                     "## Status\nAcceptedish\n"):
            ev = evidence(governing_adr=text)
            self.refuse("governing_adr_not_accepted", lambda: run(ev, inp))
        # No Status section at all: refused as ambiguous (stricter parser, Codex P1 3cb5e63).
        ev = evidence(governing_adr=ACCEPTED_ADR.replace("## Status", "## Context"))
        self.refuse("governing_adr_ambiguous", lambda: run(ev, inp))
        ev = evidence()
        del ev["governing_adr"]
        self.refuse("governing_adr_unreadable", lambda: run(ev, inp))

    def test_governing_adr_policy_cannot_relax_the_status(self):
        policy = copy.deepcopy(POLICY)
        policy["activation"]["governing_adr"]["required_status"] = "Proposed"
        self.refuse("policy_invalid", lambda: mg.require_activation(policy, "true", "tomrivera-ops"))

    def test_entry_point_refuses_before_any_token_when_not_activated(self):
        d, marker = _isolated_copy()
        (d / "policy" / "merge-policy.json").write_text(json.dumps(SHIPPED_POLICY))
        (d / "evidence.json").write_text(json.dumps(evidence()))
        for cmd, env in (("validate", GATE_ENV), ("collect", dict(GATE_ENV, GATE_READ_TOKEN="x")),
                         ("evaluate", GATE_ENV)):
            done = subprocess.run([sys.executable, "-I", "scripts/merge_gate.py", cmd], cwd=d, env=env,
                                  capture_output=True, text=True, timeout=60)
            self.assertEqual(done.returncode, 3, (cmd, done.stdout, done.stderr))
            self.assertEqual(json.loads(done.stdout)["code"], "bot_merge_not_activated", cmd)
        (d / "policy" / "merge-policy.json").write_text(json.dumps(POLICY))
        done = subprocess.run([sys.executable, "-I", "scripts/merge_gate.py", "validate"], cwd=d,
                              env=dict(GATE_ENV, IN_ACTIVATION=""), capture_output=True, text=True, timeout=60)
        self.assertEqual(json.loads(done.stdout)["code"], "bot_merge_not_activated")
        self.assertFalse((d / "decision.json").exists())
        self.assertFalse(marker.exists())

    def test_workflow_jobs_are_skipped_unless_the_variable_is_set(self):
        wf = WorkflowStatic.wf
        gate = wf.split("\n  gate:\n", 1)[1].split("\n  merge:\n", 1)[0]
        merge = wf.split("\n  merge:\n", 1)[1]
        self.assertIn("vars.FARADAY_BOT_MERGE_ENABLED == 'true' &&", gate.split("runs-on", 1)[0])
        self.assertIn("if: vars.FARADAY_BOT_MERGE_ENABLED == 'true'", merge.split("runs-on", 1)[0])
        self.assertIn("IN_ACTIVATION: ${{ vars.FARADAY_BOT_MERGE_ENABLED }}", gate)

    def test_merge_rechecks_head_and_base_before_merging(self):
        merge = WorkflowStatic.wf.split("\n  merge:\n", 1)[1]
        self.assertLess(merge.index('[ "${now_sha}" != "${IN_SHA}" ]'), merge.index("-X PUT"))
        self.assertIn('[ "${now_base}" != "${default_branch}" ]', merge)


class AdrStatusParsing(unittest.TestCase):
    """Codex P1 (3cb5e63): only the single authoritative Status section counts."""

    def status_refuses(self, text, code):
        with self.assertRaises(mg.Refuse) as cm:
            mg._check_governing_adr({"governing_adr": text}, POLICY)
        self.assertEqual(cm.exception.code, code)

    def test_accepted_passes(self):
        mg._check_governing_adr({"governing_adr": ACCEPTED_ADR}, POLICY)

    def test_html_comment_spoof_refused(self):
        text = "# ADR-0014\n<!--\n## Status\nAccepted (fake)\n-->\n\n## Status\nProposed\n"
        self.status_refuses(text, "governing_adr_not_accepted")

    def test_fenced_example_spoof_refused(self):
        text = "# ADR-0014\n```md\n## Status\nAccepted (example)\n```\n\n## Status\nProposed\n"
        self.status_refuses(text, "governing_adr_not_accepted")

    def test_tilde_fence_spoof_refused(self):
        text = "# ADR\n~~~\n## Status\nAccepted\n~~~\n## Status\nProposed — draft\n"
        self.status_refuses(text, "governing_adr_not_accepted")

    def test_duplicate_status_sections_refused(self):
        text = "# ADR\n## Status\nAccepted\n\n## Status\nSuperseded\n"
        self.status_refuses(text, "governing_adr_ambiguous")

    def test_no_status_section_refused(self):
        self.status_refuses("# ADR\n## Decision\nAccepted\n", "governing_adr_ambiguous")

    def test_unterminated_fence_refused(self):
        self.status_refuses("# ADR\n## Status\nAccepted\n```\n## Status\nProposed\n", "governing_adr_ambiguous")

    def test_unterminated_comment_refused(self):
        self.status_refuses("# ADR\n## Status\nAccepted\n<!-- x\n", "governing_adr_ambiguous")

    def test_level3_status_is_not_authoritative(self):
        self.status_refuses("# ADR\n### Status\nAccepted\n## Status\nProposed\n", "governing_adr_not_accepted")

    def test_shipped_adr_0014_proposed_is_refused(self):
        adr = Path(os.environ.get("ADR_0014_PATH", "/nonexistent"))
        if not adr.is_file():
            self.skipTest("set ADR_0014_PATH to the agent-contracts ADR-0014 file to run")
        self.status_refuses(adr.read_text(), "governing_adr_not_accepted")


class LiveActivationRecheck(unittest.TestCase):
    """Codex P1 (3cb5e63): disabling policy or withdrawing the ADR after the gate stops the merge."""

    def run_recheck(self, live_policy, adr_text):
        def fake_api(token, url, method="GET", body=None):
            if url.endswith("/contents/policy/merge-policy.json?ref=main"):
                return {"content": base64.b64encode(json.dumps(live_policy).encode()).decode()}
            if "/contents/" in url and url.endswith("?ref=main"):
                return {"content": base64.b64encode(adr_text.encode()).decode()}
            raise AssertionError(url)
        orig = mg._api
        mg._api = fake_api
        try:
            return mg.recheck_activation("t", "tomrivera-ops/.github", "true", "tomrivera-ops")
        finally:
            mg._api = orig

    def test_live_ok(self):
        self.assertEqual(self.run_recheck(POLICY, ACCEPTED_ADR)["activation"], "live")

    def test_policy_disabled_after_gate_refuses(self):
        live = copy.deepcopy(POLICY)
        live["activation"]["enabled"] = False
        with self.assertRaises(mg.Refuse) as cm:
            self.run_recheck(live, ACCEPTED_ADR)
        self.assertEqual(cm.exception.code, "bot_merge_not_activated")

    def test_adr_withdrawn_after_gate_refuses(self):
        with self.assertRaises(mg.Refuse) as cm:
            self.run_recheck(POLICY, ACCEPTED_ADR.replace("Accepted (2026-12-01)", "Suspended (2026-12-02)"))
        self.assertEqual(cm.exception.code, "governing_adr_not_accepted")

    def test_variable_off_refuses(self):
        orig = mg._api
        mg._api = lambda *a, **k: {"content": base64.b64encode(json.dumps(POLICY).encode()).decode()}
        try:
            with self.assertRaises(mg.Refuse) as cm:
                mg.recheck_activation("t", "tomrivera-ops/.github", "false", "tomrivera-ops")
        finally:
            mg._api = orig
        self.assertEqual(cm.exception.code, "bot_merge_not_activated")

    def test_bad_gate_repo_refuses(self):
        with self.assertRaises(mg.Refuse):
            mg.recheck_activation("t", "not a repo", "true", "tomrivera-ops")

    def test_merge_job_rechecks_before_write_token_and_before_put(self):
        merge = WorkflowStatic.wf.split("\n  merge:\n", 1)[1]
        first = merge.index("merge_gate.py recheck")
        self.assertLess(first, merge.index("Mint merge token"))
        self.assertLess(merge.index("merge_gate.py recheck", first + 1), merge.index("-X PUT"))
        self.assertIn("permission-contents: read", merge.split("Mint merge token", 1)[0])


if __name__ == "__main__":
    unittest.main()
