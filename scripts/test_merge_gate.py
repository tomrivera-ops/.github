"""Negative-first tests for the faraday-ci-bot merge gate (stdlib unittest, no network).

Founder signatures are real ssh-keygen signatures made with a throwaway key per run.
"""
from __future__ import annotations

import base64
import copy
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import merge_gate as mg  # noqa: E402

SHA = "a" * 40
OLD = "b" * 40
POLICY = json.loads((ROOT / "policy" / "merge-policy.json").read_text())


def inputs(**kw):
    base = dict(owner="tomrivera-ops", repo="ecosystem-audit", pr="7", sha=SHA, mode="founder", method="squash")
    base.update(kw)
    return mg.validate_inputs(base["owner"], base["repo"], base["pr"], base["sha"], base["mode"], base["method"])


def evidence(**over):
    ev = {
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

    def test_policy_mode_allows_faraday_review_a1_authorization(self):
        inp = inputs(mode="policy")
        auth = {"head_sha": SHA, "merge_authorized": True, "risk_class": "green", "approval_class": "A1"}
        ev = evidence()
        ev["check_runs"].append({"name": POLICY["faraday_review_check"], "head_sha": SHA, "status": "completed",
                                 "conclusion": "success", "app": {"slug": "github-actions"},
                                 "output": {"text": "faraday-merge-authorization:v1 " + json.dumps(auth)}})
        self.assertEqual(mg.evaluate(ev, inp, POLICY)["decision"], "ALLOW")


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

    def test_policy_mode_without_authorization(self):
        inp = inputs(mode="policy")
        with self.assertRaises(mg.Refuse) as caught:
            mg.evaluate(evidence(), inp, POLICY)
        self.assertEqual(caught.exception.code, "policy_authorization_missing")

    def test_policy_authorization_from_untrusted_app_or_other_head(self):
        inp = inputs(mode="policy")
        for app, head, cls in (("evil-app", SHA, "A1"), ("github-actions", OLD, "A1"), ("github-actions", SHA, "A2")):
            auth = {"head_sha": head, "merge_authorized": True, "risk_class": "green", "approval_class": cls}
            ev = evidence()
            ev["check_runs"].append({"name": POLICY["faraday_review_check"], "head_sha": SHA, "status": "completed",
                                     "conclusion": "success", "app": {"slug": app},
                                     "output": {"text": "faraday-merge-authorization:v1 " + json.dumps(auth)}})
            with self.assertRaises(mg.Refuse) as caught:
                mg.evaluate(ev, inp, POLICY)
            self.assertEqual(caught.exception.code, "policy_authorization_missing", (app, head, cls))

    # protected paths / privilege escalation
    def test_protected_path_in_policy_mode(self):
        inp = inputs(mode="policy")
        with self.assertRaises(mg.Refuse) as caught:
            mg.evaluate(evidence(files=[{"filename": ".github/workflows/ci.yml"}]), inp, POLICY)
        self.assertEqual(caught.exception.code, "protected_path_requires_founder")

    def test_renamed_from_protected_path_in_policy_mode(self):
        inp = inputs(mode="policy")
        ev = evidence(files=[{"filename": "docs/x.yml", "previous_filename": ".github/workflows/ci.yml"}])
        with self.assertRaises(mg.Refuse) as caught:
            mg.evaluate(ev, inp, POLICY)
        self.assertEqual(caught.exception.code, "protected_path_requires_founder")

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
        self.assertEqual(self.wf.count("repositories: ${{"), 2)
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
        self.assertEqual(self.wf.count("actions/checkout@"), 1)

    def test_actions_pinned_to_full_shas(self):
        for use in re.findall(r"^\s*(?:-\s+)?uses:\s*(\S+)", self.wf, re.M):
            self.assertRegex(use, r"@[0-9a-f]{40}$", use)

    def test_inputs_never_interpolated_into_shell(self):
        for block in re.findall(r"run: \|\n((?:\s{10,}.*\n)+)", self.wf):
            self.assertNotIn("${{", block)


if __name__ == "__main__":
    unittest.main()
