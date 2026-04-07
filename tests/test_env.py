"""
tests/test_env.py — ArmorFlo test suite.
Run: pytest tests/ -v
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest
from server.armorflo_environment import ArmorFloEnvironment
from models import ArmorFloAction, ArmorFloObservation, RewardBreakdown, RemediationStep
from graders import grade_classify_severity, grade_mixed_applicability, grade_full_triage, get_total


def act(**kwargs) -> ArmorFloAction:
    return ArmorFloAction(**kwargs)

def _ep(**kwargs):
    base = dict(classify_action=None, close_action=None, action_history=[],
                applicability_decisions={}, step_count=5, max_steps=10, assets=[])
    base.update(kwargs)
    return base

@pytest.fixture
def env():
    return ArmorFloEnvironment()


# ── reset() ─────────────────────────────────────────────────────────────────

class TestReset:
    def test_returns_observation(self, env):
        obs = env.reset(task_id="task_classify_severity")
        assert isinstance(obs, ArmorFloObservation)
        assert obs.task_id == "task_classify_severity"
        assert len(obs.reports) == 1
        assert len(obs.assets) == 3
        assert obs.step_count == 0
        assert obs.done is False
        assert float(obs.reward) < 0.01

    def test_clears_state(self, env):
        env.reset(task_id="task_classify_severity")
        env.step(act(action_type="assess", query="log4j"))
        env.reset(task_id="task_classify_severity")
        assert env.state.step_count == 0

    def test_all_three_tasks_load(self, env):
        for tid in ArmorFloEnvironment.VALID_TASKS:
            obs = env.reset(task_id=tid)
            assert obs.task_id == tid
            assert len(obs.reports) > 0
            assert len(obs.assets) > 0

    def test_invalid_task_raises(self, env):
        with pytest.raises(ValueError):
            env.reset(task_id="nonexistent")

    def test_default_task(self, env):
        obs = env.reset()
        assert obs.task_id == ArmorFloEnvironment.VALID_TASKS[0]

    def test_task2_three_reports(self, env):
        obs = env.reset(task_id="task_mixed_applicability")
        assert len(obs.reports) == 3

    def test_task3_eight_reports(self, env):
        obs = env.reset(task_id="task_full_triage")
        assert len(obs.reports) == 8


# ── step() ──────────────────────────────────────────────────────────────────

class TestStep:
    def test_assess_returns_result(self, env):
        env.reset(task_id="task_classify_severity")
        obs = env.step(act(action_type="assess", query="log4j vulnerability"))
        assert obs.assess_result is not None
        assert len(obs.assess_result) > 20
        assert not obs.done

    def test_cached_assess(self, env):
        env.reset(task_id="task_classify_severity")
        env.step(act(action_type="assess", query="log4j vulnerability"))
        obs = env.step(act(action_type="assess", query="log4j vulnerability"))
        assert "[cached]" in (obs.assess_result or "")

    def test_step_increments_count(self, env):
        env.reset(task_id="task_classify_severity")
        for _ in range(4):
            obs = env.step(act(action_type="assess", query="test query"))
        assert obs.step_count == 4

    def test_check_applicability_recorded(self, env):
        env.reset(task_id="task_classify_severity")
        obs = env.step(act(action_type="check_applicability",
                           cve_id="CVE-2021-44228", asset_id="AST-001",
                           applicable=True))
        assert "CVE-2021-44228" in obs.applicability_decisions
        assert obs.applicability_decisions["CVE-2021-44228"]["AST-001"]["applicable"] is True

    def test_classify_recorded_in_state(self, env):
        env.reset(task_id="task_classify_severity")
        env.step(act(action_type="classify", severity_tier="CRITICAL",
                     cvss_score_estimate=10.0))
        assert env._classify_action is not None
        assert env._classify_action["severity_tier"] == "CRITICAL"

    def test_close_terminates(self, env):
        env.reset(task_id="task_classify_severity")
        obs = env.step(act(action_type="close",
                           resolution_summary="Log4Shell CRITICAL, upgraded AST-001 AST-002."))
        assert obs.done is True

    def test_step_after_done_raises(self, env):
        env.reset(task_id="task_classify_severity")
        env.step(act(action_type="close", resolution_summary="done"))
        with pytest.raises(RuntimeError):
            env.step(act(action_type="assess", query="anything"))

    def test_max_steps_terminates(self, env):
        obs = env.reset(task_id="task_classify_severity")
        for _ in range(obs.max_steps):
            obs = env.step(act(action_type="assess", query="query"))
            if obs.done:
                break
        assert obs.done

    def test_reward_in_range(self, env):
        env.reset(task_id="task_classify_severity")
        obs = env.step(act(action_type="close", resolution_summary="done"))
        assert 0.0 <= float(obs.reward) <= 1.0

    def test_step_without_reset_raises(self, env):
        with pytest.raises(RuntimeError):
            env.step(act(action_type="assess", query="anything"))

    def test_recommend_doesnt_close(self, env):
        env.reset(task_id="task_classify_severity")
        obs = env.step(act(action_type="recommend", remediation_plan=[
            RemediationStep(priority=1, action="upgrade log4j",
                            target_asset_ids=["AST-001"], rationale="critical")
        ]))
        assert not obs.done

    def test_state_property(self, env):
        env.reset(task_id="task_classify_severity")
        env.step(act(action_type="assess", query="log4j"))
        s = env.state
        assert s.step_count == 1
        assert s.episode_id is not None


# ── Grader unit tests ────────────────────────────────────────────────────────

class TestGraders:

    # Task 1
    def test_task1_perfect(self):
        ep = _ep(
            classify_action={"severity_tier": "CRITICAL", "cvss_score_estimate": 10.0},
            close_action={"resolution_summary":
                "CVE-2021-44228 log4j critical rce upgrade AST-001 AST-002 not affected 2.17.1"},
            applicability_decisions={"CVE-2021-44228": {
                "AST-001": {"applicable": True},
                "AST-002": {"applicable": True},
                "AST-003": {"applicable": False, "reason": "version 2.17.1 not affected"},
            }},
            assets=[{"asset_id": "AST-001"}, {"asset_id": "AST-002"}, {"asset_id": "AST-003"}],
            step_count=4, max_steps=10,
        )
        gt = {
            "severity_tier": "CRITICAL", "cvss_score": 10.0,
            "applicable_assets": ["AST-001", "AST-002"],
            "required_remediation": [],
            "required_escalation": None,
            "resolution_keywords": ["log4j", "2.17.1", "critical", "rce", "upgrade",
                                    "AST-001", "AST-002", "not affected"],
            "par_steps": 5,
        }
        assert get_total(grade_classify_severity(ep, gt)) >= 0.75

    def test_task1_adjacent_severity(self):
        ep = _ep(
            classify_action={"severity_tier": "HIGH", "cvss_score_estimate": 8.0},
            close_action={"resolution_summary": "upgraded log4j"},
            assets=[{"asset_id": "AST-001"}],
        )
        gt = {"severity_tier": "CRITICAL", "cvss_score": 10.0,
              "applicable_assets": [], "resolution_keywords": ["log4j"], "par_steps": 5}
        score = get_total(grade_classify_severity(ep, gt))
        assert score < 0.75

    def test_task1_no_classify_zero(self):
        ep = _ep(step_count=10)
        gt = {"severity_tier": "CRITICAL", "cvss_score": 10.0,
              "applicable_assets": [], "resolution_keywords": [], "par_steps": 5}
        assert get_total(grade_classify_severity(ep, gt)) < 0.01

    def test_task1_false_negative_penalty(self):
        # Agent marks a truly applicable CVE as not-applicable
        ep = _ep(
            classify_action={"severity_tier": "CRITICAL", "cvss_score_estimate": 10.0},
            applicability_decisions={"CVE-2021-44228": {
                "AST-001": {"applicable": False, "reason": "wrong"},
            }},
            assets=[{"asset_id": "AST-001"}, {"asset_id": "AST-002"}],
        )
        gt = {"severity_tier": "CRITICAL", "cvss_score": 10.0,
              "applicable_assets": ["AST-001", "AST-002"],
              "resolution_keywords": [], "par_steps": 5}
        bd = grade_classify_severity(ep, gt)
        assert bd.false_positive_penalty > 0.0

    # Task 2
    def test_task2_good_score(self):
        ep = _ep(
            action_history=[
                {"action_type": "classify", "severity_tier": "HIGH",
                 "affected_components": ["AST-010"]},
                {"action_type": "escalate", "team": "security",
                 "justification": "active exploits"},
                {"action_type": "recommend", "remediation_plan": [
                    {"priority": 1, "action": "upgrade nginx to 1.25.3+",
                     "target_asset_ids": ["AST-010"], "rationale": "internet-facing"},
                    {"priority": 2, "action": "patch glibc on app-server-1",
                     "target_asset_ids": ["AST-011"], "rationale": "local priv esc"},
                ]},
            ],
            applicability_decisions={
                "CVE-2023-44487": {"AST-010": {"applicable": True},
                                   "AST-011": {"applicable": False, "reason": "not nginx"},
                                   "AST-012": {"applicable": False, "reason": "not nginx"},
                                   "AST-013": {"applicable": False, "reason": "not nginx"}},
                "CVE-2023-4911":  {"AST-010": {"applicable": False, "reason": "not linux"},
                                   "AST-011": {"applicable": True},
                                   "AST-012": {"applicable": False, "reason": "glibc 2.31"},
                                   "AST-013": {"applicable": False, "reason": "cisco"}},
                "CVE-2023-20198": {"AST-010": {"applicable": False, "reason": "not cisco"},
                                   "AST-011": {"applicable": False, "reason": "not IOS XE"},
                                   "AST-012": {"applicable": False, "reason": "not IOS XE"},
                                   "AST-013": {"applicable": False, "reason": "IOS not IOS XE"}},
            },
            close_action={"resolution_summary":
                "nginx AST-010 upgrade. glibc AST-011 patched. "
                "CVE-2023-20198 not applicable IOS XE not in inventory. upgrade complete."},
            step_count=10, max_steps=20,
        )
        gt = {
            "severity_tiers": {"CVE-2023-44487": "HIGH", "CVE-2023-4911": "HIGH",
                               "CVE-2023-20198": "CRITICAL"},
            "applicable_map": {
                "CVE-2023-44487": {"AST-010": True, "AST-011": False,
                                   "AST-012": False, "AST-013": False},
                "CVE-2023-4911":  {"AST-010": False, "AST-011": True,
                                   "AST-012": False, "AST-013": False},
                "CVE-2023-20198": {"AST-010": False, "AST-011": False,
                                   "AST-012": False, "AST-013": False},
            },
            "required_remediation": [
                {"action": "upgrade nginx to 1.25.3+", "target_asset_ids": ["AST-010"]},
                {"action": "patch glibc on app-server-1", "target_asset_ids": ["AST-011"]},
            ],
            "required_escalation": "security",
            "resolution_keywords": ["nginx", "AST-010", "glibc", "AST-011",
                                    "not applicable", "CVE-2023-20198", "IOS XE", "upgrade"],
            "par_steps": 10,
        }
        assert get_total(grade_mixed_applicability(ep, gt)) >= 0.70

    def test_loop_penalty_applied(self):
        same = {"action_type": "assess", "query": "what is happening"}
        ep = _ep(action_history=[same] * 7, step_count=18, max_steps=20)
        gt = {"severity_tiers": {}, "applicable_map": {}, "required_remediation": [],
              "required_escalation": "security", "resolution_keywords": [], "par_steps": 10}
        bd = grade_mixed_applicability(ep, gt)
        assert bd.loop_penalty > 0.0

    # Task 3
    def test_task3_partial_credit(self):
        ep = _ep(
            action_history=[
                {"action_type": "escalate", "team": "management", "justification": "critical"},
                {"action_type": "recommend", "remediation_plan": [
                    {"priority": 1, "action": "patch GoAnywhere to 7.4.1+",
                     "target_asset_ids": ["AST-025"], "rationale": "internet-facing critical"},
                    {"priority": 2, "action": "upgrade OpenSSH on bastion-host",
                     "target_asset_ids": ["AST-022"], "rationale": "rce"},
                ]},
            ],
            applicability_decisions={
                "CVE-2024-0204":  {"AST-025": {"applicable": True}},
                "CVE-2024-6387":  {"AST-022": {"applicable": True},
                                   "AST-023": {"applicable": True}},
                "CVE-2023-46805": {"AST-027": {"applicable": False,
                                               "reason": "Palo Alto not Ivanti"}},
            },
            close_action={"resolution_summary":
                "GoAnywhere AST-025 patched. bastion AST-022 OpenSSH upgraded. "
                "CVE-2023-46805 not applicable Palo Alto. patch upgrade."},
            step_count=20, max_steps=35,
        )
        gt = {
            "severity_tiers": {"CVE-2024-3094": "CRITICAL", "CVE-2024-6387": "HIGH",
                               "CVE-2024-21626": "HIGH", "CVE-2023-46805": "HIGH",
                               "CVE-2024-1709": "CRITICAL", "CVE-2023-36884": "HIGH",
                               "CVE-2024-0204": "CRITICAL", "CVE-2023-48795": "MEDIUM"},
            "applicable_map": {
                "CVE-2024-3094":  {f"AST-0{i+20}": (i == 4) for i in range(8)},
                "CVE-2024-6387":  {f"AST-0{i+20}": (i in [2, 3]) for i in range(8)},
                "CVE-2024-21626": {f"AST-0{i+20}": (i == 0) for i in range(8)},
                "CVE-2023-46805": {f"AST-0{i+20}": False for i in range(8)},
                "CVE-2024-1709":  {f"AST-0{i+20}": False for i in range(8)},
                "CVE-2023-36884": {f"AST-0{i+20}": (i == 6) for i in range(8)},
                "CVE-2024-0204":  {f"AST-0{i+20}": (i == 5) for i in range(8)},
                "CVE-2023-48795": {f"AST-0{i+20}": (i in [2, 3]) for i in range(8)},
            },
            "required_remediation": [
                {"action": "patch GoAnywhere to 7.4.1+",    "target_asset_ids": ["AST-025"]},
                {"action": "upgrade OpenSSH on bastion-host","target_asset_ids": ["AST-022"]},
                {"action": "patch runc on k8s-node-1",      "target_asset_ids": ["AST-020"]},
                {"action": "upgrade OpenSSH on internal-ssh-server","target_asset_ids": ["AST-023"]},
                {"action": "patch Office fleet and audit XZ","target_asset_ids": ["AST-026","AST-024"]},
            ],
            "required_escalation": "management",
            "resolution_keywords": ["GoAnywhere", "AST-025", "bastion", "AST-022",
                                    "runc", "AST-020", "OpenSSH", "CVE-2023-46805",
                                    "not applicable", "CVE-2024-1709", "patch", "upgrade"],
            "par_steps": 18,
        }
        score = get_total(grade_full_triage(ep, gt))
        assert 0.15 < score < 0.95  # partial — not perfect, not zero

    # Properties
    def test_reward_always_bounded(self, env):
        env.reset(task_id="task_full_triage")
        for _ in range(8):
            obs = env.step(act(action_type="assess", query="openssh vulnerability"))
            assert 0.0 <= float(obs.reward) <= 1.0
            if obs.done:
                break

    def test_determinism(self, env):
        def run():
            env.reset(task_id="task_classify_severity")
            env.step(act(action_type="classify", severity_tier="CRITICAL",
                         cvss_score_estimate=10.0))
            obs = env.step(act(action_type="close",
                               resolution_summary="log4j critical rce upgrade"))
            return float(obs.reward)
        assert run() == run()

    # Full integration episodes
    def test_task1_full_episode(self, env):
        env.reset(task_id="task_classify_severity")
        env.step(act(action_type="assess", query="log4j vulnerability"))
        env.step(act(action_type="check_applicability", cve_id="CVE-2021-44228",
                     asset_id="AST-001", applicable=True))
        env.step(act(action_type="check_applicability", cve_id="CVE-2021-44228",
                     asset_id="AST-002", applicable=True))
        env.step(act(action_type="check_applicability", cve_id="CVE-2021-44228",
                     asset_id="AST-003", applicable=False,
                     inapplicability_reason="version 2.17.1 is not affected"))
        env.step(act(action_type="classify", severity_tier="CRITICAL",
                     cvss_score_estimate=10.0, affected_components=["AST-001", "AST-002"]))
        obs = env.step(act(action_type="close", resolution_summary=(
            "CVE-2021-44228 Log4Shell CRITICAL CVSS 10.0 rce. "
            "AST-001 api-gateway upgrade log4j to 2.17.1. "
            "AST-002 batch-processor upgrade log4j to 2.17.1. "
            "AST-003 data-warehouse not affected version 2.17.1 already patched."
        )))
        assert obs.done
        assert float(obs.reward) >= 0.70

    def test_task2_full_episode(self, env):
        env.reset(task_id="task_mixed_applicability")
        env.step(act(action_type="assess", query="nginx vulnerability"))
        env.step(act(action_type="assess", query="glibc vulnerability"))
        env.step(act(action_type="assess", query="cisco ios xe"))
        for (cve, ast, app, reason) in [
            ("CVE-2023-44487", "AST-010", True,  ""),
            ("CVE-2023-44487", "AST-011", False, "not running nginx"),
            ("CVE-2023-44487", "AST-012", False, "not running nginx"),
            ("CVE-2023-44487", "AST-013", False, "not running nginx"),
            ("CVE-2023-4911",  "AST-010", False, "not linux"),
            ("CVE-2023-4911",  "AST-011", True,  ""),
            ("CVE-2023-4911",  "AST-012", False, "glibc 2.31 not affected"),
            ("CVE-2023-4911",  "AST-013", False, "not linux"),
            ("CVE-2023-20198", "AST-013", False, "IOS not IOS XE"),
        ]:
            env.step(act(action_type="check_applicability", cve_id=cve,
                         asset_id=ast, applicable=app, inapplicability_reason=reason))
        env.step(act(action_type="escalate", team="security",
                     justification="active exploits in the wild"))
        env.step(act(action_type="recommend", remediation_plan=[
            RemediationStep(priority=1, action="upgrade nginx to 1.25.3+",
                            target_asset_ids=["AST-010"], rationale="internet-facing critical"),
            RemediationStep(priority=2, action="patch glibc on app-server-1",
                            target_asset_ids=["AST-011"], rationale="local priv esc production"),
        ]))
        obs = env.step(act(action_type="close", resolution_summary=(
            "nginx AST-010 upgrade to 1.25.3+ (CVE-2023-44487 HIGH). "
            "glibc AST-011 patch required (CVE-2023-4911 HIGH). "
            "CVE-2023-20198 not applicable no IOS XE in inventory. upgrade complete."
        )))
        assert obs.done
        assert float(obs.reward) >= 0.60


# ── Medium CVE scenario — Task 2 extended tests ──────────────────────────────

class TestTask2Medium:
    """
    Tests for SCENARIO_MIXED_APPLICABILITY (Task 2 — medium difficulty).
    Covers assigned CVSS scores, severity tiers, false-positive suppression
    for CVE-2023-20198, and escalation/remediation correctness.
    Ground truth: CVE-2023-44487 HIGH 7.5 · CVE-2023-4911 HIGH 7.8
                  CVE-2023-20198 CRITICAL 10.0 (no applicable assets).
    """

    # --- CVSS score accuracy --------------------------------------------------

    def test_cvss_accuracy_high_boundary(self):
        """Score within ±0.5 of 7.5 earns full CVSS credit."""
        ep = _ep(
            classify_action={"severity_tier": "HIGH", "cvss_score_estimate": 7.5},
            close_action={"resolution_summary": "nginx AST-010 upgrade"},
            assets=[{"asset_id": "AST-010"}],
        )
        gt = {"severity_tier": "HIGH", "cvss_score": 7.5,
              "applicable_assets": ["AST-010"], "resolution_keywords": ["nginx"], "par_steps": 5}
        bd = grade_classify_severity(ep, gt)
        assert bd.cvss_score_accuracy == 1.0

    def test_cvss_accuracy_glibc_78(self):
        """CVSS 7.8 for CVE-2023-4911 — estimate of 7.5 is within tolerance."""
        ep = _ep(
            classify_action={"severity_tier": "HIGH", "cvss_score_estimate": 7.5},
            close_action={"resolution_summary": "glibc AST-011 patch"},
            assets=[{"asset_id": "AST-011"}],
        )
        gt = {"severity_tier": "HIGH", "cvss_score": 7.8,
              "applicable_assets": ["AST-011"], "resolution_keywords": ["glibc"], "par_steps": 5}
        bd = grade_classify_severity(ep, gt)
        assert bd.cvss_score_accuracy == 1.0  # |7.5-7.8| = 0.3 ≤ 0.5

    def test_cvss_accuracy_cisco_critical(self):
        """CVSS 10.0 for CVE-2023-20198 — estimate must be near 10 for full credit."""
        ep = _ep(
            classify_action={"severity_tier": "CRITICAL", "cvss_score_estimate": 10.0},
            close_action={"resolution_summary": "CVE-2023-20198 not applicable IOS XE"},
            assets=[],
        )
        gt = {"severity_tier": "CRITICAL", "cvss_score": 10.0,
              "applicable_assets": [], "resolution_keywords": ["IOS XE"], "par_steps": 5}
        bd = grade_classify_severity(ep, gt)
        assert bd.cvss_score_accuracy == 1.0

    def test_cvss_accuracy_off_by_2_partial(self):
        """Estimate of 5.5 vs expected 7.5 (diff 2.0) gives partial credit."""
        ep = _ep(
            classify_action={"severity_tier": "HIGH", "cvss_score_estimate": 5.5},
            close_action={"resolution_summary": "nginx"},
            assets=[{"asset_id": "AST-010"}],
        )
        gt = {"severity_tier": "HIGH", "cvss_score": 7.5,
              "applicable_assets": ["AST-010"], "resolution_keywords": ["nginx"], "par_steps": 5}
        bd = grade_classify_severity(ep, gt)
        assert 0.0 < bd.cvss_score_accuracy < 1.0

    def test_cvss_accuracy_off_by_3_zero(self):
        """Estimate of 4.5 vs expected 7.5 (diff 3.0) earns zero CVSS credit."""
        ep = _ep(
            classify_action={"severity_tier": "HIGH", "cvss_score_estimate": 4.5},
            close_action={"resolution_summary": "nginx"},
            assets=[{"asset_id": "AST-010"}],
        )
        gt = {"severity_tier": "HIGH", "cvss_score": 7.5,
              "applicable_assets": ["AST-010"], "resolution_keywords": ["nginx"], "par_steps": 5}
        bd = grade_classify_severity(ep, gt)
        assert bd.cvss_score_accuracy == 0.0

    # --- Severity tier --------------------------------------------------------

    def test_severity_high_correct(self):
        ep = _ep(
            classify_action={"severity_tier": "HIGH", "cvss_score_estimate": 7.5},
            close_action={"resolution_summary": "nginx upgrade"},
            assets=[{"asset_id": "AST-010"}],
        )
        gt = {"severity_tier": "HIGH", "cvss_score": 7.5,
              "applicable_assets": ["AST-010"], "resolution_keywords": ["nginx"], "par_steps": 5}
        bd = grade_classify_severity(ep, gt)
        assert bd.severity_score == 1.0

    def test_severity_adjacent_medium_partial(self):
        """Predicted MEDIUM vs expected HIGH (adjacent) yields 0.5."""
        ep = _ep(
            classify_action={"severity_tier": "MEDIUM", "cvss_score_estimate": 7.5},
            close_action={"resolution_summary": "nginx"},
            assets=[{"asset_id": "AST-010"}],
        )
        gt = {"severity_tier": "HIGH", "cvss_score": 7.5,
              "applicable_assets": ["AST-010"], "resolution_keywords": ["nginx"], "par_steps": 5}
        bd = grade_classify_severity(ep, gt)
        assert bd.severity_score == 0.5

    def test_severity_wrong_by_two_zero(self):
        """Predicted LOW vs expected HIGH (distance 2) yields 0.0."""
        ep = _ep(
            classify_action={"severity_tier": "LOW", "cvss_score_estimate": 7.5},
            close_action={"resolution_summary": "nginx"},
            assets=[{"asset_id": "AST-010"}],
        )
        gt = {"severity_tier": "HIGH", "cvss_score": 7.5,
              "applicable_assets": ["AST-010"], "resolution_keywords": ["nginx"], "par_steps": 5}
        bd = grade_classify_severity(ep, gt)
        assert bd.severity_score == 0.0

    # --- False positive / applicability ---------------------------------------

    def test_cisco_not_applicable_no_penalty(self, env):
        """CVE-2023-20198 correctly marked not-applicable on AST-013 incurs no penalty."""
        env.reset(task_id="task_mixed_applicability")
        obs = env.step(act(action_type="check_applicability",
                           cve_id="CVE-2023-20198", asset_id="AST-013",
                           applicable=False, inapplicability_reason="IOS not IOS XE"))
        assert obs.applicability_decisions["CVE-2023-20198"]["AST-013"]["applicable"] is False

    def test_false_positive_cisco_penalised(self):
        """Incorrectly marking AST-013 as affected by CVE-2023-20198 incurs a penalty."""
        ep = _ep(
            applicability_decisions={
                "CVE-2023-20198": {"AST-013": {"applicable": True}},
            },
            assets=[{"asset_id": "AST-013"}],
        )
        gt = {
            "severity_tiers": {"CVE-2023-20198": "CRITICAL"},
            "applicable_map": {
                "CVE-2023-20198": {"AST-013": False},
            },
            "required_remediation": [],
            "required_escalation": "security",
            "resolution_keywords": [],
            "par_steps": 10,
        }
        bd = grade_mixed_applicability(ep, gt)
        # No true positives exist, so false-positive on non-applicable asset
        # lowers the score but doesn't trigger the false_positive_penalty
        # (which only fires when a truly-applicable asset is called not-applicable).
        assert get_total(bd) < 0.5

    def test_glibc_false_negative_penalised(self):
        """Marking AST-011 (glibc 2.35 — truly affected) as not-applicable is penalised."""
        ep = _ep(
            applicability_decisions={
                "CVE-2023-4911": {"AST-011": {"applicable": False, "reason": "wrong version"}},
            },
            assets=[{"asset_id": "AST-011"}],
        )
        gt = {
            "severity_tiers": {"CVE-2023-4911": "HIGH"},
            "applicable_map": {"CVE-2023-4911": {"AST-011": True}},
            "required_remediation": [{"action": "patch glibc", "target_asset_ids": ["AST-011"]}],
            "required_escalation": "security",
            "resolution_keywords": ["glibc"],
            "par_steps": 10,
        }
        bd = grade_mixed_applicability(ep, gt)
        assert bd.false_positive_penalty > 0.0

    def test_app_server_2_glibc_correctly_excluded(self, env):
        """AST-012 runs glibc 2.31 (< affected range) — must be marked not-applicable."""
        env.reset(task_id="task_mixed_applicability")
        obs = env.step(act(action_type="check_applicability",
                           cve_id="CVE-2023-4911", asset_id="AST-012",
                           applicable=False, inapplicability_reason="glibc 2.31 not in range"))
        assert obs.applicability_decisions["CVE-2023-4911"]["AST-012"]["applicable"] is False

    # --- Escalation -----------------------------------------------------------

    def test_missing_escalation_penalises_score(self):
        """Omitting the required 'security' escalation lowers the overall grade."""
        ep_no_esc = _ep(
            action_history=[
                {"action_type": "recommend", "remediation_plan": [
                    {"priority": 1, "action": "upgrade nginx to 1.25.3+",
                     "target_asset_ids": ["AST-010"], "rationale": "crit"},
                    {"priority": 2, "action": "patch glibc on app-server-1",
                     "target_asset_ids": ["AST-011"], "rationale": "priv esc"},
                ]},
            ],
            applicability_decisions={
                "CVE-2023-44487": {"AST-010": {"applicable": True}},
                "CVE-2023-4911":  {"AST-011": {"applicable": True}},
                "CVE-2023-20198": {"AST-013": {"applicable": False,
                                               "reason": "IOS not IOS XE"}},
            },
            close_action={"resolution_summary":
                "nginx AST-010 upgrade glibc AST-011 not applicable CVE-2023-20198 IOS XE upgrade"},
            step_count=9, max_steps=20,
        )
        ep_with_esc = dict(ep_no_esc)
        ep_with_esc["action_history"] = ep_no_esc["action_history"] + [
            {"action_type": "escalate", "team": "security", "justification": "exploits"}
        ]
        gt = {
            "severity_tiers": {"CVE-2023-44487": "HIGH", "CVE-2023-4911": "HIGH",
                               "CVE-2023-20198": "CRITICAL"},
            "applicable_map": {
                "CVE-2023-44487": {"AST-010": True,  "AST-011": False,
                                   "AST-012": False, "AST-013": False},
                "CVE-2023-4911":  {"AST-010": False, "AST-011": True,
                                   "AST-012": False, "AST-013": False},
                "CVE-2023-20198": {"AST-010": False, "AST-011": False,
                                   "AST-012": False, "AST-013": False},
            },
            "required_remediation": [
                {"action": "upgrade nginx to 1.25.3+",    "target_asset_ids": ["AST-010"]},
                {"action": "patch glibc on app-server-1", "target_asset_ids": ["AST-011"]},
            ],
            "required_escalation": "security",
            "resolution_keywords": ["nginx", "AST-010", "glibc", "AST-011",
                                    "not applicable", "CVE-2023-20198", "IOS XE", "upgrade"],
            "par_steps": 10,
        }
        score_no  = get_total(grade_mixed_applicability(ep_no_esc,  gt))
        score_yes = get_total(grade_mixed_applicability(ep_with_esc, gt))
        assert score_yes > score_no
        assert score_yes - score_no >= 0.10  # escalation weight is 0.15

    # --- Full integration episode (medium) -----------------------------------

    def test_task2_perfect_episode_reward(self, env):
        """A near-perfect Task 2 episode should score ≥ 0.75."""
        env.reset(task_id="task_mixed_applicability")
        env.step(act(action_type="assess", query="nginx http2 vulnerability"))
        env.step(act(action_type="assess", query="glibc looney tunables"))
        env.step(act(action_type="assess", query="cisco ios xe cve-2023-20198"))

        # Full applicability matrix
        for (cve, ast, app, reason) in [
            ("CVE-2023-44487", "AST-010", True,  ""),
            ("CVE-2023-44487", "AST-011", False, "not running nginx"),
            ("CVE-2023-44487", "AST-012", False, "not running nginx"),
            ("CVE-2023-44487", "AST-013", False, "not running nginx or httpd"),
            ("CVE-2023-4911",  "AST-010", False, "not linux"),
            ("CVE-2023-4911",  "AST-011", True,  ""),
            ("CVE-2023-4911",  "AST-012", False, "glibc 2.31 below affected range 2.34-2.38"),
            ("CVE-2023-4911",  "AST-013", False, "cisco not linux"),
            ("CVE-2023-20198", "AST-010", False, "not cisco"),
            ("CVE-2023-20198", "AST-011", False, "not IOS XE"),
            ("CVE-2023-20198", "AST-012", False, "not IOS XE"),
            ("CVE-2023-20198", "AST-013", False, "IOS 15.2 not IOS XE"),
        ]:
            env.step(act(action_type="check_applicability", cve_id=cve,
                         asset_id=ast, applicable=app, inapplicability_reason=reason))

        env.step(act(action_type="classify", severity_tier="HIGH",
                     cvss_score_estimate=7.5, affected_components=["AST-010", "AST-011"]))
        env.step(act(action_type="escalate", team="security",
                     justification="active exploits, internet-facing asset affected"))
        env.step(act(action_type="recommend", remediation_plan=[
            RemediationStep(priority=1, action="upgrade nginx to 1.25.3+",
                            target_asset_ids=["AST-010"],
                            rationale="internet-facing critical, CVSS 7.5"),
            RemediationStep(priority=2, action="patch glibc on app-server-1",
                            target_asset_ids=["AST-011"],
                            rationale="local priv esc to root, production"),
        ]))
        obs = env.step(act(action_type="close", resolution_summary=(
            "CVE-2023-44487 HIGH 7.5 nginx AST-010 upgrade to 1.25.3+. "
            "CVE-2023-4911 HIGH 7.8 glibc AST-011 patch libc6. "
            "CVE-2023-20198 CRITICAL not applicable IOS XE not in inventory. upgrade complete."
        )))
        assert obs.done
        assert float(obs.reward) >= 0.75

    def test_task2_wrong_cvss_estimates_lower_score(self, env):
        """Accurate CVSS estimate scores higher than inaccurate on task 1 (where CVSS weight is 20%)."""
        env.reset(task_id="task_classify_severity")
        env.step(act(action_type="classify", severity_tier="CRITICAL",
                     cvss_score_estimate=5.0))
        obs_bad = env.step(act(action_type="close",
                               resolution_summary="log4j critical rce upgrade AST-001 AST-002 not affected 2.17.1"))
        bad_reward = float(obs_bad.reward)

        env.reset(task_id="task_classify_severity")
        env.step(act(action_type="classify", severity_tier="CRITICAL",
                     cvss_score_estimate=10.0))
        obs_good = env.step(act(action_type="close",
                                resolution_summary="log4j critical rce upgrade AST-001 AST-002 not affected 2.17.1"))
        good_reward = float(obs_good.reward)

        assert good_reward > bad_reward


# ── Hard CVE scenario — Task 3 extended tests ────────────────────────────────

class TestTask3Hard:
    """
    Tests for SCENARIO_FULL_TRIAGE (Task 3 — hard difficulty).
    Eight CVEs, eight assets. Tests verify assigned CVSS scores (CRITICAL 10.0
    for CVE-2024-3094/CVE-2024-1709/CVE-2024-0204, HIGH for openssh/runc/office/ivanti,
    MEDIUM for Terrapin), false-positive suppression for Ivanti and ScreenConnect,
    escalation to management, and prioritised remediation ordering.
    """

    # --- CVSS score accuracy per CVE -----------------------------------------

    def test_cvss_xz_utils_critical_10(self):
        """CVE-2024-3094 XZ backdoor — CVSS 10.0 CRITICAL."""
        ep = _ep(
            classify_action={"severity_tier": "CRITICAL", "cvss_score_estimate": 10.0},
            close_action={"resolution_summary": "xz utils backdoor AST-024 audit"},
            assets=[{"asset_id": "AST-024"}],
        )
        gt = {"severity_tier": "CRITICAL", "cvss_score": 10.0,
              "applicable_assets": ["AST-024"], "resolution_keywords": ["xz"], "par_steps": 5}
        bd = grade_classify_severity(ep, gt)
        assert bd.cvss_score_accuracy == 1.0
        assert bd.severity_score == 1.0

    def test_cvss_openssh_regresshion_high_81(self):
        """CVE-2024-6387 regreSSHion — CVSS 8.1 HIGH; estimate 8.0 is within ±0.5."""
        ep = _ep(
            classify_action={"severity_tier": "HIGH", "cvss_score_estimate": 8.0},
            close_action={"resolution_summary": "openssh AST-022 upgrade"},
            assets=[{"asset_id": "AST-022"}],
        )
        gt = {"severity_tier": "HIGH", "cvss_score": 8.1,
              "applicable_assets": ["AST-022"], "resolution_keywords": ["openssh"], "par_steps": 5}
        bd = grade_classify_severity(ep, gt)
        assert bd.cvss_score_accuracy == 1.0

    def test_cvss_runc_high_86(self):
        """CVE-2024-21626 runc container escape — CVSS 8.6 HIGH."""
        ep = _ep(
            classify_action={"severity_tier": "HIGH", "cvss_score_estimate": 8.5},
            close_action={"resolution_summary": "runc AST-020 patch"},
            assets=[{"asset_id": "AST-020"}],
        )
        gt = {"severity_tier": "HIGH", "cvss_score": 8.6,
              "applicable_assets": ["AST-020"], "resolution_keywords": ["runc"], "par_steps": 5}
        bd = grade_classify_severity(ep, gt)
        assert bd.cvss_score_accuracy == 1.0  # |8.5-8.6| = 0.1 ≤ 0.5

    def test_cvss_goanywhere_critical_98(self):
        """CVE-2024-0204 GoAnywhere — CVSS 9.8 CRITICAL; estimate 9.8 earns full credit."""
        ep = _ep(
            classify_action={"severity_tier": "CRITICAL", "cvss_score_estimate": 9.8},
            close_action={"resolution_summary": "GoAnywhere AST-025 patch 7.4.1"},
            assets=[{"asset_id": "AST-025"}],
        )
        gt = {"severity_tier": "CRITICAL", "cvss_score": 9.8,
              "applicable_assets": ["AST-025"], "resolution_keywords": ["GoAnywhere"], "par_steps": 5}
        bd = grade_classify_severity(ep, gt)
        assert bd.cvss_score_accuracy == 1.0
        assert bd.severity_score == 1.0

    def test_cvss_screenconnect_critical_10(self):
        """CVE-2024-1709 ScreenConnect — CVSS 10.0; no applicable assets but score still checked."""
        ep = _ep(
            classify_action={"severity_tier": "CRITICAL", "cvss_score_estimate": 10.0},
            close_action={"resolution_summary": "CVE-2024-1709 not applicable no ScreenConnect"},
            assets=[],
        )
        gt = {"severity_tier": "CRITICAL", "cvss_score": 10.0,
              "applicable_assets": [], "resolution_keywords": ["CVE-2024-1709"], "par_steps": 5}
        bd = grade_classify_severity(ep, gt)
        assert bd.cvss_score_accuracy == 1.0

    def test_cvss_office_rce_high_83(self):
        """CVE-2023-36884 Office HTML RCE — CVSS 8.3 HIGH; estimate 8.5 still within ±0.5."""
        ep = _ep(
            classify_action={"severity_tier": "HIGH", "cvss_score_estimate": 8.5},
            close_action={"resolution_summary": "office AST-026 patch"},
            assets=[{"asset_id": "AST-026"}],
        )
        gt = {"severity_tier": "HIGH", "cvss_score": 8.3,
              "applicable_assets": ["AST-026"], "resolution_keywords": ["office"], "par_steps": 5}
        bd = grade_classify_severity(ep, gt)
        assert bd.cvss_score_accuracy == 1.0

    def test_cvss_terrapin_medium_59(self):
        """CVE-2023-48795 Terrapin — CVSS 5.9 MEDIUM; underestimating as LOW gives zero tier."""
        ep = _ep(
            classify_action={"severity_tier": "LOW", "cvss_score_estimate": 5.9},
            close_action={"resolution_summary": "terrapin openssh upgrade"},
            assets=[{"asset_id": "AST-022"}],
        )
        gt = {"severity_tier": "MEDIUM", "cvss_score": 5.9,
              "applicable_assets": ["AST-022"], "resolution_keywords": ["openssh"], "par_steps": 5}
        bd = grade_classify_severity(ep, gt)
        assert bd.severity_score == 0.5   # adjacent miss
        assert bd.cvss_score_accuracy == 1.0  # CVSS estimate is exact

    def test_cvss_terrapin_medium_severity_correct(self):
        """Correctly classifying Terrapin as MEDIUM earns full severity credit."""
        ep = _ep(
            classify_action={"severity_tier": "MEDIUM", "cvss_score_estimate": 5.9},
            close_action={"resolution_summary": "terrapin openssh mitm upgrade"},
            assets=[{"asset_id": "AST-022"}, {"asset_id": "AST-023"}],
        )
        gt = {"severity_tier": "MEDIUM", "cvss_score": 5.9,
              "applicable_assets": ["AST-022", "AST-023"],
              "resolution_keywords": ["openssh"], "par_steps": 5}
        bd = grade_classify_severity(ep, gt)
        assert bd.severity_score == 1.0

    # --- Non-applicable CVE suppression --------------------------------------

    def test_ivanti_not_applicable_palo_alto(self, env):
        """CVE-2023-46805 must not apply to AST-027 (Palo Alto GlobalProtect, not Ivanti)."""
        env.reset(task_id="task_full_triage")
        obs = env.step(act(action_type="check_applicability",
                           cve_id="CVE-2023-46805", asset_id="AST-027",
                           applicable=False,
                           inapplicability_reason="Palo Alto GlobalProtect is not Ivanti ICS"))
        assert obs.applicability_decisions["CVE-2023-46805"]["AST-027"]["applicable"] is False

    def test_screenconnect_no_assets_affected(self, env):
        """CVE-2024-1709 — no ScreenConnect in inventory; all applicability checks should be False."""
        env.reset(task_id="task_full_triage")
        for ast_id in ["AST-020", "AST-021", "AST-022", "AST-023",
                       "AST-024", "AST-025", "AST-026", "AST-027"]:
            obs = env.step(act(action_type="check_applicability",
                               cve_id="CVE-2024-1709", asset_id=ast_id,
                               applicable=False, inapplicability_reason="no ScreenConnect"))
            assert obs.applicability_decisions["CVE-2024-1709"][ast_id]["applicable"] is False

    def test_false_negative_ivanti_penalised(self):
        """Marking AST-027 as truly affected by Ivanti CVE-2023-46805 (false negative path)
        — since the GT says it's NOT applicable, this is actually a false positive in F1 terms,
        which lowers precision and hence the applicability F1."""
        ep = _ep(
            applicability_decisions={
                "CVE-2023-46805": {"AST-027": {"applicable": True}},  # wrong
            },
            assets=[{"asset_id": "AST-027"}],
        )
        gt = {
            "severity_tiers": {"CVE-2023-46805": "HIGH"},
            "applicable_map": {"CVE-2023-46805": {f"AST-0{i+20}": False for i in range(8)}},
            "required_remediation": [],
            "required_escalation": "management",
            "resolution_keywords": ["CVE-2023-46805", "not applicable"],
            "par_steps": 18,
        }
        bd = grade_full_triage(ep, gt)
        assert get_total(bd) < 0.5

    def test_k8s_node2_runc_correctly_excluded(self, env):
        """AST-021 runs runc 1.1.12 (patched) — must not be flagged for CVE-2024-21626."""
        env.reset(task_id="task_full_triage")
        obs = env.step(act(action_type="check_applicability",
                           cve_id="CVE-2024-21626", asset_id="AST-021",
                           applicable=False, inapplicability_reason="runc 1.1.12 is patched"))
        assert obs.applicability_decisions["CVE-2024-21626"]["AST-021"]["applicable"] is False

    # --- Escalation to management --------------------------------------------

    def test_management_escalation_required(self):
        """Task 3 requires escalation to 'management', not just 'security'."""
        ep_sec = _ep(
            action_history=[
                {"action_type": "escalate", "team": "security", "justification": "critical"},
            ],
            close_action={"resolution_summary": "GoAnywhere AST-025 bastion AST-022 patch upgrade"},
            step_count=20, max_steps=35,
        )
        ep_mgmt = _ep(
            action_history=[
                {"action_type": "escalate", "team": "management", "justification": "critical"},
            ],
            close_action={"resolution_summary": "GoAnywhere AST-025 bastion AST-022 patch upgrade"},
            step_count=20, max_steps=35,
        )
        gt = {
            "severity_tiers": {f"CVE": "HIGH"},
            "applicable_map": {},
            "required_remediation": [],
            "required_escalation": "management",
            "resolution_keywords": ["GoAnywhere", "AST-025", "bastion", "AST-022",
                                    "patch", "upgrade"],
            "par_steps": 18,
        }
        score_sec  = get_total(grade_full_triage(ep_sec,  gt))
        score_mgmt = get_total(grade_full_triage(ep_mgmt, gt))
        assert score_mgmt > score_sec
        assert score_mgmt - score_sec >= 0.10  # escalation weight 0.15

    # --- Remediation priority order ------------------------------------------

    def test_remediation_priority_order_matters(self):
        """GoAnywhere (internet-facing CRITICAL) should be Priority 1 before OpenSSH."""
        ep_correct = _ep(
            action_history=[
                {"action_type": "recommend", "remediation_plan": [
                    {"priority": 1, "action": "patch GoAnywhere to 7.4.1+",
                     "target_asset_ids": ["AST-025"], "rationale": "internet critical"},
                    {"priority": 2, "action": "upgrade OpenSSH on bastion-host",
                     "target_asset_ids": ["AST-022"], "rationale": "rce"},
                ]},
            ],
            step_count=20, max_steps=35,
        )
        ep_reversed = _ep(
            action_history=[
                {"action_type": "recommend", "remediation_plan": [
                    {"priority": 1, "action": "upgrade OpenSSH on bastion-host",
                     "target_asset_ids": ["AST-022"], "rationale": "rce"},
                    {"priority": 2, "action": "patch GoAnywhere to 7.4.1+",
                     "target_asset_ids": ["AST-025"], "rationale": "critical"},
                ]},
            ],
            step_count=20, max_steps=35,
        )
        gt = {
            "severity_tiers": {},
            "applicable_map": {},
            "required_remediation": [
                {"action": "patch GoAnywhere to 7.4.1+",     "target_asset_ids": ["AST-025"]},
                {"action": "upgrade OpenSSH on bastion-host","target_asset_ids": ["AST-022"]},
                {"action": "patch runc on k8s-node-1",       "target_asset_ids": ["AST-020"]},
                {"action": "upgrade OpenSSH on internal-ssh-server", "target_asset_ids": ["AST-023"]},
                {"action": "patch Office fleet and audit XZ","target_asset_ids": ["AST-026", "AST-024"]},
            ],
            "required_escalation": "management",
            "resolution_keywords": [],
            "par_steps": 18,
        }
        score_correct  = get_total(grade_full_triage(ep_correct,  gt))
        score_reversed = get_total(grade_full_triage(ep_reversed, gt))
        # Correct order should be at least as good as reversed
        assert score_correct >= score_reversed

    # --- Full integration episode (hard) -------------------------------------

    def test_task3_full_episode_high_score(self, env):
        """A thorough Task 3 episode with all key decisions should score ≥ 0.65."""
        env.reset(task_id="task_full_triage")

        # Assess each major vulnerability domain
        for query in [
            "xz utils backdoor cve-2024-3094",
            "openssh regresshion cve-2024-6387",
            "runc container escape cve-2024-21626",
            "goanywhere mft cve-2024-0204",
            "ivanti connect secure cve-2023-46805",
            "screenconnect cve-2024-1709",
            "microsoft office html rce cve-2023-36884",
            "terrapin ssh cve-2023-48795",
        ]:
            env.step(act(action_type="assess", query=query))

        # Full applicability matrix for all 8 CVEs × 8 assets
        applicability = [
            # XZ Utils — only dev-workstation (AST-024) was affected
            ("CVE-2024-3094", "AST-020", False, "Ubuntu 22.04 uses XZ 5.4.x not 5.6"),
            ("CVE-2024-3094", "AST-021", False, "Ubuntu 22.04 uses XZ 5.4.x not 5.6"),
            ("CVE-2024-3094", "AST-022", False, "Ubuntu 22.04 uses XZ 5.4.x not 5.6"),
            ("CVE-2024-3094", "AST-023", False, "Ubuntu 22.04 uses XZ 5.4.x not 5.6"),
            ("CVE-2024-3094", "AST-024", True,  ""),
            ("CVE-2024-3094", "AST-025", False, "GoAnywhere not Ubuntu"),
            ("CVE-2024-3094", "AST-026", False, "Windows not Ubuntu"),
            ("CVE-2024-3094", "AST-027", False, "Palo Alto not Ubuntu"),
            # OpenSSH regreSSHion — bastion and internal ssh server
            ("CVE-2024-6387", "AST-022", True,  ""),
            ("CVE-2024-6387", "AST-023", True,  ""),
            ("CVE-2024-6387", "AST-020", False, "k8s node not ssh server"),
            ("CVE-2024-6387", "AST-021", False, "k8s node patched runc"),
            ("CVE-2024-6387", "AST-024", False, "dev workstation not sshd"),
            ("CVE-2024-6387", "AST-025", False, "GoAnywhere not openssh"),
            ("CVE-2024-6387", "AST-026", False, "Windows not openssh"),
            ("CVE-2024-6387", "AST-027", False, "Palo Alto not openssh"),
            # runc — only k8s-node-1 (AST-020) with runc 1.1.10
            ("CVE-2024-21626", "AST-020", True,  ""),
            ("CVE-2024-21626", "AST-021", False, "runc 1.1.12 patched"),
            ("CVE-2024-21626", "AST-022", False, "not runc"),
            ("CVE-2024-21626", "AST-023", False, "not runc"),
            ("CVE-2024-21626", "AST-024", False, "not runc"),
            ("CVE-2024-21626", "AST-025", False, "not runc"),
            ("CVE-2024-21626", "AST-026", False, "not runc"),
            ("CVE-2024-21626", "AST-027", False, "not runc"),
            # Ivanti — no Ivanti devices in inventory
            ("CVE-2023-46805", "AST-027", False, "Palo Alto GlobalProtect not Ivanti ICS"),
            ("CVE-2023-46805", "AST-022", False, "OpenSSH not Ivanti"),
            ("CVE-2023-46805", "AST-025", False, "GoAnywhere not Ivanti"),
            # ScreenConnect — not in inventory
            ("CVE-2024-1709",  "AST-025", False, "GoAnywhere not ScreenConnect"),
            ("CVE-2024-1709",  "AST-022", False, "not ScreenConnect"),
            # Office RCE — workstation fleet AST-026
            ("CVE-2023-36884", "AST-026", True,  ""),
            ("CVE-2023-36884", "AST-020", False, "not Windows Office"),
            ("CVE-2023-36884", "AST-025", False, "not Windows Office"),
            # GoAnywhere — file-transfer-server AST-025
            ("CVE-2024-0204",  "AST-025", True,  ""),
            ("CVE-2024-0204",  "AST-020", False, "not GoAnywhere"),
            ("CVE-2024-0204",  "AST-026", False, "not GoAnywhere"),
            # Terrapin — both OpenSSH servers
            ("CVE-2023-48795", "AST-022", True,  ""),
            ("CVE-2023-48795", "AST-023", True,  ""),
            ("CVE-2023-48795", "AST-020", False, "not openssh"),
            ("CVE-2023-48795", "AST-025", False, "not openssh"),
            ("CVE-2023-48795", "AST-026", False, "not openssh"),
            ("CVE-2023-48795", "AST-027", False, "not openssh"),
        ]
        for (cve, ast, app, reason) in applicability:
            env.step(act(action_type="check_applicability",
                         cve_id=cve, asset_id=ast, applicable=app,
                         inapplicability_reason=reason))

        # Classify the highest-severity CVEs
        env.step(act(action_type="classify",
                     severity_tier="CRITICAL", cvss_score_estimate=9.8,
                     affected_components=["AST-025"]))  # GoAnywhere

        # Escalate to management
        env.step(act(action_type="escalate", team="management",
                     justification=(
                         "Multiple critical/high CVEs with internet-facing assets compromised. "
                         "Supply-chain backdoor (XZ) and RCE on GoAnywhere demand management visibility."
                     )))

        # Prioritised remediation plan
        env.step(act(action_type="recommend", remediation_plan=[
            RemediationStep(priority=1, action="patch GoAnywhere to 7.4.1+",
                            target_asset_ids=["AST-025"],
                            rationale="internet-facing CRITICAL RCE, CVSS 9.8"),
            RemediationStep(priority=2, action="upgrade OpenSSH on bastion-host",
                            target_asset_ids=["AST-022"],
                            rationale="internet-facing RCE CVE-2024-6387 CVSS 8.1"),
            RemediationStep(priority=3, action="patch runc on k8s-node-1",
                            target_asset_ids=["AST-020"],
                            rationale="container escape CVE-2024-21626 CVSS 8.6"),
            RemediationStep(priority=4, action="upgrade OpenSSH on internal-ssh-server",
                            target_asset_ids=["AST-023"],
                            rationale="RCE internal"),
            RemediationStep(priority=5, action="patch Office fleet and audit XZ",
                            target_asset_ids=["AST-026", "AST-024"],
                            rationale="Office RCE + XZ supply chain audit"),
        ]))

        obs = env.step(act(action_type="close", resolution_summary=(
            "GoAnywhere AST-025 patched 7.4.1+ CVE-2024-0204 CRITICAL 9.8. "
            "bastion AST-022 OpenSSH upgraded CVE-2024-6387 HIGH regreSSHion. "
            "runc AST-020 k8s-node-1 patch CVE-2024-21626 container escape. "
            "internal-ssh-server AST-023 OpenSSH upgrade. "
            "Office fleet AST-026 patch CVE-2023-36884 audit XZ AST-024. "
            "CVE-2023-46805 not applicable Palo Alto GlobalProtect not Ivanti. "
            "CVE-2024-1709 not applicable no ScreenConnect in inventory. "
            "upgrade patch complete."
        )))
        assert obs.done
        assert float(obs.reward) >= 0.65

    def test_task3_missing_key_actions_low_score(self, env):
        """A Task 3 episode that skips applicability checks and remediation scores poorly."""
        env.reset(task_id="task_full_triage")
        # Only close immediately — no assess, classify, check_applicability, or recommend
        obs = env.step(act(action_type="close",
                           resolution_summary="done everything is fine"))
        assert obs.done
        assert float(obs.reward) < 0.30

    def test_task3_reward_bounded(self, env):
        """Reward must stay in [0.0, 1.0] across all Task 3 steps."""
        env.reset(task_id="task_full_triage")
        for query in ["openssh", "runc", "goanywhere", "office", "ivanti",
                      "xz", "terrapin", "screenconnect"]:
            obs = env.step(act(action_type="assess", query=query))
            assert 0.0 <= float(obs.reward) <= 1.0
            if obs.done:
                break
