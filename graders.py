"""
armorflo/graders.py
-------------------
Deterministic task-specific graders for ArmorFlo.
All scores [0.0, 1.0]. Pure functions of episode state — no randomness.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
try:
    from .models import RewardBreakdown
except ImportError:
    from models import RewardBreakdown


_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "": 0}


def _severity_score(predicted: str, expected: str) -> float:
    if not predicted:
        return 0.0
    if predicted == expected:
        return 1.0
    dist = abs(_SEVERITY_ORDER.get(predicted, 0) - _SEVERITY_ORDER.get(expected, 0))
    return 0.5 if dist == 1 else 0.0


def _cvss_accuracy(predicted: float, expected: float) -> float:
    """Linear decay: full credit ≤0.5 diff, zero at ≥3.0 diff."""
    diff = abs(predicted - expected)
    if diff <= 0.5:
        return 1.0
    if diff >= 3.0:
        return 0.0
    return round(1.0 - (diff - 0.5) / 2.5, 3)


def _applicability_f1(
    decisions: Dict[str, Dict[str, Any]],
    ground_truth_map: Dict[str, Dict[str, bool]],
) -> float:
    """
    Micro-averaged F1 over all (cve_id, asset_id) applicability decisions.
    True-negatives (correctly said not-applicable) are not counted in recall
    to avoid inflating scores for doing nothing.
    """
    tp = fp = fn = 0
    for cve_id, asset_map in ground_truth_map.items():
        for asset_id, expected in asset_map.items():
            pred = decisions.get(cve_id, {}).get(asset_id)
            if pred is None:
                if expected:
                    fn += 1
                continue
            pred_applicable = pred.get("applicable", True)
            if expected and pred_applicable:
                tp += 1
            elif expected and not pred_applicable:
                fn += 1
            elif not expected and pred_applicable:
                fp += 1
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    if precision + recall == 0:
        return 0.0
    return round(2 * precision * recall / (precision + recall), 3)


def _remediation_score(action_history: List[Dict], required: List[Dict]) -> float:
    """LCS-based ordering + presence score for remediation plans."""
    if not required:
        return 1.0

    all_steps: List[Dict] = []
    for a in action_history:
        if a.get("action_type") == "recommend":
            for step in a.get("remediation_plan", []):
                all_steps.append(step)

    def targets_of(r):
        return set(r.get("target_asset_ids", []))

    hits = 0
    for req in required:
        req_t = targets_of(req)
        for ex in all_steps:
            if req_t & targets_of(ex):
                hits += 1
                break
    presence = hits / len(required)

    def match_key(r):
        return "|".join(sorted(targets_of(r)))

    required_keys = [match_key(r) for r in required]
    executed_keys = [match_key(s) for s in all_steps]

    def lcs(a, b):
        n, m = len(a), len(b)
        dp = [[0] * (m + 1) for _ in range(n + 1)]
        for i in range(1, n + 1):
            for j in range(1, m + 1):
                dp[i][j] = dp[i-1][j-1] + 1 if a[i-1] == b[j-1] else max(dp[i-1][j], dp[i][j-1])
        return dp[n][m]

    exec_matched = [k for k in executed_keys if k in required_keys]
    order = lcs(exec_matched, required_keys) / len(required_keys) if required_keys else 0.0

    return round(0.6 * presence + 0.4 * order, 3)


def _summary_quality(note: Optional[str], keywords: List[str]) -> float:
    if not note or not keywords:
        return 0.0
    n = note.lower()
    return round(sum(1 for kw in keywords if kw.lower() in n) / len(keywords), 3)


def _efficiency_bonus(steps: int, par: int, max_steps: int) -> float:
    if steps <= par:
        return 0.05
    over   = steps - par
    window = max_steps - par
    return round(max(0.0, 0.05 * (1 - over / window)), 3)


def _loop_penalty(history: List[Dict]) -> float:
    queries = [
        a.get("query", "").strip().lower()
        for a in history if a.get("action_type") == "assess"
    ]
    seen: Dict[str, int] = {}
    pen = 0.0
    for q in queries:
        seen[q] = seen.get(q, 0) + 1
        if seen[q] > 2:
            pen += 0.03
    return round(min(0.15, pen), 3)


def _false_positive_penalty(
    decisions: Dict[str, Dict[str, Any]],
    gt_map: Dict[str, Dict[str, bool]],
) -> float:
    """Penalise marking a truly-applicable CVE×asset as not-applicable."""
    pen = 0.0
    for cve_id, asset_map in gt_map.items():
        for asset_id, expected in asset_map.items():
            if not expected:
                continue
            pred = decisions.get(cve_id, {}).get(asset_id, {})
            if pred and not pred.get("applicable", True):
                pen += 0.05
    return round(min(0.20, pen), 3)


def _set_total(bd: RewardBreakdown, raw: float) -> RewardBreakdown:
    object.__setattr__(bd, "_task_total", max(0.0, min(1.0, round(raw, 4))))
    return bd


def grade_classify_severity(
    episode_state: Dict[str, Any],
    ground_truth: Dict[str, Any],
) -> RewardBreakdown:
    """Task 1 — weights: severity 40%, cvss 20%, applicability 20%, summary 10%, eff 10%."""
    classify  = episode_state.get("classify_action") or {}
    close     = episode_state.get("close_action") or {}
    history   = episode_state.get("action_history", [])
    steps     = episode_state.get("step_count", 0)
    decisions = episode_state.get("applicability_decisions", {})
    assets    = episode_state.get("assets", [])

    sev  = _severity_score(classify.get("severity_tier", ""), ground_truth["severity_tier"])
    cvss = _cvss_accuracy(classify.get("cvss_score_estimate", 0.0), ground_truth["cvss_score"])

    cve_id = "CVE-2021-44228"
    gt_map = {cve_id: {a["asset_id"]: (a["asset_id"] in ground_truth["applicable_assets"])
                       for a in assets}}
    app  = _applicability_f1(decisions, gt_map)
    fp   = _false_positive_penalty(decisions, gt_map)

    summ = _summary_quality(close.get("resolution_summary", ""), ground_truth["resolution_keywords"])
    eff  = _efficiency_bonus(steps, ground_truth["par_steps"], episode_state.get("max_steps", 10))
    loop = _loop_penalty(history)

    raw = sev * 0.40 + cvss * 0.20 + app * 0.20 + summ * 0.10 + eff - loop - fp
    return _set_total(RewardBreakdown(
        severity_score=sev, cvss_score_accuracy=cvss, applicability_score=app,
        summary_quality=summ, efficiency_bonus=eff, loop_penalty=loop, false_positive_penalty=fp,
    ), raw)


def grade_mixed_applicability(
    episode_state: Dict[str, Any],
    ground_truth: Dict[str, Any],
) -> RewardBreakdown:
    """Task 2 — weights: applicability 30%, remediation 25%, sev 15%, escalation 15%, summary 10%, eff 5%."""
    history   = episode_state.get("action_history", [])
    close     = episode_state.get("close_action") or {}
    steps     = episode_state.get("step_count", 0)
    decisions = episode_state.get("applicability_decisions", {})

    app = _applicability_f1(decisions, ground_truth["applicable_map"])
    fp  = _false_positive_penalty(decisions, ground_truth["applicable_map"])
    rem = _remediation_score(history, ground_truth["required_remediation"])

    classify_actions = [a for a in history if a.get("action_type") == "classify"]
    sev_scores = []
    for cve_id, exp_tier in ground_truth["severity_tiers"].items():
        best = 0.0
        for a in classify_actions:
            if cve_id in str(a):
                best = max(best, _severity_score(a.get("severity_tier", ""), exp_tier))
        if not sev_scores or best > 0:
            sev_scores.append(best)
    if not sev_scores and classify_actions:
        tier = classify_actions[-1].get("severity_tier", "")
        sev_scores = [_severity_score(tier, t) for t in ground_truth["severity_tiers"].values()]
    sev_avg = round(sum(sev_scores) / len(sev_scores), 3) if sev_scores else 0.0

    escalations = [a.get("team") for a in history if a.get("action_type") == "escalate"]
    esc = 1.0 if ground_truth.get("required_escalation") in escalations else 0.0

    summ = _summary_quality(close.get("resolution_summary", ""), ground_truth["resolution_keywords"])
    eff  = _efficiency_bonus(steps, ground_truth["par_steps"], episode_state.get("max_steps", 20))
    loop = _loop_penalty(history)

    raw = app * 0.30 + rem * 0.25 + sev_avg * 0.15 + esc * 0.15 + summ * 0.10 + eff - loop - fp
    return _set_total(RewardBreakdown(
        severity_score=sev_avg, applicability_score=app, remediation_score=rem,
        escalation_score=esc, summary_quality=summ, efficiency_bonus=eff,
        loop_penalty=loop, false_positive_penalty=fp,
    ), raw)


def grade_full_triage(
    episode_state: Dict[str, Any],
    ground_truth: Dict[str, Any],
) -> RewardBreakdown:
    """Task 3 — weights: applicability 25%, remediation 25%, sev 15%, escalation 15%, summary 15%, eff 5%."""
    history   = episode_state.get("action_history", [])
    close     = episode_state.get("close_action") or {}
    steps     = episode_state.get("step_count", 0)
    decisions = episode_state.get("applicability_decisions", {})

    app = _applicability_f1(decisions, ground_truth["applicable_map"])
    fp  = _false_positive_penalty(decisions, ground_truth["applicable_map"])
    rem = _remediation_score(history, ground_truth["required_remediation"])

    classify_actions = [a for a in history if a.get("action_type") == "classify"]
    sev_scores = []
    for cve_id, exp_tier in ground_truth["severity_tiers"].items():
        best = 0.0
        for a in classify_actions:
            if cve_id in str(a):
                best = max(best, _severity_score(a.get("severity_tier", ""), exp_tier))
        sev_scores.append(best)
    sev_avg = round(sum(sev_scores) / len(sev_scores), 3) if sev_scores else 0.0

    escalations = [a.get("team") for a in history if a.get("action_type") == "escalate"]
    esc = 1.0 if ground_truth.get("required_escalation") in escalations else 0.0

    summ = _summary_quality(close.get("resolution_summary", ""), ground_truth["resolution_keywords"])
    eff  = _efficiency_bonus(steps, ground_truth["par_steps"], episode_state.get("max_steps", 35))
    loop = _loop_penalty(history)

    raw = app * 0.25 + rem * 0.25 + sev_avg * 0.15 + esc * 0.15 + summ * 0.15 + eff - loop - fp
    return _set_total(RewardBreakdown(
        severity_score=sev_avg, applicability_score=app, remediation_score=rem,
        escalation_score=esc, summary_quality=summ, efficiency_bonus=eff,
        loop_penalty=loop, false_positive_penalty=fp,
    ), raw)


GRADERS = {
    "task_classify_severity":   grade_classify_severity,
    "task_mixed_applicability": grade_mixed_applicability,
    "task_full_triage":         grade_full_triage,
}


def get_total(bd: RewardBreakdown) -> float:
    return getattr(bd, "_task_total", bd.total)


def _clamp(v: float) -> float:
    return round(max(0.0001, min(0.9999, float(v))), 4)


def clamp_breakdown(bd):
    from models import RewardBreakdown
    return RewardBreakdown(
        severity_score=_clamp(bd.severity_score),
        cvss_score_accuracy=_clamp(bd.cvss_score_accuracy),
        applicability_score=_clamp(bd.applicability_score),
        remediation_score=_clamp(bd.remediation_score),
        escalation_score=_clamp(bd.escalation_score),
        summary_quality=_clamp(bd.summary_quality),
        efficiency_bonus=_clamp(bd.efficiency_bonus),
        loop_penalty=_clamp(bd.loop_penalty),
        false_positive_penalty=_clamp(bd.false_positive_penalty),
    )
