"""
inference.py
------------
ArmorFlo baseline inference script.

REQUIRED env vars (per competition spec):
  API_BASE_URL  — LLM API endpoint  (default: https://api.openai.com/v1)
  MODEL_NAME    — model identifier  (default: gpt-4o-mini)
  HF_TOKEN      — API key           (fallback: OPENAI_API_KEY)

Uses the OpenAI Client for all LLM calls.
Runtime target: < 20 min on vcpu=2, memory=8gb.

Usage:
    API_BASE_URL=https://router.huggingface.co/v1 MODEL_NAME=meta-llama/Llama-3.1-8B-Instruct HF_TOKEN=hf_... python inference.py
    python inference.py --task task_classify_severity
    python inference.py --quiet
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
import pathlib
from typing import Dict, Optional

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

try:
    from openai import OpenAI
except ImportError:
    print("ERROR: openai not installed. Run: pip install openai")
    sys.exit(1)

from server.armorflo_environment import ArmorFloEnvironment
from models import ArmorFloAction, ArmorFloObservation, RemediationStep


SYSTEM_PROMPT = textwrap.dedent("""
You are an expert Application Security (AppSec) analyst performing vulnerability triage.

You receive a vulnerability triage report with CVE details and an asset inventory.
At each step respond with exactly ONE action as a valid JSON object.

Available actions — set action_type and fill only the relevant fields:

1. assess — gather more context
   {"action_type": "assess", "query": "<question about CVE, asset, or remediation>"}

2. classify — declare severity and affected components
   {"action_type": "classify",
    "severity_tier": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW",
    "affected_components": ["<asset_id>", ...],
    "cvss_score_estimate": <0.0-10.0>}

3. check_applicability — mark a CVE applicable or not for one asset
   {"action_type": "check_applicability",
    "cve_id": "<CVE-XXXX-XXXXX>",
    "asset_id": "<AST-XXX>",
    "applicable": true|false,
    "inapplicability_reason": "<reason if false, else empty string>"}

4. recommend — submit prioritised remediation plan
   {"action_type": "recommend",
    "remediation_plan": [
      {"priority": 1, "action": "<what to do>",
       "target_asset_ids": ["<AST-XXX>"], "rationale": "<why>"},
      ...
    ]}

5. escalate — escalate to a team
   {"action_type": "escalate",
    "team": "security"|"platform"|"network"|"development"|"management",
    "justification": "<reason>"}

6. defer — defer a CVE
   {"action_type": "defer",
    "defer_reason": "<reason>", "defer_until": "<YYYY-MM-DD>"}

7. close — close the report with a full summary
   {"action_type": "close",
    "resolution_summary": "<comprehensive summary: findings, applicability decisions, actions taken, rationale>"}

Strategy:
- Use assess to understand CVE details and asset versions before deciding.
- Use check_applicability for every CVE×asset pair you determine applicable or not.
- CVEs with no affected assets in inventory should be marked not-applicable on all assets.
- Prioritise internet-facing critical assets in your remediation plan.
- Escalate to the appropriate team before closing.
- Your resolution_summary must mention all CVEs, all affected assets, and actions taken.

Respond ONLY with a single JSON object. No markdown fences, no explanation outside JSON.
""").strip()


def _format_obs(obs: ArmorFloObservation) -> str:
    lines = [f"=== {obs.report_id} | {obs.task_id} | step {obs.step_count}/{obs.max_steps} ===\n"]

    lines.append("VULNERABILITY REPORTS:")
    for r in obs.reports:
        tier = ("CRITICAL" if r.cvss_score >= 9.0 else
                "HIGH"     if r.cvss_score >= 7.0 else
                "MEDIUM"   if r.cvss_score >= 4.0 else "LOW")
        lines.append(
            f"  [{r.cve_id}] {r.title}\n"
            f"    CVSS {r.cvss_score} ({tier}) | "
            f"{'PATCH AVAILABLE' if r.patch_available else 'NO PATCH'} | "
            f"{'EXPLOIT PUBLIC' if r.exploit_public else 'no public exploit'}\n"
            f"    Affected products: {', '.join(r.affected_products[:2])}\n"
            f"    {r.description[:180]}..."
        )

    lines.append("\nASSET INVENTORY:")
    for a in obs.assets:
        lines.append(
            f"  [{a.asset_id}] {a.name} — {a.product} {a.version} "
            f"| {a.environment} | internet={a.internet_facing} | crit={a.business_criticality}"
        )

    if obs.applicability_decisions:
        lines.append("\nAPPLICABILITY DECISIONS:")
        for cve_id, assets in obs.applicability_decisions.items():
            for asset_id, dec in assets.items():
                s = "APPLICABLE" if dec.get("applicable") else f"NOT APPLICABLE ({dec.get('reason','')})"
                lines.append(f"  {cve_id} × {asset_id}: {s}")

    if obs.assess_result:
        lines.append(f"\nASSESS RESULT:\n{obs.assess_result}")

    return "\n".join(lines)


def run_episode(
    env: ArmorFloEnvironment,
    client: OpenAI,
    task_id: str,
    model: str = "gpt-4o-mini",
    verbose: bool = True,
) -> float:
    """Run one full episode and return final score (0.0–1.0)."""
    obs = env.reset(task_id=task_id)
    conversation: list = []
    final_score = 0.0
    step_num = 0

    if verbose:
        print(f"\n{'='*60}\n  Task: {task_id}\n  Model: {model}\n{'='*60}")

    print(f"[START] task={task_id}", flush=True)

    for step_num in range(obs.max_steps):
        user_content = _format_obs(obs)
        conversation.append({"role": "user", "content": user_content})

        try:
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "system", "content": SYSTEM_PROMPT}] + conversation,
                temperature=0.0,
                max_tokens=1024,
                response_format={"type": "json_object"},
            )
            raw_action = response.choices[0].message.content
        except Exception as e:
            if verbose:
                print(f"  LLM ERROR: {e}")
            raw_action = '{"action_type": "assess", "query": "what are the CVEs and assets present"}'

        conversation.append({"role": "assistant", "content": raw_action})

        if verbose:
            print(f"\n  Step {step_num + 1}: {raw_action[:160]}...")

        try:
            action_dict = json.loads(raw_action)
            if "remediation_plan" in action_dict and action_dict["remediation_plan"]:
                action_dict["remediation_plan"] = [
                    RemediationStep(**s) if isinstance(s, dict) else s
                    for s in action_dict["remediation_plan"]
                ]
            action = ArmorFloAction(**action_dict)
            obs    = env.step(action)
        except Exception as e:
            if verbose:
                print(f"  ERROR: {e}")
            try:
                obs = env.step(ArmorFloAction(
                    action_type="assess", query="what are the CVEs and assets present"
                ))
            except Exception:
                break

        final_score = float(obs.reward) if obs.reward is not None else final_score
        final_score = max(0.0001, min(0.9999, final_score))
        print(f"[STEP] step={step_num + 1} reward={final_score:.4f}", flush=True)
        if obs.done:
            break

    if verbose:
        print(f"\n  --- Score: {final_score:.3f} ---")
        for k, v in (obs.score_breakdown or {}).items():
            if isinstance(v, float) and v != 0.0:
                print(f"    {k}: {v:.3f}")

    final_score = max(0.0001, min(0.9999, final_score))
    print(f"[END] task={task_id} score={final_score:.4f} steps={step_num + 1}", flush=True)

    return final_score


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ArmorFlo inference script — uses API_BASE_URL, MODEL_NAME, HF_TOKEN"
    )
    parser.add_argument("--task",  default=None,
                        help="Single task ID (default: all tasks)")
    parser.add_argument("--model", default=None,
                        help="Override MODEL_NAME env var")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    api_base = os.environ.get("API_BASE_URL", "https://router.huggingface.co/v1")
    api_key  = os.environ.get("HF_TOKEN") or os.environ.get("OPENAI_API_KEY", "")
    model    = args.model or os.environ.get("MODEL_NAME", "gpt-4o-mini")

    if not api_key:
        print("ERROR: Set HF_TOKEN or OPENAI_API_KEY environment variable.")
        sys.exit(1)

    client = OpenAI(api_key=api_key, base_url=api_base)

    tasks  = [args.task] if args.task else ArmorFloEnvironment.VALID_TASKS
    scores: Dict[str, float] = {}

    for task_id in tasks:
        try:
            env = ArmorFloEnvironment()
            scores[task_id] = run_episode(
                env, client, task_id,
                model=model,
                verbose=not args.quiet,
            )
        except Exception as e:
            print(f"  FAILED {task_id}: {e}")
            scores[task_id] = 0.001

    print(f"\n{'='*60}")
    print(f"  ARMORFLO BASELINE RESULTS  (model: {model})")
    print(f"{'='*60}")
    for task_id, score in scores.items():
        bar = "█" * int(score * 20)
        print(f"  {task_id:<42} {score:.3f}  {bar}")
    if scores:
        avg = sum(scores.values()) / len(scores)
        print(f"  {'AVERAGE':<42} {avg:.3f}")
    print("=" * 60)


if __name__ == "__main__":
    main()
