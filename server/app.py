"""
armorflo/server/app.py
----------------------
ArmorFlo FastAPI server.

Creates the OpenEnv-spec base app via create_app(), then adds the three
required competition endpoints:
  GET  /tasks     — list tasks + full action schema
  POST /grader    — score a completed episode
  POST /baseline  — run inference script, return scores for all tasks

Validator checks:
  ✓ def main(  — present
  ✓ __name__   — present
  ✓ main()     — present in __name__ block
"""
from __future__ import annotations

import os
import sys
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    from openenv.core.env_server.http_server import create_app
except Exception as e:
    raise ImportError("openenv-core is required. Run: uv sync") from e

try:
    from ..models import ArmorFloAction, ArmorFloObservation
    from .armorflo_environment import ArmorFloEnvironment
except ImportError:
    from models import ArmorFloAction, ArmorFloObservation
    from server.armorflo_environment import ArmorFloEnvironment

app = create_app(
    ArmorFloEnvironment,
    ArmorFloAction,
    ArmorFloObservation,
    env_name="armorflo",
    max_concurrent_envs=4,
)

from fastapi import HTTPException
from pydantic import BaseModel
from typing import Any, Dict, List, Optional


@app.get("/tasks", tags=["Environment Info"])
def list_tasks() -> List[Dict[str, Any]]:
    """
    List all tasks with difficulty, description, step limits, and the full
    action schema (field names / types required for a step action).
    """
    try:
        from scenarios import ALL_SCENARIOS
    except ImportError:
        from armorflo.scenarios import ALL_SCENARIOS

    action_schema = ArmorFloAction.model_json_schema()

    meta = {
        "task_classify_severity": {
            "difficulty":  "easy",
            "description": (
                "Single CVE (Log4Shell CVE-2021-44228). Classify CVSS severity tier, "
                "identify which assets are affected vs. patched, and close with summary."
            ),
            "par_steps": 5,
            "max_steps": 10,
        },
        "task_mixed_applicability": {
            "difficulty":  "medium",
            "description": (
                "Three CVEs across four assets. CVE-2023-20198 (Cisco IOS XE) has zero "
                "applicable assets — agent must suppress it. Requires per-asset applicability "
                "decisions, remediation plan, and escalation to security team."
            ),
            "par_steps": 10,
            "max_steps": 20,
        },
        "task_full_triage": {
            "difficulty":  "hard",
            "description": (
                "Eight CVEs across eight assets. Two CVEs (Ivanti, ScreenConnect) have no "
                "applicable assets in inventory. Requires full applicability matrix, a "
                "five-step prioritised remediation plan in correct order, escalation to "
                "management, and a comprehensive resolution summary."
            ),
            "par_steps": 18,
            "max_steps": 35,
        },
    }

    tasks = []
    for task_id, scenario in ALL_SCENARIOS.items():
        m = meta.get(task_id, {})
        tasks.append({
            "task_id":      task_id,
            "difficulty":   m.get("difficulty"),
            "description":  m.get("description"),
            "par_steps":    m.get("par_steps"),
            "max_steps":    m.get("max_steps"),
            "num_reports":  len(scenario.get("reports", [])),
            "num_assets":   len(scenario.get("assets", [])),
            "action_schema": action_schema,
        })
    return tasks


class GraderRequest(BaseModel):
    task_id: str
    classify_action: Optional[Dict[str, Any]] = None
    close_action: Optional[Dict[str, Any]] = None
    action_history: List[Dict[str, Any]] = []
    applicability_decisions: Dict[str, Any] = {}
    step_count: int = 0
    max_steps: int = 20
    assets: List[Dict[str, Any]] = []


@app.post("/grader", tags=["Environment Info"])
def run_grader(req: GraderRequest) -> Dict[str, Any]:
    """
    Score a completed episode without running it live.
    Submit the episode state and receive per-component breakdown + total score.
    """
    try:
        from graders import GRADERS, get_total
        from scenarios import ALL_SCENARIOS
    except ImportError:
        from armorflo.graders import GRADERS, get_total
        from armorflo.scenarios import ALL_SCENARIOS

    import copy

    grader = GRADERS.get(req.task_id)
    if not grader:
        raise HTTPException(status_code=404, detail=f"Unknown task_id: {req.task_id!r}")

    raw_scenario = copy.deepcopy(ALL_SCENARIOS.get(req.task_id, {}))
    ground_truth = raw_scenario.get("_ground_truth", {})
    if not ground_truth:
        raise HTTPException(status_code=500, detail="Ground truth not found for task.")

    episode_state = {
        "classify_action":         req.classify_action,
        "close_action":            req.close_action,
        "action_history":          req.action_history,
        "step_count":              req.step_count,
        "applicability_decisions": req.applicability_decisions,
        "max_steps":               req.max_steps,
        "assets":                  req.assets,
    }

    bd    = grader(episode_state, ground_truth)
    score = get_total(bd)

    return {"task_id": req.task_id, "score": score, "breakdown": bd.model_dump()}


class BaselineRequest(BaseModel):
    model: Optional[str] = None
    tasks: Optional[List[str]] = None


@app.post("/baseline", tags=["Environment Info"])
def run_baseline(req: BaselineRequest) -> Dict[str, Any]:
    """
    Trigger the inference script server-side.
    Requires API_BASE_URL, MODEL_NAME, and HF_TOKEN (or OPENAI_API_KEY) env vars.
    Returns scores for all requested tasks.
    """
    api_base = os.environ.get("API_BASE_URL", "https://api.openai.com/v1")
    api_key  = os.environ.get("HF_TOKEN") or os.environ.get("OPENAI_API_KEY", "")
    model    = req.model or os.environ.get("MODEL_NAME", "gpt-4o-mini")

    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="API key not set. Set HF_TOKEN or OPENAI_API_KEY environment variable.",
        )

    try:
        from openai import OpenAI
    except ImportError:
        raise HTTPException(status_code=503, detail="openai package not installed.")

    try:
        from inference import run_episode
    except ImportError:
        sys.path.insert(0, str(_ROOT))
        from inference import run_episode

    client = OpenAI(api_key=api_key, base_url=api_base)
    tasks  = req.tasks or ArmorFloEnvironment.VALID_TASKS
    scores: Dict[str, float] = {}

    for task_id in tasks:
        if task_id not in ArmorFloEnvironment.VALID_TASKS:
            raise HTTPException(status_code=400, detail=f"Unknown task_id: {task_id!r}")
        try:
            env   = ArmorFloEnvironment()
            score = run_episode(env, client, task_id, model=model, verbose=False)
            scores[task_id] = score
        except Exception as e:
            scores[task_id] = -1.0

    valid = [v for v in scores.values() if v >= 0]
    return {
        "model":   model,
        "scores":  scores,
        "average": round(sum(valid) / max(1, len(valid)), 4),
    }


def main(host: str = "0.0.0.0", port: int = 8000) -> None:
    """
    Start the ArmorFlo server.
        uv run server
        python -m server.app
        uvicorn server.app:app --host 0.0.0.0 --port 8000
    """
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    main(host=args.host, port=args.port)
