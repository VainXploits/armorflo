"""
armorflo/server/armorflo_environment.py
----------------------------------------
ArmorFloEnvironment — implements openenv.core.env_server.interfaces.Environment.

step()  → ArmorFloObservation  (reward + done embedded per OpenEnv spec)
reset() → ArmorFloObservation
state   → @property returning State
"""
from __future__ import annotations

import copy
import re
import sys
import pathlib
from typing import Any, Dict, List, Optional
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    from ..models import ArmorFloAction, ArmorFloObservation, VulnerabilityReport, AssetRecord
    from ..scenarios import ALL_SCENARIOS
    from ..graders import GRADERS, get_total
except ImportError:
    from models import ArmorFloAction, ArmorFloObservation, VulnerabilityReport, AssetRecord
    from scenarios import ALL_SCENARIOS
    from graders import GRADERS, get_total


class ArmorFloEnvironment(Environment):
    """
    ArmorFlo — Vulnerability Report Triage Environment.

    An agent receives realistic CVE reports alongside an organisational asset
    inventory and must: assess applicability, classify severity, build a
    prioritised remediation plan, escalate appropriately, and produce a
    resolution summary — mirroring real AppSec analyst workflows.

    Conforms to OpenEnv Environment[ArmorFloAction, ArmorFloObservation, State].
    """

    SUPPORTS_CONCURRENT_SESSIONS: bool = True
    VALID_TASKS = list(ALL_SCENARIOS.keys())

    def __init__(self) -> None:
        super().__init__()
        self._scenario: Optional[Dict[str, Any]] = None
        self._ground_truth: Optional[Dict[str, Any]] = None
        self._assess_data: Dict[str, str] = {}
        self._task_id: Optional[str] = None
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._done: bool = False
        self._action_history: List[Dict[str, Any]] = []
        self._classify_action: Optional[Dict] = None
        self._close_action: Optional[Dict] = None
        self._applicability_decisions: Dict[str, Dict[str, Any]] = {}
        self._assess_cache: Dict[str, str] = {}


    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        task_id: Optional[str] = None,
        **kwargs,
    ) -> ArmorFloObservation:
        if task_id is None:
            task_id = self.VALID_TASKS[0]
        if task_id not in ALL_SCENARIOS:
            raise ValueError(f"Unknown task_id {task_id!r}. Valid: {self.VALID_TASKS}")

        raw = copy.deepcopy(ALL_SCENARIOS[task_id])
        self._ground_truth = raw.pop("_ground_truth")
        self._assess_data  = raw.pop("_assess_data", {})
        self._scenario     = raw
        self._task_id      = task_id
        self._done         = False
        self._action_history.clear()
        self._classify_action  = None
        self._close_action     = None
        self._applicability_decisions.clear()
        self._assess_cache.clear()
        self._state = State(episode_id=episode_id or str(uuid4()), step_count=0)
        return self._build_obs()

    def step(
        self,
        action: ArmorFloAction,
        timeout_s: Optional[float] = None,
        **kwargs,
    ) -> ArmorFloObservation:
        if self._done:
            raise RuntimeError("Episode is done. Call reset() to start a new episode.")
        if self._scenario is None:
            self.reset()

        raw = action.model_dump()
        self._action_history.append(raw)
        self._state.step_count += 1

        assess_result: Optional[str] = None
        at = action.action_type

        if at == "assess":
            assess_result = self._handle_assess(action.query)
        elif at == "classify":
            self._classify_action = raw
        elif at == "check_applicability":
            if action.cve_id and action.asset_id:
                if action.cve_id not in self._applicability_decisions:
                    self._applicability_decisions[action.cve_id] = {}
                self._applicability_decisions[action.cve_id][action.asset_id] = {
                    "applicable": action.applicable,
                    "reason":     action.inapplicability_reason,
                }
        elif at == "close":
            self._close_action = raw
            self._done = True

        max_steps = self._scenario.get("max_steps", 20)
        if self._state.step_count >= max_steps and not self._done:
            self._done = True

        reward, breakdown = self._compute_reward()
        return self._build_obs(
            assess_result=assess_result,
            reward=reward,
            done=self._done,
            breakdown=breakdown,
        )

    @property
    def state(self) -> State:
        return self._state


    def _build_obs(
        self,
        assess_result: Optional[str] = None,
        reward: float = 0.0,
        done: bool = False,
        breakdown: Optional[Dict[str, float]] = None,
    ) -> ArmorFloObservation:
        s = self._scenario or {}
        return ArmorFloObservation(
            task_id      = self._task_id or "",
            report_id    = s.get("report_id", ""),
            step_count   = self._state.step_count,
            max_steps    = s.get("max_steps", 20),
            reports      = [VulnerabilityReport(**r) for r in s.get("reports", [])],
            assets       = [AssetRecord(**a)          for a in s.get("assets", [])],
            applicability_decisions = dict(self._applicability_decisions),
            assess_result   = assess_result,
            score_breakdown = breakdown or {},
            reward = round(max(0.0001, min(0.9999, reward)), 4),
            done   = done,
        )

    def _handle_assess(self, query: str) -> str:
        q = query.strip().lower()
        if q in self._assess_cache:
            return f"[cached] {self._assess_cache[q]}"

        keywords = re.findall(r"[a-z0-9\-\._]+", q)
        result = None

        for topic, content in self._assess_data.items():
            if any(kw in topic.lower() or kw in content.lower()[:120] for kw in keywords):
                result = content
                break

        if not result:
            for report in self._scenario.get("reports", []):
                if any(kw in report["cve_id"].lower() or kw in report["description"].lower()[:200]
                       for kw in keywords):
                    r = report
                    result = (
                        f"[CVE DETAIL] {r['cve_id']} — {r['title']}\n"
                        f"  CVSS: {r['cvss_score']} | Patch: {r['patch_available']} | "
                        f"Exploit public: {r['exploit_public']}\n"
                        f"  Affected: {', '.join(r['affected_products'][:3])}"
                    )
                    break

        if not result:
            for asset in self._scenario.get("assets", []):
                if any(kw in asset["name"].lower() or kw in asset["product"].lower()
                       or kw in asset["asset_id"].lower() for kw in keywords):
                    a = asset
                    result = (
                        f"[ASSET] {a['asset_id']} {a['name']}\n"
                        f"  Product: {a['product']} {a['version']}\n"
                        f"  Env: {a['environment']} | Internet-facing: {a['internet_facing']} "
                        f"| Criticality: {a['business_criticality']}"
                    )
                    break

        if not result:
            result = (
                "No specific data found. Try: a CVE ID, product name (e.g. 'nginx', 'openssh', "
                "'glibc'), asset name, 'cvss', 'remediation', or 'exploit'."
            )

        self._assess_cache[q] = result
        return result

    def _compute_reward(self):
        if not self._task_id or not self._ground_truth:
            return 0.0, {}
        grader = GRADERS.get(self._task_id)
        if not grader:
            return 0.0, {}
        episode_state = {
            "classify_action":         self._classify_action,
            "close_action":            self._close_action,
            "action_history":          self._action_history,
            "step_count":              self._state.step_count,
            "applicability_decisions": self._applicability_decisions,
            "max_steps":               (self._scenario or {}).get("max_steps", 20),
            "assets":                  (self._scenario or {}).get("assets", []),
        }
        bd    = grader(episode_state, self._ground_truth)
        total = get_total(bd)
        return round(total, 4), bd.model_dump()
