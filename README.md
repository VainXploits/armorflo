---
title: ArmorFlo
emoji: 🛡️
colorFrom: red
colorTo: red
sdk: docker
pinned: false
tags:
  - openenv
---

# ArmorFlo — Vulnerability Report Triage Environment

**ArmorFlo** is a production-grade [OpenEnv](https://github.com/meta-pytorch/OpenEnv)-compatible reinforcement learning environment that simulates real-world Application Security (AppSec) vulnerability triage workflows.

An AI agent receives realistic CVE reports alongside an organisational asset inventory and must do exactly what a human security analyst does: assess exploitability in context, classify severity, determine which assets are actually affected, build a prioritised remediation plan, escalate to the right team, and produce a written resolution summary.

> **Why this domain?** CVE triage is one of the highest-volume, highest-stakes tasks in enterprise security. The average organisation receives hundreds of CVEs per week; deciding which ones matter for *your specific environment* is genuinely hard and time-consuming. ArmorFlo is the first OpenEnv environment to model this workflow, making it immediately valuable for training and evaluating security-reasoning agents.

---

## Environment Description

Each episode presents a realistic vulnerability triage scenario:

- **CVE reports** — real CVE IDs with accurate CVSS scores, vectors, affected products, patch status, and exploit availability
- **Asset inventory** — services with product names, versions, environments, internet-exposure flags, and business criticality
- **Assess actions** — agent can query for additional context (runbook-style guidance, version-specific applicability info)
- **Mixed applicability** — some CVEs in the report do not affect any asset in inventory (false positives the agent must suppress)
- **Prioritised remediation** — internet-facing critical assets must be addressed before internal low-criticality ones
- **Escalation** — different tasks require escalating to different teams (security team vs. management)

---

## Action Space

| Action | Key Fields | Description |
|--------|-----------|-------------|
| `assess` | `query: str` | Query for CVE context, asset details, or remediation guidance |
| `classify` | `severity_tier`, `affected_components`, `cvss_score_estimate` | Declare CVSS severity (CRITICAL/HIGH/MEDIUM/LOW) and affected assets |
| `check_applicability` | `cve_id`, `asset_id`, `applicable`, `inapplicability_reason` | Mark a CVE as applicable or not for a specific asset |
| `recommend` | `remediation_plan: List[RemediationStep]` | Submit a prioritised remediation plan (priority, action, target_asset_ids, rationale) |
| `escalate` | `team`, `justification` | Escalate to security / platform / network / development / management |
| `defer` | `defer_reason`, `defer_until` | Defer a CVE with documented reason and revisit date |
| `close` | `resolution_summary: str` | Close the report with a comprehensive post-triage summary |

Full JSON schema available at `GET /schema` and `GET /tasks`.

---

## Observation Space

| Field | Type | Description |
|-------|------|-------------|
| `reports` | `List[VulnerabilityReport]` | CVE reports in scope (cve_id, title, cvss_score, cvss_vector, affected_products, patch_available, exploit_public) |
| `assets` | `List[AssetRecord]` | Asset inventory (asset_id, name, product, version, environment, internet_facing, business_criticality) |
| `applicability_decisions` | `Dict` | Decisions recorded so far: `{cve_id: {asset_id: {applicable, reason}}}` |
| `assess_result` | `str \| None` | Result of the most recent assess action |
| `step_count` | `int` | Current step within the episode |
| `max_steps` | `int` | Maximum allowed steps |
| `reward` | `float` | Current episode score (0.0–1.0), updated every step |
| `done` | `bool` | Whether the episode has terminated |

---

## Tasks

### Task 1 — Severity Classification `[easy]`

**Incident:** CVE-2021-44228 (Log4Shell) — CVSS 10.0. Three assets running Apache Log4j; one is already patched (version 2.17.1).

**Agent must:** Classify as CRITICAL, identify that AST-001 and AST-002 are affected, correctly mark AST-003 as not-applicable (patched version), and close with a summary covering upgrade actions.

**Grader weights:** severity 40% · CVSS accuracy 20% · applicability F1 20% · summary quality 10% · efficiency 10%

**Par steps:** 5 | **Max steps:** 10

---

### Task 2 — Mixed Applicability `[medium]`

**Incident:** Three CVEs across four assets.
- CVE-2023-44487 (HTTP/2 Rapid Reset) — affects only nginx AST-010
- CVE-2023-4911 (glibc Looney Tunables) — affects AST-011 (glibc 2.35) but NOT AST-012 (glibc 2.31, out of range)
- CVE-2023-20198 (Cisco IOS XE) — **zero applicable assets** (inventory has Cisco IOS, not IOS XE)

**Agent must:** Correctly determine per-asset applicability for all CVE×asset pairs, build a 2-step remediation plan (nginx upgrade → glibc patch), escalate to the security team, and suppress the Cisco CVE as non-applicable.

**Grader weights:** applicability F1 30% · remediation 25% · severity 15% · escalation 15% · summary 10% · efficiency 5%

**Par steps:** 10 | **Max steps:** 20

---

### Task 3 — Full Triage `[hard]`

**Incident:** Eight CVEs across eight assets. Two CVEs (Ivanti Connect Secure, ConnectWise ScreenConnect) have **zero applicable assets** in inventory and must be correctly suppressed. The remaining six affect specific assets with nuanced version-matching requirements.

**Agent must:**
1. Correctly assess applicability for all 64 CVE×asset combinations
2. Build a **5-step prioritised remediation plan in the correct order**: GoAnywhere (AST-025) → OpenSSH bastion (AST-022) → runc k8s-node (AST-020) → OpenSSH internal (AST-023) → Office + XZ audit (AST-026, AST-024)
3. Escalate to **management** (business impact severity)
4. Produce a resolution summary covering all CVEs, correct applicability decisions, and actions taken

**Grader weights:** applicability F1 25% · remediation ordering 25% · severity 15% · escalation 15% · summary 15% · efficiency 5%

**Par steps:** 18 | **Max steps:** 35

---

## Reward Function

ArmorFlo provides **shaped rewards at every step** — not a binary end-of-episode signal.

```
score = (
    severity_score        × w_sev    # CVSS tier accuracy; 0.5 for adjacent tier
  + cvss_score_accuracy   × w_cvss   # linear decay: full credit ≤0.5 diff, zero at ≥3.0
  + applicability_score   × w_app    # micro-averaged F1 over all CVE×asset decisions
  + remediation_score     × w_rem    # 60% presence + 40% LCS ordering score
  + escalation_score      × w_esc    # correct team escalated (binary)
  + summary_quality       × w_summ   # keyword coverage of resolution summary
  + efficiency_bonus                 # up to +0.05 for completing under par steps
  - loop_penalty                     # −0.03 per repeated assess query (cap 0.15)
  - false_positive_penalty           # −0.05 per applicable CVE incorrectly marked not-applicable
)
```

All component scores are in `[0.0, 1.0]`. The weighted sum is clamped to `[0.0, 1.0]`.

**Partial progress signals:** An agent that correctly classifies severity but misses applicability decisions scores ~0.40. An agent that additionally gets applicability right scores ~0.65. Full credit requires correct remediation ordering.

---

## Baseline Scores

Measured with `gpt-4o-mini` at temperature 0 via the OpenAI API:

| Task | Score |
|------|-------|
| task_classify_severity | 0.71 |
| task_mixed_applicability | 0.48 |
| task_full_triage | 0.29 |
| **Average** | **0.49** |

---

## Setup & Usage

### Prerequisites

```bash
git clone https://huggingface.co/spaces/YOUR_USERNAME/armorflo
cd armorflo
pip install uv
uv sync
```

### Run the server locally

```bash
uv run server
# or
uvicorn server.app:app --host 0.0.0.0 --port 8000 --reload
```

Server will be available at `http://localhost:8000`. Swagger UI at `http://localhost:8000/docs`.

### Quick smoke test

```bash
# Health check
curl http://localhost:8000/health

# List tasks + action schema
curl http://localhost:8000/tasks | python -m json.tool

# Start an episode
curl -s -X POST http://localhost:8000/reset \
  -H 'Content-Type: application/json' \
  -d '{"task_id": "task_classify_severity"}' | python -m json.tool

# Score an episode
curl -s -X POST http://localhost:8000/grader \
  -H 'Content-Type: application/json' \
  -d '{
    "task_id": "task_classify_severity",
    "classify_action": {"severity_tier": "CRITICAL", "cvss_score_estimate": 10.0},
    "close_action": {"resolution_summary": "CVE-2021-44228 Log4Shell CRITICAL. Upgrade AST-001 and AST-002. AST-003 not affected."},
    "step_count": 3,
    "max_steps": 10,
    "assets": [{"asset_id": "AST-001"}, {"asset_id": "AST-002"}, {"asset_id": "AST-003"}]
  }' | python -m json.tool
```

### Run the inference script

```bash
export API_BASE_URL=https://api.openai.com/v1
export MODEL_NAME=gpt-4o-mini
export HF_TOKEN=sk-...          # or OPENAI_API_KEY=sk-...

# All 3 tasks
python inference.py

# Single task
python inference.py --task task_classify_severity

# Quiet mode (scores only)
python inference.py --quiet
```

### Run tests

```bash
pytest tests/ -v
```

### Docker

```bash
docker build -f server/Dockerfile -t armorflo .
docker run -p 8000:8000 \
  -e API_BASE_URL=https://api.openai.com/v1 \
  -e MODEL_NAME=gpt-4o-mini \
  -e HF_TOKEN=sk-... \
  armorflo
```

---

## Project Structure

```
armorflo/
├── models.py                    # ArmorFloAction, ArmorFloObservation (OpenEnv types)
├── scenarios.py                 # 3 CVE triage scenarios with ground truth
├── graders.py                   # Deterministic per-task graders
├── inference.py                 # Inference script (API_BASE_URL/MODEL_NAME/HF_TOKEN)
├── server/
│   ├── app.py                   # FastAPI: create_app + /tasks /grader /baseline
│   ├── armorflo_environment.py  # ArmorFloEnvironment (OpenEnv Environment subclass)
│   └── Dockerfile               # Multi-stage Docker build
├── tests/
│   └── test_env.py              # 30-test suite
├── openenv.yaml                 # OpenEnv spec metadata
├── pyproject.toml               # Dependencies + server entry point
└── uv.lock                      # Pinned dependency lockfile
```

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/reset` | POST | Start new episode, returns initial observation |
| `/step` | POST | Execute action, returns observation with reward + done |
| `/state` | GET | Current environment state |
| `/schema` | GET | JSON schema for Action, Observation, State |
| `/metadata` | GET | Environment metadata |
| `/tasks` | GET | Task list with difficulty, description, and action schema |
| `/grader` | POST | Score a completed episode (no live session required) |
| `/baseline` | POST | Trigger inference script, returns scores for all tasks |
| `/docs` | GET | Swagger UI |
| `/ws` | WS | WebSocket for persistent sessions |
