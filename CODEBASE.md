# ArmorFlo codebase documentation

This file documents every module, class, function, and design decision in the ArmorFlo codebase. It replaces inline code comments as the single source of truth for how the system works.

---

## Project structure

```
armorflo/
├── models.py                    Pydantic data models (Action, Observation, domain types)
├── scenarios.py                 Three CVE triage scenarios with ground truth
├── graders.py                   Deterministic scoring functions for all three tasks
├── inference.py                 Baseline inference script using the OpenAI client
├── server/
│   ├── armorflo_environment.py  OpenEnv-compliant Environment class
│   └── app.py                   FastAPI server exposing all HTTP endpoints
├── tests/
│   └── test_env.py              62-test suite covering all three difficulty levels
├── openenv.yaml                 OpenEnv spec metadata
├── pyproject.toml               Python package config and dependency declaration
├── uv.lock                      Pinned dependency lockfile (121 packages)
├── Dockerfile                   Root Dockerfile for HF Spaces deployment
└── server/Dockerfile            Server-context Dockerfile for openenv build
```

---

## models.py

### Purpose
Defines all typed data structures that flow between the environment, the agent, and the graders. Two of these classes subclass the real OpenEnv base types so that `openenv validate` passes and `create_app` works correctly.

### `CvssVector`
Plain Pydantic model representing the eight components of a CVSS v3.1 vector string. All fields are `Literal` types constraining to valid CVSS values. Used inside `VulnerabilityReport`.

### `VulnerabilityReport`
One CVE report as presented to the agent. Fields:
- `cve_id` — real CVE identifier e.g. `CVE-2021-44228`
- `title` — human-readable name
- `description` — paragraph describing the vulnerability
- `cvss_score` — float 0.0–10.0, validated by pydantic `ge`/`le`
- `cvss_vector` — `CvssVector` instance
- `affected_products` — list of product+version strings from NVD
- `patch_available` — whether a fix exists
- `exploit_public` — whether working exploit code is publicly known
- `published_date` — ISO date string
- `references` — list of URLs

### `AssetRecord`
One server or service in the organisation's inventory. Fields:
- `asset_id` — stable identifier e.g. `AST-001`
- `name` — human name e.g. `api-gateway`
- `product` — software product name e.g. `Apache Log4j`
- `version` — exact version string; version-matching is the core challenge
- `environment` — `production`, `staging`, or `development`
- `internet_facing` — bool; internet-facing assets get higher remediation priority
- `business_criticality` — `critical`, `high`, `medium`, or `low`

### `RemediationStep`
One step in an ordered remediation plan. Fields:
- `priority` — integer; lower = fix first
- `action` — free-text description of what to do
- `target_asset_ids` — list of `AssetRecord.asset_id` values this step applies to
- `rationale` — justification for the priority

### `ArmorFloAction`
Subclasses `openenv.core.env_server.types.Action`. This inheritance is required for `create_app` and `openenv validate` to work. The base class adds `metadata: Dict` and enforces `extra="forbid"`.

The discriminator field is `action_type`. All seven action types are encoded in one flat model — unused fields default to empty string or empty list. This avoids the complexity of discriminated unions while remaining fully typed.

Action types and their active fields:

| action_type | Active fields |
|---|---|
| `assess` | `query` |
| `classify` | `severity_tier`, `affected_components`, `cvss_score_estimate` |
| `check_applicability` | `cve_id`, `asset_id`, `applicable`, `inapplicability_reason` |
| `recommend` | `remediation_plan` |
| `escalate` | `team`, `justification` |
| `defer` | `defer_reason`, `defer_until` |
| `close` | `resolution_summary` |

### `ArmorFloObservation`
Subclasses `openenv.core.env_server.types.Observation`. The base class provides `reward: float | None`, `done: bool`, and `metadata: Dict`. Subclass adds:

- `task_id` — which task is active
- `report_id` — identifier for the current report batch
- `step_count` — how many steps have been taken
- `max_steps` — episode step limit
- `reports` — list of `VulnerabilityReport` currently in scope
- `assets` — list of `AssetRecord` in the inventory
- `applicability_decisions` — dict of form `{cve_id: {asset_id: {applicable, reason}}}` recording all decisions made so far
- `assess_result` — string result of the most recent `assess` action; `None` for all other action types
- `score_breakdown` — dict of component scores from the grader, populated on every step

### `RewardBreakdown`
Plain Pydantic model (not an OpenEnv type). Used internally by the graders. Fields map to the weighted scoring components. The `total` property computes the weighted sum with default weights — but the actual task-specific total is stored as `_task_total` via `object.__setattr__` because task graders use different weights than the default.

Default weight formula (used as fallback only):
```
severity × 0.20 + cvss × 0.10 + applicability × 0.20
+ remediation × 0.25 + escalation × 0.10 + summary × 0.15
+ efficiency_bonus - loop_penalty - false_positive_penalty
```

---

## scenarios.py

### Purpose
Contains the three scenario dicts that define each task's CVE reports, asset inventory, assessment reference data, and ground truth. These are the "exam questions" for the environment.

### Structure of a scenario dict
Every scenario is a plain dict with these keys:

- `task_id` — must match a key in `GRADERS`
- `report_id` — display identifier for the scenario
- `max_steps` — episode step limit (10 / 20 / 60 for easy / medium / hard)
- `reports` — list of dicts matching `VulnerabilityReport` schema
- `assets` — list of dicts matching `AssetRecord` schema
- `_assess_data` — dict mapping keyword topics to reference text returned by `assess` actions. Keys are lowercase topic words; the environment matches against them using keyword overlap.
- `_ground_truth` — dict consumed by the grader. Removed from the scenario dict during `reset()` so agents cannot access it.

### `SCENARIO_CLASSIFY_SEVERITY` — Task 1 (easy)
One CVE: Log4Shell (`CVE-2021-44228`, CVSS 10.0 CRITICAL). Three assets running Apache Log4j: versions 2.12.0, 2.10.0, and 2.17.1. The 2.17.1 instance is already patched and must be correctly marked not-applicable. Ground truth requires severity CRITICAL, applicable assets AST-001 and AST-002, not-applicable AST-003.

### `SCENARIO_MIXED_APPLICABILITY` — Task 2 (medium)
Three CVEs across four assets:
- `CVE-2023-44487` (HTTP/2 Rapid Reset, CVSS 7.5 HIGH) — affects only AST-010 running nginx 1.24.0
- `CVE-2023-4911` (glibc Looney Tunables, CVSS 7.8 HIGH) — affects AST-011 (Ubuntu 22.04, glibc 2.35) but not AST-012 (Ubuntu 20.04, glibc 2.31 which is below the affected range 2.34–2.38)
- `CVE-2023-20198` (Cisco IOS XE, CVSS 10.0 CRITICAL) — affects zero assets because the inventory contains Cisco IOS 15.2, not IOS XE. The agent must correctly suppress this CVE.

Ground truth requires escalation to `security` team.

### `SCENARIO_FULL_TRIAGE` — Task 3 (hard)
Eight CVEs across eight assets. Two CVEs (`CVE-2023-46805` Ivanti Connect Secure, `CVE-2024-1709` ConnectWise ScreenConnect) have zero applicable assets in inventory and must be suppressed. Key applicability details:
- `CVE-2024-3094` (XZ Utils backdoor) — only AST-024 (dev-workstation, Ubuntu 23.04)
- `CVE-2024-6387` (regreSSHion OpenSSH) — AST-022 and AST-023 (OpenSSH 9.3p1 and 8.9p1)
- `CVE-2024-21626` (runc container escape) — only AST-020 (runc 1.1.10); AST-021 runs runc 1.1.12 which is patched
- `CVE-2023-46805` (Ivanti) — AST-027 runs Palo Alto GlobalProtect, not Ivanti ICS; zero assets affected
- `CVE-2024-1709` (ScreenConnect) — no ScreenConnect in inventory; zero assets affected
- `CVE-2023-36884` (Office HTML RCE) — AST-026 (Microsoft Office 2021 workstation fleet)
- `CVE-2024-0204` (GoAnywhere MFT) — AST-025 (Fortra GoAnywhere 7.3.0, internet-facing critical)
- `CVE-2023-48795` (Terrapin SSH) — AST-022 and AST-023 (both OpenSSH servers)

Ground truth requires escalation to `management`, and a five-step remediation plan in priority order: GoAnywhere → bastion OpenSSH → runc k8s-node → internal OpenSSH → Office fleet + XZ audit.

### `ALL_SCENARIOS`
Module-level dict mapping `task_id` strings to scenario dicts. Used by the environment and the grader registry.

---

## graders.py

### Purpose
Contains pure, deterministic scoring functions. Graders are pure functions of the episode state — they do not touch the environment or make API calls. The same input always produces the same output.

### Scoring utilities

**`_severity_score(predicted, expected)`**
Returns 1.0 for exact match, 0.5 if the predicted tier is adjacent (one step away in CRITICAL > HIGH > MEDIUM > LOW), and 0.0 otherwise. Uses `_SEVERITY_ORDER` dict for distance calculation.

**`_cvss_accuracy(predicted, expected)`**
Linear decay function. Returns 1.0 if `|predicted - expected| <= 0.5`, returns 0.0 if the difference is 3.0 or greater, and interpolates linearly in between. This rewards agents that correctly estimate CVSS scores to within half a point.

**`_applicability_f1(decisions, ground_truth_map)`**
Computes micro-averaged precision-recall F1 over all `(cve_id, asset_id)` pairs. True negatives (correctly saying a CVE does not apply) are deliberately excluded from recall to avoid rewarding agents that do nothing. The formula counts:
- TP: agent said applicable, CVE is truly applicable
- FP: agent said applicable, CVE is not applicable
- FN: agent said not-applicable (or made no decision), CVE is truly applicable

**`_remediation_score(action_history, required)`**
Scores the remediation plan on two dimensions:
- Presence (60% weight): for each required remediation item, is there any executed step whose `target_asset_ids` overlaps? Binary per item, averaged.
- Order (40% weight): longest common subsequence (LCS) of matched executed steps against the required sequence, divided by required length. This rewards getting items in the right order without requiring exact matches.

Final score = `0.6 × presence + 0.4 × order`.

**`_summary_quality(note, keywords)`**
Keyword coverage: fraction of required keywords that appear as substrings in the resolution summary (case-insensitive). Returns 0.0 if note is empty.

**`_efficiency_bonus(steps, par, max_steps)`**
Returns 0.05 if the episode completed in `par_steps` or fewer. Linearly decays to 0.0 as steps approach `max_steps`. Rewards concise triage.

**`_loop_penalty(history)`**
Inspects the action history for repeated identical `assess` queries. Each query repeated more than twice beyond the second occurrence adds 0.03 to the penalty, capped at 0.15. This discourages circular reasoning.

**`_false_positive_penalty(decisions, gt_map)`**
For each truly-applicable CVE×asset pair that the agent marked as not-applicable, adds 0.05 to the penalty, capped at 0.20. This is a "false negative" in epidemiological terms — missing a real vulnerability.

**`_set_total(bd, raw)`**
Stores the task-specific weighted total in the `_task_total` attribute using `object.__setattr__` to bypass Pydantic's validation. This is necessary because each task uses different weights, but `RewardBreakdown` has fixed default weights. `get_total()` reads `_task_total` first and falls back to `bd.total`.

### Task graders

**`grade_classify_severity(episode_state, ground_truth)`** — Task 1 weights:
- severity 40%, cvss accuracy 20%, applicability F1 20%, summary quality 10%, efficiency 10%
- Applicability is evaluated only for the single CVE `CVE-2021-44228` against the assets list in episode state.

**`grade_mixed_applicability(episode_state, ground_truth)`** — Task 2 weights:
- applicability F1 30%, remediation 25%, severity avg 15%, escalation 15%, summary 10%, efficiency 5%
- Severity is averaged across all CVEs. For each CVE, the grader checks all classify actions in history for any that reference that CVE ID. Falls back to the last classify action's tier if no CVE-specific classify is found.

**`grade_full_triage(episode_state, ground_truth)`** — Task 3 weights:
- applicability F1 25%, remediation 25%, severity avg 15%, escalation 15%, summary 15%, efficiency 5%
- Same severity-averaging logic as Task 2 but over eight CVEs.

### `GRADERS` registry
Dict mapping task IDs to grader functions. Used by the environment and the `/grader` HTTP endpoint.

---

## server/armorflo_environment.py

### Purpose
The core environment class. Subclasses `openenv.core.env_server.interfaces.Environment` so that `create_app` can serve it over HTTP and WebSocket without any additional wiring.

### Class: `ArmorFloEnvironment`

**Class attributes:**
- `SUPPORTS_CONCURRENT_SESSIONS = True` — tells the OpenEnv HTTP server that multiple WebSocket connections may each have their own independent environment instance. This is safe because all state is instance-level.
- `VALID_TASKS` — list of valid task IDs derived from `ALL_SCENARIOS`

**Instance state (all reset on `reset()` call):**
- `_scenario` — deep copy of the scenario dict with `_ground_truth` and `_assess_data` removed
- `_ground_truth` — the removed ground truth dict; not accessible to the agent
- `_assess_data` — the removed assess reference data; used by `_handle_assess`
- `_task_id` — currently active task
- `_state` — `State(episode_id, step_count)` OpenEnv state object
- `_done` — episode termination flag
- `_action_history` — list of raw action dicts in order
- `_classify_action` — last `classify` action dict; overwritten on each classify
- `_close_action` — the `close` action dict; set exactly once
- `_applicability_decisions` — nested dict `{cve_id: {asset_id: {applicable, reason}}}`
- `_assess_cache` — dict caching assess results by query string to detect repeated queries

**`reset(seed, episode_id, task_id, **kwargs)`**
Validates `task_id`, deep-copies the scenario, pops `_ground_truth` and `_assess_data` out of the scenario dict, resets all instance state, and returns the initial observation. The `seed` and `episode_id` parameters conform to the OpenEnv spec signature; `seed` is unused since scenarios are deterministic.

**`step(action, timeout_s, **kwargs)`**
Validates the episode is not done, records the action, increments `step_count`, dispatches on `action_type`, calls `_compute_reward()`, and returns a new observation with reward and done embedded. Force-terminates when `step_count >= max_steps`.

Action dispatch:
- `assess` → calls `_handle_assess`, puts result in observation
- `classify` → stores raw action dict in `_classify_action`
- `check_applicability` → updates `_applicability_decisions` nested dict
- `recommend`, `escalate`, `defer` → recorded in `_action_history` only
- `close` → stores `_close_action`, sets `_done = True`

**`state` property**
Returns `self._state` (a `State` instance with `episode_id` and `step_count`). Required by the OpenEnv spec.

**`_build_obs(assess_result, reward, done, breakdown)`**
Constructs an `ArmorFloObservation` from current instance state. Converts raw dicts from the scenario into typed Pydantic models.

**`_handle_assess(query)`**
Implements the investigate mechanic. Lowercases the query, checks the cache, then tries three lookup strategies in order:
1. Keyword match against `_assess_data` topic keys and content (returns the first matching entry)
2. Keyword match against CVE descriptions and IDs in the scenario reports
3. Keyword match against asset names and products

Returns a cache-miss string if nothing matches. Caches the result. The cache is checked before each lookup — repeated identical queries return `[cached] ...` which is how the loop penalty detects circular reasoning.

**`_compute_reward()`**
Looks up the appropriate grader from `GRADERS`, builds the episode state dict, calls the grader, and returns `(total_score, breakdown_dict)`.

---

## server/app.py

### Purpose
Creates the FastAPI application and adds the three competition-required endpoints that `create_app` does not provide.

### `create_app(...)` base application
Called with `ArmorFloEnvironment`, `ArmorFloAction`, `ArmorFloObservation`, `env_name="armorflo"`, `max_concurrent_envs=4`. Returns a FastAPI instance pre-wired with:
- `POST /reset` — stateless; creates a fresh environment, calls `reset()`, returns observation
- `POST /step` — stateless; creates a fresh environment, calls `step()`, returns observation + reward + done
- `GET /state` — returns current episode state
- `GET /schema` — returns JSON schemas for Action, Observation, State
- `GET /health` — returns `{"status": "healthy"}`
- `GET /metadata` — returns environment metadata
- `WS /ws` — WebSocket for persistent stateful sessions
- `POST /mcp`, `WS /mcp` — MCP protocol endpoints

### `GET /tasks`
Returns a list of all three tasks. Each entry includes `task_id`, `difficulty`, `description`, `par_steps`, `max_steps`, `num_reports`, `num_assets`, and the full `action_schema` JSON Schema for `ArmorFloAction`. The action schema is what judges use to verify the action space is well-defined.

### `POST /grader`
Accepts a `GraderRequest` body containing the episode state fields (`task_id`, `classify_action`, `close_action`, `action_history`, `applicability_decisions`, `step_count`, `max_steps`, `assets`). Looks up the appropriate grader, loads a fresh deep copy of the ground truth from `ALL_SCENARIOS`, runs the grader, and returns `{task_id, score, breakdown}`.

This endpoint allows scoring an episode without running it live — useful for the competition's automated evaluation pipeline.

### `POST /baseline`
Accepts an optional `model` override and optional `tasks` list. Reads `API_BASE_URL`, `HF_TOKEN` (or `OPENAI_API_KEY`), and `MODEL_NAME` from environment variables. Imports `run_episode` from `inference.py`, creates an `OpenAI` client with `base_url`, and runs one episode per requested task. Returns `{model, scores, average}`.

Returns HTTP 503 if `HF_TOKEN`/`OPENAI_API_KEY` is not set.

### `main(host, port)`
Entry point for `uv run server` (via `pyproject.toml` `[project.scripts]`). The `if __name__ == "__main__"` block with the `main()` call is required by `openenv validate` — it checks for both `"def main("` and `"main()"` as literal strings in `server/app.py`.

---

## inference.py

### Purpose
Standalone script that runs an LLM agent through ArmorFlo episodes and reports scores. Also importable as a module by `server/app.py`'s `/baseline` endpoint.

### Environment variables (required by competition spec)
- `API_BASE_URL` — LLM endpoint base URL. Defaults to `https://router.huggingface.co/v1` (HF's OpenAI-compatible router, free with HF token)
- `MODEL_NAME` — model identifier e.g. `meta-llama/Llama-3.1-8B-Instruct`
- `HF_TOKEN` — API key. Falls back to `OPENAI_API_KEY` for compatibility with OpenAI endpoints

### `SYSTEM_PROMPT`
Static system prompt describing the seven action types and their JSON schemas. Instructs the model to respond with a single JSON object and no markdown fences.

### `_format_obs(obs)`
Converts an `ArmorFloObservation` into a text string for the LLM. Includes the task/step header, all CVE reports with computed severity tier, full asset inventory, applicability decisions made so far, and the most recent assess result if present.

### `run_episode(env, client, task_id, model, verbose)`
Core episode loop. Calls `env.reset(task_id=task_id)`, then loops up to `obs.max_steps` times:
1. Formats the observation into a user message
2. Appends to conversation history
3. Calls `client.chat.completions.create` with `response_format={"type": "json_object"}` to force valid JSON output
4. Parses the response as `ArmorFloAction`
5. Converts any `remediation_plan` dicts to `RemediationStep` objects
6. Calls `env.step(action)`
7. On parse/execution error, falls back to a neutral assess action to avoid crashing
8. Breaks when `obs.done` is True

Returns `final_reward` as a float.

### `main()`
Parses `--task`, `--model`, `--quiet` CLI arguments. Reads env vars. Creates one `ArmorFloEnvironment` and `OpenAI` client per task. Runs `run_episode` for each task. Prints a formatted results table.

---

## tests/test_env.py

### Structure
The test file has five test classes covering all three task difficulty levels.

**`TestReset`** — 7 tests covering `reset()` behaviour: returns correct observation shape, clears state between episodes, loads all three tasks, rejects invalid task IDs.

**`TestStep`** — 13 tests covering `step()` mechanics: assess caching, step counter, applicability recording, classify persistence, close termination, post-done exception, max_steps termination, reward bounds, recommend not closing, state property.

**`TestGraders`** — 12 tests covering grader unit behaviour and two full integration episodes (Task 1 and Task 2). Includes determinism check and reward-bounds property test on Task 3.

**`TestTask2Medium`** — 17 tests specifically for Task 2. Covers CVSS accuracy at boundary conditions (within ±0.5, off by 2.0, off by 3.0), severity tier correctness and adjacent-miss partial credit, applicability decisions for each asset×CVE pair, false-positive and false-negative penalty behaviour, the escalation weight (missing escalation lowers score by ≥0.10), and a full integration episode expecting ≥0.75 score.

**`TestTask3Hard`** — 13 tests specifically for Task 3. Covers CVSS accuracy for all eight CVEs (XZ, regreSSHion, runc, GoAnywhere, ScreenConnect, Office, Terrapin), non-applicable CVE suppression for Ivanti and ScreenConnect, management escalation requirement, remediation priority ordering (GoAnywhere must be Priority 1), and a full 54-step integration episode expecting ≥0.65 score.

### Helper functions
- `act(**kwargs)` — constructs an `ArmorFloAction` from keyword arguments
- `_ep(**kwargs)` — builds a synthetic episode state dict for grader unit tests, with sensible defaults

---

## openenv.yaml

Minimal spec file required by `openenv validate`. Fields:
- `spec_version: 1` — OpenEnv spec version
- `name: armorflo` — environment name
- `type: space` — HF Spaces deployment type
- `runtime: fastapi` — server runtime
- `app: server.app:app` — Python module path to the FastAPI app instance
- `port: 8000` — port the server listens on

---

## pyproject.toml

Key configuration:

**`[project.scripts]`** — `server = "armorflo.server.app:main"` enables `uv run server`. The validator checks for this entry and for `:main` in the value.

**`[tool.setuptools]`** — maps the `armorflo` package to `.` (project root) and `armorflo.server` to `./server/`. This lets Python import `from armorflo.models import ...` when installed, and `from models import ...` when running from the project root directly.

**Dependencies:**
- `openenv-core[core]>=0.2.2` — the real OpenEnv framework (not the unrelated 2020 `openenv` PyPI package). Provides `Environment`, `Action`, `Observation`, `State`, `create_app`, `openenv validate`, and the CLI.
- `pydantic>=2.5.0` — data validation
- `fastapi>=0.109.0`, `uvicorn[standard]>=0.27.0` — HTTP server
- `openai>=1.12.0` — OpenAI client used in `inference.py`

---

## Reward design rationale

### Why shaped reward instead of binary end-of-episode
Binary reward (0 or 1 at the end) makes RL training extremely slow because the agent must discover the correct sequence of actions entirely by chance before receiving any signal. ArmorFlo returns a score at every step so that even partial progress (e.g. correct severity classification without correct applicability) receives a non-zero reward. This makes gradient-based RL methods like GRPO tractable.

### Why F1 for applicability instead of accuracy
Accuracy would give misleadingly high scores to agents that simply mark everything as not-applicable, since most CVE×asset pairs are not applicable. F1 over only the positive class (truly applicable pairs) properly rewards both precision (not crying wolf) and recall (not missing real vulnerabilities).

### Why LCS for remediation ordering
The order of remediation actions has causal meaning — internet-facing critical services must be patched before internal lower-priority ones. Longest Common Subsequence preserves order sensitivity while tolerating extra steps that weren't in the required plan.

### Why loop penalty instead of step limit alone
A hard step limit would terminate episodes that spend steps on repeated queries. The loop penalty instead reduces the score proportionally, allowing an episode to continue to completion while discouraging circular reasoning. The threshold of 2 allowed repeats accounts for legitimate re-queries after new information from an assess action.

### Why false-negative penalty separate from F1
The F1 score for applicability already accounts for false negatives (missed applicable CVEs) through recall. The separate `false_positive_penalty` is specifically for the case where the agent explicitly marks a truly-applicable CVE as not-applicable — this is a dangerous decision in a real security context and deserves an additional deterrent beyond just a lower recall score.
