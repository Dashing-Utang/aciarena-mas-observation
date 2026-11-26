<h2 align="center">
  <strong>ACIArena</strong>: Toward Unified Evaluation for Agent Cascading Injection
</h2>

<div align='center'>
  <img src="assets/figure.png" width="75%">
</div>

---
## 🔧 Installation

```bash
# Step 1: Create and activate the environment
conda create -n aciarena python=3.10
conda activate aciarena

# Step 2: Clone the repository
git clone https://github.com/Greysahy/aciarena.git
cd aciarena

# Step 3: Install dependencies
pip install -e .
```

## 🚀 Quickstart

### 1. Set up API keys for the agent and judge models.

Do not commit API keys. Copy the environment template, enter newly issued keys,
and export them before running the benchmark:

```bash
cp .env.example .env
set -a
source .env
set +a
```

`configs/model.yaml` configures the system under test; `configs/judge.yaml`
configures the separate judge. This checkout uses OpenAI for both. Run-specific
model names can be selected with `--model` and `--judge_model`.

### 2. Run Evaluation
```bash
# Step 2: Run the evaluation pipeline
bash run.sh
```

## CAI adapter

This fork adds Alias Robotics CAI Framework as an ACIArena MAS adapter. The
dependency is pinned to `cai-framework` 1.1.5 at commit
`6dc79257777f5f1c9500b4d2319935d34a47412e`.

After configuring `configs/model.yaml` and `configs/judge.yaml`, run CAI through
the normal ACIArena entry point:

```bash
python3 benchmark.py \
  --mas cai \
  --suite hijacking \
  --task_domain code \
  --malicious_agents codeagent \
  --max_workers 1
```

The adapter is located in `aciarena/mas/cai/`.

## Guardrail comparison

Use Python 3.12 for the comparison environment. Install the BERT dependencies
and SubAgentShield, then install the pinned AGrail source:

```bash
pip install -e '.[bert]' -e ../subagentShield
python -m aciarena.defenses.agrail --install-source
```

`--compare` runs one suite with identical task selection, model and judge
settings across none, BERT, ACI-Sentinel, AGrail publication and Shield Release.
`--answer-recovery` adds a separate Shield Release arm with one task-only retry.
Configure the model and judge credentials and `TYPESAFE_API_KEY` before running.
The comparison checks the guard dependencies and probes JEV with a synthetic
request. Code comparisons use the existing Linux/Python 3.12 isolated official
grader and run its local preflight.

```bash
python benchmark.py --compare --mas metagpt --suite benign --task_domain sci \
  --task_ids 0,1 --repeat 1 --answer-recovery \
  --shield-policy ../subagentShield/configs/policies/mas-runtime-release-v1.json \
  --shield-release-config ../subagentShield/configs/output-release-recovery.json
```

Run the benign suite for benign utility and the selected attack suite for
utility under attack and ASR. Attack comparisons require a single target.
MetaGPT math uses the `metagpt_math_v1` role profile across all arms. Compare
the same task and target selections per arm and report each suite's coverage.

Each run writes `result.json` in its own session directory. Comparisons write
an index at `results_extended/comparisons/<id>/summary.json` with each arm's
official scores, extended metrics, and result path. Check execution errors,
verification errors, defense blocks, attack application counts and the valid
ASR denominator alongside the official numbers. The recovery counts record
new attempts, delivered answers and delivered correct answers.

The published QA prompts and scorer are used by default. The QA summary also
records an always-A baseline and utility from explicit option answers. Use
`--qa-shuffle-seed 37` for a separate, reproducible QA variant with remapped
answer labels. Its results record the shuffle seed.

## ACIArena-Extended v1

The branch adds isolated execution traces and a separate four-axis evaluator.
See [the schema, metric denominators and smoke commands](docs/extended_v1.md)
and [the verified implementation report](analysis/measurement_v1_report_2026-10-06.md).
The [live GPT-5 nano smoke report](analysis/live_nano_smoke_2026-10-06.md)
separates real model outputs from official scores and documents remaining
semantic-classifier coverage gaps.
