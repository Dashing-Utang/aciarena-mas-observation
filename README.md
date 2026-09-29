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

### 1. Set up the API keys for both the agent model and the judge model.
See `configs/judge.yaml` and `configs/model.yaml`
```yaml
# Step 1: Set up the API keys
provider: openai
api_key: <your_api_key>
base_url: <your_base_url>
model_name: <your_model_name>
temperature: 0.0
max_tokens: 1024
```

### 2. Run Evaluation
```bash
# Step 2: Run the evaluation pipeline
bash run.sh
```

## Reproducible ACI observation experiment

This fork adds a shared console/JSONL observer, an official CAI Framework adapter, and focused
`SafetyCheckInstruction` runs for MetaGPT, CAMEL, and CAI. The default scripts use
the OpenAI-compatible Ollama endpoint at `http://127.0.0.1:11434/v1` with
`llama3.2:latest`; override any `ACI_ARENA_*` environment variable to use another
compatible model service.

The CAI adapter executes `cai-framework` 1.1.5 from the official
`aliasrobotics/cai` archival commit `6dc79257777f5f1c9500b4d2319935d34a47412e`.
CAI's upstream Research-Use License restricts its proprietary additions to
non-commercial research and academic use.

```bash
./scripts/setup_experiment.sh
./scripts/run_metagpt.sh
./scripts/run_camel.sh
./scripts/run_cai.sh
```

See `docs/experiment.md` for the observation points and verified run results.
