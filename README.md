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

`configs/model.yaml` uses Claude as the system under test through Anthropic's
OpenAI SDK compatibility endpoint. `configs/judge.yaml` uses OpenAI as the
separate judge.

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
