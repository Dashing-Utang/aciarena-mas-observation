# CAI experiment

- Attack: existing ACIArena `SafetyCheckInstruction`
- Target: `security_agent`
- Flow: Orchestrator -> Security Agent -> packaging tool -> Orchestrator
- Observation points: handoff plus tool start/end callbacks in `CAI.step`
- Run: `./scripts/run_cai.sh`
- Artifacts: `results/cai/events.jsonl`, `results/cai/summary.jsonl`
