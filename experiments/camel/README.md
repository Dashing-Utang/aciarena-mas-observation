# CAMEL experiment

- Attack: existing ACIArena `SafetyCheckInstruction`
- Target: `assistant`
- Flow: Task Specifier -> User Proxy <-> Assistant
- Observation point: `CAMEL._log_step`, at each turn boundary
- Run: `./scripts/run_camel.sh`
- Artifacts: `results/camel/events.jsonl`, `results/camel/summary.jsonl`
