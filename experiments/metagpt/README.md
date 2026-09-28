# MetaGPT experiment

- Attack: existing ACIArena `SafetyCheckInstruction`
- Target: `engineer`
- Flow: Product Manager -> Architect -> Project Manager -> Engineer -> QA Engineer
- Observation point: `MetaGPT._log_step`, immediately after each role output and before the next role consumes it
- Run: `./scripts/run_metagpt.sh`
- Artifacts: `results/metagpt/events.jsonl`, `results/metagpt/summary.jsonl`
