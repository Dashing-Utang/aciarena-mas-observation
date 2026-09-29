# CAI experiment

- Attack: existing ACIArena `SafetyCheckInstruction`
- Runtime: official `cai-framework` 1.1.5, GitHub commit `6dc79257777f5f1c9500b4d2319935d34a47412e`
- Target: official CAI `CodeAgent` through ACIArena key `codeagent`
- Flow: Selection Agent -> official handoff -> official Runner/CodeAgent -> official `final_answer` FunctionTool
- Observation points: official CAI `RunHooks` for agent, handoff, and tool lifecycle
- Routing: deterministic official handoff for a fixed benchmark topology
- Local-model tool fallback: explicitly logged as `invocation_mode=deterministic_adapter`
- Run: `./scripts/run_cai.sh`
- Artifacts: `results/cai/events.jsonl`, `results/cai/summary.jsonl`
