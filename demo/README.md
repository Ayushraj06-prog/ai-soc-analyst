# Synthetic Demo

Run `python -m demo` for the default multi-stage synthetic SOC workflow or `python -m demo --scenario all --reset --json` for every checked-in scenario.

The demo uses documentation-only addresses, deterministic fixtures, a mock investigation provider, and simulation-only response recommendations. It does not contact Ollama, real targets, or external systems. Results are safe to expose through the existing API and dashboard by pointing `SOC_DATABASE_PATH` at the demo database.
