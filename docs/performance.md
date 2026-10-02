# Performance

Run a local benchmark with:

```powershell
python -m benchmarks run --events 1000
python -m benchmarks run --events 10000
```

The command generates synthetic documentation-range events, measures ingestion and detection wall time, records SQLite size, and captures peak memory with `tracemalloc`. It does not contact external systems or call an AI provider. Results are machine-dependent measurements, not product guarantees.

The normal unit-test suite does not run large performance workloads. Use benchmark output to establish a local baseline before introducing thresholds or comparing changes.
