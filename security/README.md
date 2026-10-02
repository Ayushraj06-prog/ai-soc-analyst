# Static Security Scanning

Run `python -m security.scan` for a machine-readable JSON report. The scan checks Python ASTs for forbidden dynamic execution constructs and runs Ruff, Bandit, ESLint, and npm audit when those tools are available.

Results are reported as `PASS`, `WARNING`, `FAIL`, or `SKIPPED`. Missing optional tools are not treated as passes. Existing vulnerabilities should be reviewed before changing dependencies; this project does not silently upgrade packages to make scans green.
