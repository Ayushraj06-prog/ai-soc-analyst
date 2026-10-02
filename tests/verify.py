"""Phase 10 verification runner with explicit result states."""
import argparse
import importlib.util
import shutil
import subprocess
import sys


def run_stage(name, command, required, results):
    try:
        completed = subprocess.run(command, capture_output=True, text=True)
    except FileNotFoundError:
        status = "FAIL" if required else "SKIPPED"
        results.append((name, status, "command unavailable"))
        return
    status = "PASS" if completed.returncode == 0 else "FAIL"
    results.append((name, status, completed.stderr.strip()[-300:] or completed.stdout.strip()[-300:]))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m tests.verify")
    parser.add_argument("--require-all", action="store_true")
    args = parser.parse_args(argv)
    results = []
    npm = "npm.cmd" if shutil.which("npm.cmd") else "npm"
    run_stage("backend tests", [sys.executable, "-m", "unittest", "discover"], True, results)
    run_stage("configuration and hardening tests", [sys.executable, "-m", "unittest", "tests.test_phase10_hardening"], True, results)
    frontend = [npm, "--prefix", "frontend"]
    run_stage("frontend tests", frontend + ["test", "--", "--run"], args.require_all, results)
    run_stage("frontend typecheck", frontend + ["run", "typecheck"], args.require_all, results)
    run_stage("frontend lint", frontend + ["run", "lint"], args.require_all, results)
    run_stage("frontend build", frontend + ["run", "build"], args.require_all, results)
    if importlib.util.find_spec("fastapi") is None:
        results.append(("route inventory", "SKIPPED", "FastAPI unavailable"))
    else:
        run_stage("route inventory", [sys.executable, "-m", "unittest", "tests.test_phase10_routes"], True, results)
    for name, status, detail in results:
        print(f"{status}: {name}" + (f" ({detail})" if detail and status != "PASS" else ""))
    failed = any(status == "FAIL" for _, status, _ in results)
    skipped = any(status == "SKIPPED" for _, status, _ in results)
    return 1 if failed or (args.require_all and skipped) else 0


if __name__ == "__main__":
    raise SystemExit(main())
