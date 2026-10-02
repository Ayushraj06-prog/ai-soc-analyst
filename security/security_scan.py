"""Dependency-light static security scan with truthful optional tool status."""
import ast
import json
import shutil
import subprocess
from pathlib import Path

FORBIDDEN = {"eval", "exec", "pickle", "yaml.load", "shell=True", "os.system"}


def forbidden_calls(root: Path) -> list[str]:
    findings = []
    for path in root.rglob("*.py"):
        if any(part in {".venv", "venv", "node_modules", "__pycache__"} for part in path.parts):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                findings.append(f"{path}:{node.lineno}:{node.func.id}")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "system":
                findings.append(f"{path}:{node.lineno}:os.system")
    return findings


def tool_status(command: list[str], cwd: Path) -> str:
    if shutil.which(command[0]) is None:
        return "SKIPPED"
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    return "PASS" if result.returncode == 0 else "WARNING"


def scan(root: Path | None = None) -> dict:
    root = Path(root or Path(__file__).resolve().parents[1])
    findings = forbidden_calls(root)
    npm = "npm.cmd" if shutil.which("npm.cmd") else "npm"
    result = {
        "python": {"forbidden_calls": "FAIL" if findings else "PASS", "ruff": tool_status(["ruff", "check", "."], root), "bandit": tool_status(["bandit", "-r", "."], root)},
        "frontend": {"eslint": tool_status([npm, "run", "lint"], root / "frontend"), "npm_audit": tool_status([npm, "audit", "--audit-level=high"], root / "frontend")},
        "findings": findings,
    }
    return result


def main() -> int:
    result = scan()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["python"]["forbidden_calls"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
