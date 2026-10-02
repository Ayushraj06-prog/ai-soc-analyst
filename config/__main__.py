"""Validate and display effective configuration without revealing secrets."""
import json

from app.config import effective_config, settings, validate_production


def main() -> int:
    errors = validate_production(settings)
    print(json.dumps(effective_config(settings), indent=2, sort_keys=True))
    if errors:
        print("INVALID CONFIGURATION")
        for error in errors:
            print(f"- {error}")
        return 1
    print("CONFIGURATION OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
