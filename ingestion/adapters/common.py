"""Shared safe field extraction helpers."""
import ipaddress
import json
from typing import Any

from ingestion.base import clean_text
from ingestion.errors import RecordParseError


def normalize_ip(value: Any) -> str | None:
    text = clean_text(value, 128)
    if text is None or text in {"-", "::ffff:0:0"}:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise RecordParseError(f"invalid IP address: {text!r}") from exc


def safe_raw(value: Any) -> Any:
    if isinstance(value, dict):
        return {clean_text(key, 256) or "": safe_raw(item) for key, item in value.items()}
    if isinstance(value, list):
        return [safe_raw(item) for item in value]
    if isinstance(value, str):
        return clean_text(value, 65536)
    return value


def decode_json(line: str) -> dict[str, Any]:
    try:
        value = json.loads(line)
    except json.JSONDecodeError as exc:
        raise RecordParseError(f"invalid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise RecordParseError("JSON record must be an object")
    return value


def first(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return None


def flatten_fields(value: Any) -> dict[str, Any]:
    """Expose nested tshark/Windows JSON leaf names alongside original keys."""
    flattened: dict[str, Any] = {}
    def visit(item):
        if isinstance(item, dict):
            for key, child in item.items():
                if isinstance(child, (dict, list)):
                    visit(child)
                else:
                    flattened.setdefault(str(key), child)
        elif isinstance(item, list):
            for child in item:
                visit(child)
    visit(value)
    return flattened
