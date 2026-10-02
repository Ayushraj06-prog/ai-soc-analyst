"""Stable, reproducible identifiers for idempotent ingestion."""
import hashlib


def make_id(prefix: str, *parts: object) -> str:
    """Build a compact deterministic ID; callers should pass canonical parts."""
    digest = hashlib.sha256("|".join(map(str, parts)).encode("utf-8")).hexdigest()[:16]
    return f"{prefix}_{digest}"


stable_id = make_id
