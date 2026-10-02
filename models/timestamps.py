"""Shared timestamp parsing and UTC serialization."""
from datetime import datetime, timezone
from numbers import Real
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def to_utc_iso(value, assume_tz="UTC") -> str:
    """Normalize datetime, ISO-8601 string, or epoch seconds to UTC ISO-8601."""
    if isinstance(value, bool):
        raise TypeError("Boolean is not a valid timestamp")
    if isinstance(value, Real):
        epoch = float(value)
        if abs(epoch) >= 100_000_000_000:  # Practical millisecond epoch detection.
            epoch /= 1000.0
        parsed = datetime.fromtimestamp(epoch, tz=timezone.utc)
    elif isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            raise ValueError("Timestamp cannot be empty")
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Unsupported timestamp: {value!r}") from exc
    else:
        raise TypeError("Timestamp must be datetime, ISO string, or epoch number")
    if parsed.tzinfo is None:
        if assume_tz.strip().upper() in {"UTC", "GMT", "Z"}:
            tz = timezone.utc
        else:
            try:
                tz = ZoneInfo(assume_tz)
            except ZoneInfoNotFoundError as exc:
                raise ValueError(f"Timezone {assume_tz!r} is unavailable") from exc
        parsed = parsed.replace(tzinfo=tz)
    return parsed.astimezone(timezone.utc).isoformat()
