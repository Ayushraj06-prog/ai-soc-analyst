import hmac
import logging
import threading
import time
from fastapi import Depends, Header, Request
from app.config import settings
from api.errors import api_error

log = logging.getLogger("ai_soc.auth")
_failures: dict[str, tuple[int, float]] = {}
_failure_lock = threading.Lock()


def get_service(request: Request):
    return request.app.state.api_service


def _client_address(request: Request) -> str:
    actual = request.client.host if request.client else "unknown"
    if actual in getattr(settings, "api_trusted_proxies", ()):
        forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if forwarded:
            return forwarded
    return actual


def require_auth(request: Request, authorization: str | None = Header(default=None)):
    if not settings.api_auth_enabled:
        return "local-user"
    token = settings.api_auth_token.reveal() if hasattr(settings.api_auth_token, "reveal") else settings.api_auth_token
    if not token:
        api_error(503, "authentication_misconfigured", "API authentication is enabled but no token is configured.")
    client = _client_address(request)
    now = time.monotonic()
    with _failure_lock:
        count, blocked_until = _failures.get(client, (0, 0.0))
        if blocked_until > now:
            api_error(429, "authentication_throttled", "Authentication is temporarily throttled.")
    expected = "Bearer " + token
    if not authorization or not hmac.compare_digest(authorization, expected):
        with _failure_lock:
            count += 1
            backoff = getattr(settings, "api_auth_backoff_seconds", 1)
            threshold = getattr(settings, "api_auth_rate_limit", 10)
            delay = backoff * min(count, 10)
            _failures[client] = (count, now + delay if count >= threshold else 0.0)
        log.warning("authentication_failed client=%s count=%s", client, count)
        api_error(401, "unauthorized", "Authentication is required.")
    with _failure_lock:
        _failures.pop(client, None)
    return "api-user"


Analyst = Depends(require_auth)
