"""Environment-backed settings with safe local defaults."""
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from version import __version__


def _env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


class Secret:
    """A value that never exposes its contents through normal stringification."""

    def __init__(self, value: str):
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret('********')"

    __str__ = __repr__


@dataclass(frozen=True)
class Settings:
    app_name: str = "AI SOC Analyst"
    app_version: str = __version__
    environment: str = os.getenv("SOC_ENVIRONMENT", "development").strip().lower()
    data_dir: Path = Path(os.getenv("SOC_DATA_DIR", "data"))
    database_path: Path = Path(os.getenv("SOC_DATABASE_PATH", "data/soc.db"))
    llm_provider: str = os.getenv("SOC_LLM_PROVIDER", "ollama")
    llm_model: str = os.getenv("SOC_LLM_MODEL", "llama3")
    ollama_host: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    allow_remote_llm: bool = _env_bool("ALLOW_REMOTE_LLM", False)
    llm_num_ctx: int = int(os.getenv("LLM_NUM_CTX", "4096"))
    llm_timeout_seconds: int = int(os.getenv("LLM_TIMEOUT_SECONDS", "120"))
    llm_max_output_tokens: int = int(os.getenv("LLM_MAX_OUTPUT_TOKENS", "1024"))
    llm_temperature: float = float(os.getenv("LLM_TEMPERATURE", "0"))
    llm_seed: int = int(os.getenv("LLM_SEED", "42"))
    llm_stale_timeout_seconds: int = int(os.getenv("LLM_STALE_TIMEOUT_SECONDS", "900"))
    llm_max_attempts: int = int(os.getenv("LLM_MAX_ATTEMPTS", "3"))
    llm_packet_max_bytes: int = int(os.getenv("LLM_PACKET_MAX_BYTES", "256000"))
    llm_packet_max_events: int = int(os.getenv("LLM_PACKET_MAX_EVENTS", "100"))
    llm_packet_max_iocs: int = int(os.getenv("LLM_PACKET_MAX_IOCS", "100"))
    llm_packet_max_mappings: int = int(os.getenv("LLM_PACKET_MAX_MAPPINGS", "100"))
    llm_raw_excerpt_chars: int = int(os.getenv("LLM_RAW_EXCERPT_CHARS", "1000"))
    llm_max_validation_errors: int = int(os.getenv("LLM_MAX_VALIDATION_ERRORS", "10"))
    llm_created_by: str = os.getenv("LLM_CREATED_BY", "system")
    log_level: str = os.getenv("SOC_LOG_LEVEL", "INFO")
    max_parse_errors: int = int(os.getenv("SOC_MAX_PARSE_ERRORS", "100"))
    scanner_enabled: bool = _env_bool("SOC_SCANNER_ENABLED", True)
    scanner_lab_mode: bool = _env_bool("SOC_SCANNER_LAB_MODE", True)
    scanner_allowed_targets: tuple[str, ...] = tuple(
        value.strip().lower() for value in os.getenv("SOC_SCANNER_ALLOWED_TARGETS", "127.0.0.1,localhost,::1").split(",") if value.strip()
    )
    ingest_assume_tz: str = os.getenv("INGEST_ASSUME_TZ", "UTC")
    ingest_assume_year: int | None = int(os.environ["INGEST_ASSUME_YEAR"]) if os.getenv("INGEST_ASSUME_YEAR") else None
    ingest_max_file_bytes: int = int(os.getenv("INGEST_MAX_FILE_BYTES", str(100 * 1024 * 1024)))
    ingest_max_line_length: int = int(os.getenv("INGEST_MAX_LINE_LENGTH", "65536"))
    ingest_max_raw_bytes: int = int(os.getenv("INGEST_MAX_RAW_BYTES", "16384"))
    ingest_detection_lines: int = int(os.getenv("INGEST_DETECTION_LINES", "20"))
    ingest_error_limit: int = int(os.getenv("INGEST_MAX_PARSE_ERRORS", "100"))
    ingest_invalid_threshold_percent: float = float(os.getenv("INGEST_INVALID_THRESHOLD_PERCENT", "50"))
    ingest_chunk_size: int = int(os.getenv("INGEST_CHUNK_SIZE", "1000"))
    api_host: str = os.getenv("API_HOST", "127.0.0.1")
    api_port: int = int(os.getenv("API_PORT", "8000"))
    api_auth_enabled: bool = _env_bool("API_AUTH_ENABLED", False)
    api_auth_token: Secret = Secret(os.getenv("API_AUTH_TOKEN", ""))
    api_max_body_bytes: int = int(os.getenv("API_MAX_BODY_BYTES", str(1024 * 1024)))
    api_trusted_proxies: tuple[str, ...] = tuple(
        value.strip() for value in os.getenv("API_TRUSTED_PROXIES", "").split(",") if value.strip()
    )
    api_auth_rate_limit: int = int(os.getenv("API_AUTH_RATE_LIMIT", "10"))
    api_auth_backoff_seconds: int = int(os.getenv("API_AUTH_BACKOFF_SECONDS", "1"))
    api_docs_enabled: bool = _env_bool("API_DOCS_ENABLED", True)
    api_auto_migrate: bool = _env_bool("API_AUTO_MIGRATE", True)
    api_cors_origins: tuple[str, ...] = tuple(
        value.strip() for value in os.getenv("API_CORS_ORIGINS", "http://localhost:3000").split(",") if value.strip()
    )
    response_approval_ttl_seconds: int = max(60, int(os.getenv("SOC_RESPONSE_APPROVAL_TTL_SECONDS", "3600")))
    response_require_different_approver: bool = _env_bool("SOC_RESPONSE_REQUIRE_DIFFERENT_APPROVER", False)
    response_protected_ips: tuple[str, ...] = tuple(v.strip() for v in os.getenv("SOC_RESPONSE_PROTECTED_IPS", "").split(",") if v.strip())
    response_protected_hosts: tuple[str, ...] = tuple(v.strip().lower() for v in os.getenv("SOC_RESPONSE_PROTECTED_HOSTS", "").split(",") if v.strip())
    response_protected_accounts: tuple[str, ...] = tuple(v.strip().lower() for v in os.getenv("SOC_RESPONSE_PROTECTED_ACCOUNTS", "administrator,system,root").split(",") if v.strip())


settings = Settings()


def validate_production(settings_value: Settings = settings) -> list[str]:
    """Return configuration errors that must block a production start."""
    errors: list[str] = []
    if settings_value.environment not in {"development", "demo", "production", "test"}:
        errors.append("SOC_ENVIRONMENT must be development, demo, test, or production")
    if settings_value.environment != "production":
        return errors
    token = settings_value.api_auth_token.reveal()
    if not settings_value.api_auth_enabled:
        errors.append("API_AUTH_ENABLED must be true in production")
    if len(token) < 32:
        errors.append("API_AUTH_TOKEN must contain at least 32 characters in production")
    if token in {"change-me", "replace-me", "development-token", ""}:
        errors.append("API_AUTH_TOKEN must not be a placeholder")
    if not settings_value.api_cors_origins or "*" in settings_value.api_cors_origins:
        errors.append("API_CORS_ORIGINS must contain explicit origins and cannot contain '*'")
    if settings_value.api_host == "0.0.0.0" and not settings_value.api_auth_enabled:
        errors.append("0.0.0.0 cannot be exposed with development authentication")
    if settings_value.api_docs_enabled:
        errors.append("API_DOCS_ENABLED must be false in production")
    if settings_value.api_auto_migrate:
        errors.append("API_AUTO_MIGRATE must be false in production")
    if settings_value.response_protected_accounts is None:
        errors.append("response protected accounts must be configured")
    return errors


def effective_config(settings_value: Settings = settings) -> dict[str, Any]:
    """Return a JSON-safe configuration view with secrets redacted."""
    result = {}
    for key, value in settings_value.__dict__.items():
        if key == "api_auth_token":
            result[key] = repr(value)
        elif isinstance(value, Path):
            result[key] = str(value)
        elif isinstance(value, tuple):
            result[key] = list(value)
        else:
            result[key] = value
    return result
