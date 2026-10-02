"""Bounded local SOC assistant chat backed by Ollama or a deterministic fallback."""
import json
import time
import urllib.error
import urllib.request

from app.config import settings
from investigation.provider import validate_endpoint

_SYSTEM_PROMPT = """You are the AI SOC Analyst assistant inside a defensive security operations dashboard.
Answer questions about the dashboard, alerts, incidents, detections, IOCs, ATT&CK mappings, investigations, and safe simulated response workflows.
Use concise analyst language. Do not claim access to systems or data outside the supplied dashboard context.
Never provide instructions for exploitation, credential theft, persistence, evasion, or destructive actions.
If the user asks for an action, explain that this application only recommends or simulates response actions.
"""
_status_cache: tuple[float, str] = (0.0, "unknown")


def provider_status() -> str:
    """Return cached local-provider state without probing Ollama on every request."""
    global _status_cache
    now = time.monotonic()
    if now - _status_cache[0] < 15:
        return _status_cache[1]
    if settings.llm_provider.lower() != "ollama":
        result = "not_configured"
    else:
        try:
            host = validate_endpoint(settings.ollama_host)
            request = urllib.request.Request(host.rstrip("/") + "/api/tags", method="GET")
            with urllib.request.urlopen(request, timeout=2) as response:
                models = json.loads(response.read().decode("utf-8")).get("models", [])
            names = {str(model.get("name", "")) for model in models if isinstance(model, dict)}
            result = "available" if settings.llm_model in names or f"{settings.llm_model}:latest" in names else "unavailable"
        except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError):
            result = "unavailable"
    _status_cache = (now, result)
    return result


def _fallback(question: str) -> str:
    lowered = question.lower()
    if "ollama" in lowered or "provider" in lowered:
        return "The assistant is configured to use the local Ollama provider. Check System Status for the current provider state."
    if "response" in lowered or "block" in lowered or "disable" in lowered:
        return "Response actions in this dashboard are recommendation and simulation only. Analyst approval is required before any simulated action."
    if "incident" in lowered or "alert" in lowered or "ioc" in lowered:
        return "Review the linked evidence, risk score, confidence, ATT&CK mappings, and investigation findings before taking action."
    return "I can explain the SOC dashboard, alerts, incidents, IOCs, investigations, ATT&CK mappings, and simulated response workflow."


def ask(question: str, *, context: dict | None = None) -> dict:
    question = " ".join(str(question).split())[:2000]
    if not question:
        raise ValueError("question is required")
    provider = settings.llm_provider.lower()
    if provider != "ollama":
        return {"answer": _fallback(question), "provider": "fallback", "model": None}
    host = validate_endpoint(settings.ollama_host)
    payload = json.dumps({
        "model": settings.llm_model,
        "system": _SYSTEM_PROMPT,
        "prompt": f"Dashboard context:\n{json.dumps(context or {}, sort_keys=True)[:6000]}\n\nQuestion: {question}",
        "stream": False,
        "options": {"temperature": 0, "seed": settings.llm_seed, "num_predict": min(settings.llm_max_output_tokens, 512)},
    }).encode("utf-8")
    request = urllib.request.Request(host.rstrip("/") + "/api/generate", data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=min(settings.llm_timeout_seconds, 60)) as response:
            result = json.loads(response.read().decode("utf-8"))
        answer = str(result.get("response", "")).strip()
        if not answer:
            raise ValueError("Ollama returned an empty response")
        return {"answer": answer[:6000], "provider": "ollama", "model": settings.llm_model}
    except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        return {"answer": _fallback(question), "provider": "fallback", "model": None, "warning": "Local Ollama was unavailable; a safe fallback answer was used."}
