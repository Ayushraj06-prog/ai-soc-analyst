"""Provider boundary: explicit loopback policy and bounded Ollama requests."""
from urllib.parse import urlparse
import ipaddress

from app.config import settings
from investigation.output_schema import OUTPUT_JSON_SCHEMA


class ProviderError(RuntimeError): pass


def validate_endpoint(host, allow_remote=None):
    allow_remote=settings.allow_remote_llm if allow_remote is None else bool(allow_remote)
    parsed=urlparse(host if "://" in host else "http://"+host)
    hostname=(parsed.hostname or "").lower().rstrip(".")
    local=hostname=="localhost"
    if not local:
        try: local=ipaddress.ip_address(hostname).is_loopback
        except ValueError: local=False
    if not local and not allow_remote:
        raise ProviderError("remote LLM endpoint rejected; set ALLOW_REMOTE_LLM=true to explicitly permit remote processing")
    return parsed.geturl()


class OllamaProvider:
    def __init__(self, *, model=None, host=None, timeout=None, num_ctx=None, temperature=None, seed=None, max_output_tokens=None, allow_remote=None):
        self.model=model or settings.llm_model; self.host=validate_endpoint(host or settings.ollama_host,allow_remote)
        self.timeout=settings.llm_timeout_seconds if timeout is None else timeout
        self.num_ctx=settings.llm_num_ctx if num_ctx is None else num_ctx
        self.temperature=settings.llm_temperature if temperature is None else temperature
        self.seed=settings.llm_seed if seed is None else seed
        self.max_output_tokens=settings.llm_max_output_tokens if max_output_tokens is None else max_output_tokens

    def generate(self,prompt):
        try: import ollama
        except ImportError as exc: raise ProviderError("Ollama Python package is not installed") from exc
        try:
            client=ollama.Client(host=self.host,timeout=self.timeout)
            try:
                response=client.generate(model=self.model,prompt=prompt,format=OUTPUT_JSON_SCHEMA,
                    options={"num_ctx":self.num_ctx,"temperature":self.temperature,"seed":self.seed,"num_predict":self.max_output_tokens})
            except (TypeError,ValueError):
                # Older Ollama clients accept JSON mode but not a JSON Schema object.
                response=client.generate(model=self.model,prompt=prompt,format="json",
                    options={"num_ctx":self.num_ctx,"temperature":self.temperature,"seed":self.seed,"num_predict":self.max_output_tokens})
            if isinstance(response,dict): return str(response.get("response", ""))
            return str(getattr(response,"response",""))
        except Exception as exc:
            raise ProviderError(f"Ollama request failed: {str(exc)[:500]}") from exc
