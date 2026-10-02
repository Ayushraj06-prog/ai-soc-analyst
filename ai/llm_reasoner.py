"""
LLM Reasoner module handling communication with language models.
"""
import logging

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

class LLMReasoner:
    """
    Provider-based architecture for communicating with an LLM.
    Defaults to Ollama (llama3), but designed to be extensible to OpenAI/Gemini.
    """
    def __init__(self, provider="ollama", model="llama3"):
        self.provider = provider
        self.model = model
        self.logger = logging.getLogger(__name__)
        
    def health_check(self) -> bool:
        """Verifies that the configured provider is available."""
        if self.provider == "ollama":
            if not OLLAMA_AVAILABLE:
                self.logger.error("Ollama python package is not installed. Run `pip install ollama`.")
                return False
            # Can also test local ollama ping here if desired
            return True
        return False
        
    def analyze(self, prompt: str) -> str:
        """Sends the prompt to the configured LLM and returns the response."""
        if self.provider == "ollama":
            return self._analyze_ollama(prompt)
        else:
            return f"Error: Provider {self.provider} not implemented yet."
            
    def _analyze_ollama(self, prompt: str) -> str:
        """Internal method for Ollama interaction with error handling."""
        if not OLLAMA_AVAILABLE:
            return "Error: Ollama library not installed. Please run `pip install ollama` to use the AI features."
            
        try:
            # Using ollama library directly
            response = ollama.generate(model=self.model, prompt=prompt)
            return response.get('response', '')
        except Exception as e:
            error_msg = f"Failed to connect to Ollama or generate response: {str(e)}"
            self.logger.error(error_msg)
            return f"Error: {error_msg}\n\nPlease ensure Ollama is running on your machine and the model '{self.model}' is downloaded (run `ollama run {self.model}`)."
