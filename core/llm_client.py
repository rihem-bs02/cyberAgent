"""
LLM Client — unified Groq/Qwen wrapper
All agents call this. Never call Groq directly from agent code.
Handles retries, model fallback, and token limits.
"""
from groq import Groq
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from loguru import logger
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config.settings import GROQ_API_KEY, GROQ_MODEL_HEAVY, GROQ_MODEL_FAST

# Model assignments per task weight
MODELS = {
    "heavy":  GROQ_MODEL_HEAVY,   # llama-3.3-70b-versatile  — orchestration, planning
    "fast":   GROQ_MODEL_FAST,    # qwen/qwen3-32b           — analysis, structured output
    "local":  "ollama/qwen2.5:7b-instruct",                  # offline fallback
}

MAX_TOKENS   = 4096
TEMPERATURE  = 0.2    # low = more deterministic decisions


class LLMClient:

    def __init__(self):
        if not GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY not set in .env")
        self.client = Groq(api_key=GROQ_API_KEY)
        logger.info(f"LLM client initialized | heavy={MODELS['heavy']} fast={MODELS['fast']}")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(Exception),
        reraise=True,
    )
    def complete(
        self,
        system_prompt: str,
        user_prompt:   str,
        model_tier:    str  = "heavy",
        max_tokens:    int  = MAX_TOKENS,
        temperature:   float = TEMPERATURE,
        json_mode:     bool  = False,
    ) -> str:
        """
        Single completion call.
        model_tier: "heavy" | "fast"
        json_mode:  True → forces JSON output (use for structured agent outputs)
        """
        model = MODELS.get(model_tier, MODELS["heavy"])

        kwargs = dict(
            model=model,
            messages=[
                {"role": "system",  "content": system_prompt},
                {"role": "user",    "content": user_prompt},
            ],
            max_tokens=max_tokens,
            temperature=temperature,
        )
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
            # Qwen3 defaults to thinking mode — disable it for deterministic JSON output
            if "qwen3" in model.lower() or "qwen/qwen3" in model.lower():
                kwargs["reasoning_effort"] = "none"

        try:
            response = self.client.chat.completions.create(**kwargs)
            content  = response.choices[0].message.content
            logger.debug(f"LLM [{model_tier}] → {len(content)} chars")
            return content

        except Exception as e:
            logger.warning(f"LLM error ({model_tier}/{model}): {e} — retrying...")
            raise

    def plan(self, system: str, prompt: str) -> str:
        """Campaign planning — uses heavy model."""
        return self.complete(system, prompt, model_tier="heavy")

    def analyze(self, system: str, prompt: str) -> str:
        """Structured analysis — uses fast model."""
        return self.complete(system, prompt, model_tier="fast")

    def decide(self, system: str, prompt: str) -> dict:
        """
        Decision call — returns parsed JSON dict.
        Use for: should I exploit X? which technique? pivot or continue?
        """
        import json
        raw = self.complete(system, prompt, model_tier="fast", json_mode=True)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("JSON decode failed — returning raw text in dict")
            return {"raw": raw, "error": "json_parse_failed"}
