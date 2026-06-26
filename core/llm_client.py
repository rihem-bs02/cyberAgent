"""
LLM Client — unified Groq/Qwen wrapper
All agents call this. Never call Groq directly from agent code.
Handles retries, model fallback, empty responses, and token limits.
"""
from groq import Groq
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from loguru import logger
import os, sys, json, time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config.settings import GROQ_API_KEY, GROQ_MODEL_HEAVY, GROQ_MODEL_FAST

# Model assignments per task weight
MODELS = {
    "heavy":  GROQ_MODEL_HEAVY,   # llama-3.3-70b-versatile  — orchestration, planning
    "fast":   GROQ_MODEL_FAST,    # qwen/qwen3-32b           — analysis, structured output
    "local":  "qwen",                                        # offline fallback
}

MAX_TOKENS   = 4096
TEMPERATURE  = 0.2    # low = more deterministic decisions

# Models known to sometimes return empty output when thinking is enabled
_QWEN3_MODELS = {"qwen/qwen3-32b", "qwen3-32b"}


class LLMClient:

    def __init__(self):
        if not GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY not set in .env")
        self.client = Groq(api_key=GROQ_API_KEY)
        logger.info(f"LLM client initialized | heavy={MODELS['heavy']} fast={MODELS['fast']}")

    def complete(
        self,
        # Accept both calling conventions: (system, user) and (system_prompt, user_prompt)
        system:       str  = "",
        user:         str  = "",
        system_prompt:str  = "",
        user_prompt:  str  = "",
        # Model: accept both "model" and "model_tier" keys
        model:        str  = "",
        model_tier:   str  = "heavy",
        max_tokens:   int  = MAX_TOKENS,
        temperature:  float= TEMPERATURE,
        json_mode:    bool = False,
        retries:      int  = 3,
    ) -> str:
        """
        Single completion call with retry and empty-response handling.

        Accepts two calling conventions:
          llm.complete(system=..., user=..., model="heavy", json_mode=True)
          llm.complete(system_prompt=..., user_prompt=..., model_tier="fast")
        """
        # Normalize arguments
        sys_msg  = system or system_prompt
        usr_msg  = user   or user_prompt
        tier     = model  or model_tier or "heavy"
        resolved = MODELS.get(tier, MODELS["heavy"])

        kwargs = dict(
            model    = resolved,
            messages = [
                {"role": "system", "content": sys_msg},
                {"role": "user",   "content": usr_msg},
            ],
            max_tokens  = max_tokens,
            temperature = temperature,
        )

        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
            # Qwen3 defaults to thinking mode — disable it so JSON output is clean
            if any(m in resolved.lower() for m in ("qwen3", "qwen/qwen3")):
                kwargs["reasoning_effort"] = "none"

        last_error = None
        for attempt in range(1, retries + 1):
            try:
                response = self.client.chat.completions.create(**kwargs)
                content  = response.choices[0].message.content

                # Guard: Groq can return None content on empty model outputs
                if not content or not content.strip():
                    logger.warning(
                        f"LLM [{tier}/{resolved}] returned empty content "
                        f"(attempt {attempt}/{retries}) — retrying with higher temperature"
                    )
                    kwargs["temperature"] = min(0.7, temperature + 0.2 * attempt)
                    # If json_mode caused it, try without on last attempt
                    if attempt == retries - 1 and json_mode:
                        logger.warning("Disabling json_mode for final retry on empty response")
                        kwargs.pop("response_format", None)
                        kwargs.pop("reasoning_effort", None)
                    time.sleep(1.5 * attempt)
                    continue

                logger.debug(f"LLM [{tier}] -> {len(content)} chars")
                return content

            except Exception as e:
                last_error = e
                err_str = str(e)
                # Specific handling: "model output must contain either output text or tool calls"
                if "model output" in err_str and "empty" in err_str:
                    logger.warning(
                        f"LLM [{tier}] empty output error (attempt {attempt}/{retries}): {err_str}"
                    )
                    # Retry without json_mode — sometimes the model gets confused
                    if json_mode:
                        kwargs.pop("response_format", None)
                        kwargs.pop("reasoning_effort", None)
                        json_mode = False
                    time.sleep(2 * attempt)
                    continue
                else:
                    logger.warning(f"LLM error ({tier}/{resolved}): {e} — retrying...")
                    time.sleep(1.5 * attempt)
                    continue

        # All retries exhausted
        logger.error(f"LLM [{tier}] failed after {retries} attempts: {last_error}")
        # Return a safe fallback so the caller doesn't crash
        if json_mode:
            return json.dumps({
                "error":      str(last_error),
                "thought":    "LLM unavailable — skipping step",
                "tool":       "none",
                "args":       {},
                "done":       False,
                "finding":    None,
            })
        return f"[LLM error: {last_error}]"

    # ── Convenience wrappers ───────────────────────────────────────────────────

    def plan(self, system: str, prompt: str) -> str:
        """Campaign planning — uses heavy model."""
        return self.complete(system=system, user=prompt, model="heavy")

    def analyze(self, system: str, prompt: str) -> str:
        """Structured analysis — uses fast model."""
        return self.complete(system=system, user=prompt, model="fast")

    def decide(self, system: str, prompt: str) -> dict:
        """
        Decision call — returns parsed JSON dict.
        Use for: should I exploit X? which technique? pivot or continue?
        """
        raw = self.complete(
            system=system, user=prompt,
            model="fast", json_mode=True,
        )
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("JSON decode failed — returning raw text in dict")
            return {"raw": raw, "error": "json_parse_failed"}
