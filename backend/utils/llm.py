"""
Kryx LLM Client - unified interface to multiple LLM providers
"""
import os
import asyncio
from contextvars import ContextVar
import httpx
from dotenv import load_dotenv

load_dotenv()

# Per-scan model override (async-safe - each scan task has its own context).
# The SaaS layer sets this to gate the model by plan tier (cheap DeepSeek for
# free/low tiers, Opus for paid) so one user can't burn the API budget.
_model_override: ContextVar[str | None] = ContextVar("kryx_model_override", default=None)


def set_model_override(model: str | None):
    """Pin the LLM model for the current async context. Returns a reset token."""
    return _model_override.set(model)


class LLMClient:
    """Unified LLM client with provider fallback."""

    def __init__(self, model: str | None = None):
        self.model = model or os.getenv("KRYX_MODEL") or os.getenv("HEXOR_MODEL", "openrouter/anthropic/claude-opus-4")

    async def ask(self, system: str, prompt: str, json_mode: bool = True) -> str:
        provider, model_name = self._parse_model(self.model)

        if provider == "openrouter":
            return await self._openrouter(system, prompt, model_name, json_mode)
        elif provider == "anthropic":
            return await self._anthropic(system, prompt, model_name)
        elif provider == "openai":
            return await self._openai(system, prompt, model_name, json_mode)
        elif provider == "groq":
            return await self._groq(system, prompt, model_name)
        else:
            return await self._openrouter(system, prompt, model_name, json_mode)

    def _parse_model(self, model: str) -> tuple[str, str]:
        if "/" in model:
            provider, name = model.split("/", 1)
            return provider, name
        return "openrouter", model

    async def _openrouter(self, system: str, prompt: str, model: str, json_mode: bool) -> str:
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise RuntimeError("OPENROUTER_API_KEY not set")

        # Fallback models if the primary fails. Default to DeepSeek - a cheap
        # BUT COHERENT model - not the free junk models we used pre-revenue:
        # those emit garbled multilingual text (e.g. "Крабжа сессий") that
        # silently corrupted paid reports when the primary 402'd on low credit.
        # Set OPENROUTER_FALLBACKS="" to disable fallback and fail loudly.
        env_fb = os.getenv("OPENROUTER_FALLBACKS")
        if env_fb is not None:
            extra = [m.strip() for m in env_fb.split(",") if m.strip()]
        else:
            extra = ["deepseek/deepseek-chat-v3-0324"]
        fallbacks = [model] + [m for m in extra if m != model]

        last_err = "unknown"
        for fb_model in fallbacks:
            for attempt in range(3):
                try:
                    async with httpx.AsyncClient(timeout=120) as client:
                        payload = {
                            "model": fb_model,
                            "messages": [
                                {"role": "system", "content": system},
                                {"role": "user", "content": prompt},
                            ],
                            # Cap output tokens. Without this OpenRouter reserves
                            # the model's full context (e.g. 65k for Opus) and
                            # rejects with 402 on a low balance - which then
                            # silently fell back to junk models. A sane cap lets
                            # the paid model actually run.
                            "max_tokens": int(os.getenv("OPENROUTER_MAX_TOKENS", "8000")),
                        }
                        # Only request strict JSON mode when explicitly asked;
                        # many (esp. free) models reject response_format and
                        # the caller-side parser already extracts JSON.
                        if json_mode and os.getenv("OPENROUTER_JSON_MODE") == "1":
                            payload["response_format"] = {"type": "json_object"}
                        r = await client.post(
                            "https://openrouter.ai/api/v1/chat/completions",
                            headers={
                                "Authorization": f"Bearer {api_key}",
                                "HTTP-Referer": "https://kryx.io",
                                "X-Title": "Kryx",
                            },
                            json=payload,
                        )
                        if r.status_code == 429:
                            last_err = f"{fb_model}: 429 rate-limited"
                            await asyncio.sleep(5 * (attempt + 1))
                            continue
                        r.raise_for_status()
                        body = r.json()
                        choices = body.get("choices")
                        if not choices:
                            last_err = f"{fb_model}: no choices ({str(body)[:120]})"
                            await asyncio.sleep(2)
                            continue
                        return choices[0]["message"]["content"]
                except Exception as e:
                    last_err = f"{fb_model}: {type(e).__name__}: {str(e)[:120]}"
                    await asyncio.sleep(3)
        raise RuntimeError(f"All models failed. Last error - {last_err}")

    async def _groq(self, system: str, prompt: str, model: str) -> str:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError("GROQ_API_KEY not set")

        # Groq is OpenAI-compatible. Generous free tier, no card. We don't
        # force response_format (json) - the caller-side parser extracts JSON.
        last_err = "unknown"
        for attempt in range(4):
            try:
                async with httpx.AsyncClient(timeout=120) as client:
                    r = await client.post(
                        "https://api.groq.com/openai/v1/chat/completions",
                        headers={"Authorization": f"Bearer {api_key}"},
                        json={
                            "model": model,
                            "messages": [
                                {"role": "system", "content": system},
                                {"role": "user", "content": prompt},
                            ],
                            "temperature": 0.3,
                        },
                    )
                    if r.status_code == 429:
                        last_err = "429 rate-limited"
                        await asyncio.sleep(4 * (attempt + 1))
                        continue
                    r.raise_for_status()
                    return r.json()["choices"][0]["message"]["content"]
            except Exception as e:
                last_err = f"{type(e).__name__}: {str(e)[:120]}"
                await asyncio.sleep(2)
        raise RuntimeError(f"Groq failed - {last_err}")

    async def _anthropic(self, system: str, prompt: str, model: str) -> str:
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")

        async with httpx.AsyncClient(timeout=120) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                },
                json={
                    "model": model,
                    "max_tokens": 4096,
                    "system": system,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            r.raise_for_status()
            return r.json()["content"][0]["text"]

    async def _openai(self, system: str, prompt: str, model: str, json_mode: bool) -> str:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY not set")

        async with httpx.AsyncClient(timeout=120) as client:
            r = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    "response_format": {"type": "json_object"} if json_mode else None,
                },
            )
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]


# Singleton
_llm: LLMClient | None = None


def get_llm(model: str | None = None) -> LLMClient:
    global _llm
    effective = model or _model_override.get()
    if effective:
        # per-context model (tier gating) - don't cache across tiers/scans
        return LLMClient(effective)
    if _llm is None:
        _llm = LLMClient(None)
    return _llm


# Backward compatibility
async def ask(system: str, prompt: str) -> str:
    return await get_llm().ask(system, prompt)