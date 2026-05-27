"""
Hexor LLM Client — unified interface to multiple LLM providers
"""
import os
import json
import asyncio
import httpx
from dotenv import load_dotenv

load_dotenv()


class LLMClient:
    """Unified LLM client with provider fallback."""

    def __init__(self, model: str | None = None):
        self.model = model or os.getenv("HEXOR_MODEL", "openrouter/anthropic/claude-opus-4")

    async def ask(self, system: str, prompt: str, json_mode: bool = True) -> str:
        provider, model_name = self._parse_model(self.model)

        if provider == "openrouter":
            return await self._openrouter(system, prompt, model_name, json_mode)
        elif provider == "anthropic":
            return await self._anthropic(system, prompt, model_name)
        elif provider == "openai":
            return await self._openai(system, prompt, model_name, json_mode)
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

        # Fallback models if primary fails
        fallbacks = [
            model,
            "anthropic/claude-sonnet-4",
            "openai/gpt-4o",
            "google/gemini-2.5-pro",
        ]

        for fb_model in fallbacks:
            for attempt in range(3):
                try:
                    async with httpx.AsyncClient(timeout=120) as client:
                        r = await client.post(
                            "https://openrouter.ai/api/v1/chat/completions",
                            headers={
                                "Authorization": f"Bearer {api_key}",
                                "HTTP-Referer": "https://hexor.dev",
                                "X-Title": "Hexor",
                            },
                            json={
                                "model": fb_model,
                                "messages": [
                                    {"role": "system", "content": system},
                                    {"role": "user", "content": prompt},
                                ],
                                "response_format": {"type": "json_object"} if json_mode else None,
                            },
                        )
                        if r.status_code == 429:
                            await asyncio.sleep(5 * (attempt + 1))
                            continue
                        r.raise_for_status()
                        return r.json()["choices"][0]["message"]["content"]
                except Exception:
                    await asyncio.sleep(3)
        raise RuntimeError("All models failed. Try again later.")

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
    if _llm is None or model:
        _llm = LLMClient(model)
    return _llm


# Backward compatibility
async def ask(system: str, prompt: str) -> str:
    return await get_llm().ask(system, prompt)