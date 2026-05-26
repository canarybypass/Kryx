import os
import asyncio
import httpx
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("OPENROUTER_API_KEY")
MODELS = [
    "nvidia/nemotron-3-super-120b-a12b:free",
    "google/gemma-4-31b-it:free",
    "google/gemma-4-26b-a4b-it:free",
    "minimax/minimax-m2.5:free",
]


async def ask(system: str, prompt: str) -> str:
    for model in MODELS:
        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=90) as client:
                    r = await client.post(
                        "https://openrouter.ai/api/v1/chat/completions",
                        headers={"Authorization": f"Bearer {API_KEY}"},
                        json={
                            "model": model,
                            "messages": [
                                {"role": "system", "content": system},
                                {"role": "user", "content": prompt},
                            ],
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
