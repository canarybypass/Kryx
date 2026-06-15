import os
from dotenv import load_dotenv

load_dotenv()

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# KRYX_* env vars (with HEXOR_* fallback for backward compatibility)
def _env(new, old, default):
    return os.getenv(new) or os.getenv(old, default)

DEFAULT_MODEL = _env("KRYX_MODEL", "HEXOR_MODEL", "openrouter/anthropic/claude-opus-4")
MAX_HUNTERS = int(_env("KRYX_MAX_HUNTERS", "HEXOR_MAX_HUNTERS", "8"))
MAX_STEPS = int(_env("KRYX_MAX_STEPS", "HEXOR_MAX_STEPS", "15"))
SANDBOX_DIR = _env("KRYX_SANDBOX_DIR", "HEXOR_SANDBOX_DIR", "/tmp/kryx-sandbox")