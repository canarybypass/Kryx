import os
from dotenv import load_dotenv

load_dotenv()

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

DEFAULT_MODEL = os.getenv("HEXOR_MODEL", "openrouter/anthropic/claude-opus-4")
MAX_HUNTERS = int(os.getenv("HEXOR_MAX_HUNTERS", "8"))
MAX_STEPS = int(os.getenv("HEXOR_MAX_STEPS", "15"))
SANDBOX_DIR = os.getenv("HEXOR_SANDBOX_DIR", "/tmp/hexor-sandbox")