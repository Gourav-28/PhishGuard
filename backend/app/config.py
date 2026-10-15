"""Environment configuration (loaded from .env via python-dotenv)."""
import os

from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "").strip()

# "*" keeps the API usable from file:// pages (Origin: null) and chrome-extension:// popups.
# Safe here because we use no cookies/credentials; protect the API with API_KEY if you expose it publicly.
ALLOWED_ORIGINS = ["*"]

API_KEY = os.getenv("API_KEY", "").strip()
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "60"))
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "5"))
HASH_SALT = os.getenv("HASH_SALT", "change-me")
TRACE_MODE = os.getenv("TRACE_MODE", "auto").lower()          # auto | real | mock
MEDIA_SIMULATION = os.getenv("MEDIA_SIMULATION", "1") == "1"

# Optional local LLM second opinion (Ollama). "auto" = use it when reachable, "off" = never.
LLM_MODE = os.getenv("LLM_MODE", "auto").lower()
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
LLM_TIMEOUT = float(os.getenv("LLM_TIMEOUT", "25"))
