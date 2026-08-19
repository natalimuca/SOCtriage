import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
OUT = ROOT / "out"

load_dotenv(ROOT / ".env")


class Settings:
    def __init__(self) -> None:
        self.model = os.getenv("SOC_MODEL", "claude-opus-5")
        self.effort = os.getenv("SOC_EFFORT", "high")
        self.max_tokens = int(os.getenv("SOC_MAX_TOKENS", "8000"))
        self.indexer_url = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
        self.indexer_user = os.getenv("WAZUH_INDEXER_USER", "admin")
        self.indexer_password = os.getenv("WAZUH_INDEXER_PASSWORD", "SecretPassword")
        self.indexer_verify = os.getenv("WAZUH_INDEXER_VERIFY", "false").lower() == "true"
        self.correlation_window = int(os.getenv("SOC_CORRELATION_WINDOW", "600"))
        self.concurrency = int(os.getenv("SOC_CONCURRENCY", "4"))

    @property
    def has_credentials(self) -> bool:
        if os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN"):
            return True
        return (Path.home() / ".config" / "anthropic").exists()


settings = Settings()
