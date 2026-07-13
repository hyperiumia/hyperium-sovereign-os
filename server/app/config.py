from pydantic import ConfigDict
from pydantic_settings import BaseSettings
from pathlib import Path
import os


class Settings(BaseSettings):
    APP_NAME: str = "Hyperium Sovereign-OS"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    DATABASE_URL: str = "sqlite+aiosqlite:///./sovereign_os.db"
    KEYS_DIR: Path = Path("./app/keys")
    EVIDENCE_DIR: Path = Path("./evidence_store")
    AGENT_HMAC_SECRET: str = os.getenv(
        "SOS_AGENT_HMAC_SECRET",
        "change-me-in-production-to-a-strong-random-secret-256bit"
    )
    POLICIES_DIR: Path = Path("./policies")
    MERKLE_EPOCH_SECONDS: int = 300
    RISK_FREEZE_THRESHOLD: float = 0.85
    RISK_ALERT_THRESHOLD: float = 0.60
    MAX_EVENTS_PER_AGENT_PER_MINUTE: int = 600

    class Config:
        env_prefix = "SOS_"


settings = Settings()
