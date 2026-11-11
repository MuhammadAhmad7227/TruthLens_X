from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="TLX_",
        extra="ignore",
    )

    app_name: str = "TruthLens X"
    environment: str = Field(
        default="development",
        pattern="^(development|test|production)$",
    )
    log_level: str = "INFO"
    api_prefix: str = "/api/v1"
    database_url: str = "postgresql+psycopg://tlx:tlx_dev_only@localhost:5432/truthlens"
    redis_url: str = "redis://localhost:6379/0"
    secret_key: SecretStr = SecretStr("dev-only-change-me")
    cors_origins: list[str] = ["http://localhost:3000"]

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def validate_security(self) -> None:
        if self.is_production and self.secret_key.get_secret_value() == "dev-only-change-me":
            raise RuntimeError("TLX_SECRET_KEY must be changed in production")


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.validate_security()
    return settings
