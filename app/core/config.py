from typing import Literal

from pydantic import Field, ValidationInfo, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_SECRET_KEY = "change-me-generate-with-openssl-rand-hex-32"


class Settings(BaseSettings):
    """Application settings loaded from environment variables and `.env`."""

    APP_NAME: str
    APP_ENV: Literal["development", "staging", "production"]
    DEBUG: bool
    DATABASE_URL: str
    SECRET_KEY: str = Field(min_length=32)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    JWT_ALGORITHM: str = "HS256"
    CORS_ORIGINS: list[str]

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, value: str, info: ValidationInfo) -> str:
        """Reject weak secrets and the documented placeholder in production."""
        if len(value) < 32:
            msg = "SECRET_KEY must be at least 32 characters long."
            raise ValueError(msg)

        app_env = info.data.get("APP_ENV")
        if app_env == "production" and value == DEFAULT_SECRET_KEY:
            msg = "SECRET_KEY must not use the default placeholder in production."
            raise ValueError(msg)

        return value


settings = Settings()  # type: ignore[call-arg]
