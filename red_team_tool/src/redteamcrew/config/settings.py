from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application configuration management.
    Validates environment variables on startup.
    """
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    deepinfra_api_key: str = Field(
        default="", description="API Key for DeepInfra services"
    )
    llm_model: str = Field(
        default="deepinfra/google/gemma-4-31B-it",
        description="LLM model identifier in deepinfra/<modelo> format",
    )
    # Add other configuration variables here
