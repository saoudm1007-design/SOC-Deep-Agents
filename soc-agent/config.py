from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Model selection
    model_provider: str = Field(default="openrouter", pattern="^(ollama|claude|openrouter)$")

    # OpenRouter (default/recommended)
    openrouter_api_key: str = ""
    openrouter_model: str = "google/gemini-2.5-flash"

    # Anthropic Claude
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-6"

    # Ollama (local)
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"

    # Tool API keys (all optional)
    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""
    nvd_api_key: str = ""

    # Cache
    cache_dir: str = ".cache"


settings = Settings()
