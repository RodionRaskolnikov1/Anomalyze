from pathlib import Path
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str
    API_KEY: str

    
    MODELS_DIR: Path = Path("models")

    class Config:
        env_file = ".env"

settings = Settings()

settings.MODELS_DIR.mkdir(parents=True, exist_ok=True)