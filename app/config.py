"""Global configuration — loaded from settings.json, overridable via GUI."""
from __future__ import annotations

import json
from pathlib import Path
from pydantic import BaseModel, Field

SETTINGS_PATH = Path(__file__).parent.parent / "settings.json"

_IDA_DEFAULT = r"D:\my\ReSource\IDA Pro 8.3"


class Settings(BaseModel):
    # MCP / IDA connection
    mcp_endpoint: str = "http://localhost:13337"
    mcp_mode: str = "headless"          # "headless" | "ida_plugin"

    # Headless mode — idat64.exe
    ida_dir: str = _IDA_DEFAULT         # IDA Pro installation directory
    idat_timeout: float = 600.0         # seconds for full idat64 run

    # Plugin mode — parallel MCP calls
    max_workers: int = 3
    decompile_timeout: float = 30.0
    retry_count: int = 2

    # Storage
    artifacts_dir: str = "artifacts"
    outputs_dir: str = "outputs"

    # .NET decompile — reference assembly directories (passed as -r to ilspycmd)
    dotnet_ref_paths: list[str] = Field(default_factory=list)


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = _load()
    return _settings


def _load() -> Settings:
    if SETTINGS_PATH.exists():
        data = json.loads(SETTINGS_PATH.read_text())
        return Settings(**data)
    return Settings()


def save_settings(s: Settings) -> None:
    global _settings
    _settings = s
    SETTINGS_PATH.write_text(s.model_dump_json(indent=2))
