"""Configuration loading.

Deliberately reads ONLY project-scoped ``USER_LLM_*`` / ``AP_ENGINE_*``
variables. It must never read agent-platform credentials such as
``MCAI_LLM_*``; doing so would couple user code to the execution environment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

_TRUTHY = {"1", "true", "yes", "on"}


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (no external dependency).

    Existing environment variables always win, so a real shell export is not
    silently overridden by a stale file.
    """
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


@dataclass
class Config:
    provider: str = "anthropic"
    api_key: str | None = None
    base_url: str | None = None
    model: str = "claude-sonnet-5"
    offline: bool = False
    top_n: int = 15
    max_depth: int = 12
    owned: list[str] = field(default_factory=list)

    @property
    def llm_enabled(self) -> bool:
        return (not self.offline) and bool(self.api_key) and bool(self.model)

    @classmethod
    def from_env(cls, env_file: str | os.PathLike[str] | None = None) -> "Config":
        if env_file is None:
            env_file = Path(__file__).resolve().parents[2] / ".env"
        _load_dotenv(Path(env_file))

        owned_raw = os.getenv("AP_ENGINE_OWNED", "")
        owned = [s.strip().lower() for s in owned_raw.split(",") if s.strip()]

        return cls(
            provider=os.getenv("AP_ENGINE_LLM_PROVIDER", "anthropic").strip(),
            api_key=os.getenv("USER_LLM_API_KEY") or None,
            base_url=os.getenv("USER_LLM_BASE_URL") or None,
            model=os.getenv("USER_LLM_MODEL", "claude-sonnet-5").strip(),
            offline=os.getenv("AP_ENGINE_OFFLINE", "0").strip().lower() in _TRUTHY,
            top_n=int(os.getenv("AP_ENGINE_TOP_N", "15")),
            owned=owned,
        )
