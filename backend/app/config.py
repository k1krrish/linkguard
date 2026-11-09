"""Runtime settings, read from environment variables on every call.

Reading on every call (instead of caching) keeps tests simple: a test can
change an environment variable with ``monkeypatch.setenv`` and the next
request sees the new value.
"""

import os
from dataclasses import dataclass, field


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    # Development/test only. When true, loopback/private destinations and
    # arbitrary ports are accepted by the live diagnostic endpoints so that
    # controlled local test servers can be used. NEVER enable on a shared host.
    allow_private_targets: bool = False
    max_upload_bytes: int = 10 * 1024 * 1024
    max_packets: int = 20_000
    default_timeout: float = 5.0
    max_timeout: float = 10.0
    max_investigations: int = 50
    cors_origins: list[str] = field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "https://linkguard-de1c.onrender.com",
        ]
    )


def get_settings() -> Settings:
    origins = os.environ.get("LINKGUARD_CORS_ORIGINS")
    return Settings(
        allow_private_targets=_env_bool("LINKGUARD_ALLOW_PRIVATE_TARGETS", False),
        max_upload_bytes=_env_int("LINKGUARD_MAX_UPLOAD_MB", 10) * 1024 * 1024,
        max_packets=_env_int("LINKGUARD_MAX_PACKETS", 20_000),
        cors_origins=[o.strip() for o in origins.split(",") if o.strip()]
        if origins
        else Settings().cors_origins,
    )
