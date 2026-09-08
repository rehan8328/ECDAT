from __future__ import annotations

import os
from pathlib import Path


def _load_root_env() -> dict[str, str]:
    values: dict[str, str] = {}
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if env_path.exists():
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
    return values


_env = _load_root_env()
FRONTEND_PORT = int(os.getenv("FRONTEND_PORT", _env.get("FRONTEND_PORT", "5174")))
API_PORT = int(os.getenv("API_PORT", _env.get("API_PORT", "8001")))
API_BASE_URL = os.getenv("API_BASE_URL", _env.get("API_BASE_URL", f"http://127.0.0.1:{API_PORT}"))
FRONTEND_ORIGINS = [f"http://127.0.0.1:{FRONTEND_PORT}", f"http://localhost:{FRONTEND_PORT}"]
