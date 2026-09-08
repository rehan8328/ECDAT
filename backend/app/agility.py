from __future__ import annotations

import re
import os
from pathlib import Path

from .models import CryptoAsset


CONFIG_SUFFIXES = {".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf"}
WRAPPER_PATTERN = re.compile(r"\b(?:class\s+\w*(?:Crypto|Provider)|def\s+(?:encrypt|decrypt|sign|verify|create_cipher|crypto_\w+))", re.IGNORECASE)
SKIP_DIRECTORIES = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "dist", "build", "coverage", "__pycache__", ".pytest_cache", ".pytest-run", ".mypy_cache", ".ruff_cache", ".tox", ".ppt-build", ".npm-cache", ".cache", ".next", ".nuxt", "vendor", "target", "outputs", "tests", "test", "fixtures", "examples", "docs"}
MAX_TEXT_FILE_BYTES = 1_000_000


def enrich_crypto_agility(directory: Path, assets: list[CryptoAsset]) -> list[CryptoAsset]:
    """Calculate explainable migration agility without changing discovery findings."""
    texts: dict[str, str] = {}
    for root, directories, filenames in os.walk(directory):
        directories[:] = [
            name for name in directories
            if name not in SKIP_DIRECTORIES and not name.startswith(("test-tmp", "test_"))
        ]
        root_path = Path(root)
        for filename in filenames:
            path = root_path / filename
            try:
                if path.stat().st_size > MAX_TEXT_FILE_BYTES:
                    continue
                texts[path.relative_to(directory).as_posix()] = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

    enriched: list[CryptoAsset] = []
    for asset in assets:
        token = re.escape(asset.algorithm).replace(r"\-", "[-_ ]?")
        references = [name for name, content in texts.items() if re.search(token, content, re.IGNORECASE)]
        count = len(references)
        config_names = [name for name in references if Path(name).suffix.lower() in CONFIG_SUFFIXES or Path(name).name in {"settings.py", "config.py"}]
        config_points = 30 if config_names else 0
        fanout_points = max(0, 30 - max(0, count - 1) * 5)
        source = texts.get(asset.location, "")
        dedicated_module = any(part in asset.location.lower() for part in ("crypto", "security", "encryption"))
        wrapped = bool(WRAPPER_PATTERN.search(source))
        abstraction_points = 40 if wrapped else 15 if dedicated_module else 0
        score = min(100, config_points + fanout_points + abstraction_points)
        reason_parts = ["configuration-managed" if config_names else "inline or unlinked configuration", f"referenced in {count or 1} file(s)", "project abstraction detected" if wrapped else "no project abstraction detected"]
        enriched.append(asset.model_copy(update={
            "crypto_agility_score": score,
            "crypto_agility_reason": "; ".join(reason_parts),
            "algorithm_file_count": count or 1,
        }))
    return enriched
