from __future__ import annotations

import json
import re
from dataclasses import dataclass


CRYPTO_PACKAGES = {"cryptography", "pyopenssl", "pycryptodome", "pynacl", "bcrypt"}
JAVASCRIPT_CRYPTO_PACKAGES = {"crypto-js", "node-forge", "libsodium-wrappers", "tweetnacl", "openpgp"}
REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(?:==|>=|~=|<=)?\s*([A-Za-z0-9_.+-]+)?")


@dataclass(frozen=True)
class CryptoDependency:
    package: str
    version: str | None
    line: int
    evidence: str


def discover_python_dependencies(content: str) -> list[CryptoDependency]:
    dependencies = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        match = REQUIREMENT.match(line)
        if match is None or line.lstrip().startswith("#"):
            continue
        package = match.group(1).lower()
        if package in CRYPTO_PACKAGES:
            dependencies.append(CryptoDependency(package, match.group(2), line_number, line.strip()))
    return dependencies


def discover_javascript_dependencies(content: str) -> list[CryptoDependency]:
    """Return declared JavaScript cryptography dependencies from package.json only."""
    try:
        manifest = json.loads(content)
    except json.JSONDecodeError:
        return []

    dependencies: list[CryptoDependency] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        entries = manifest.get(section, {})
        if not isinstance(entries, dict):
            continue
        for package, version in entries.items():
            normalized = str(package).lower()
            if normalized not in JAVASCRIPT_CRYPTO_PACKAGES:
                continue
            matcher = re.search(rf'"{re.escape(str(package))}"\s*:\s*"([^"]+)"', content)
            line = content.count("\n", 0, matcher.start()) + 1 if matcher else 1
            dependencies.append(CryptoDependency(
                package=normalized,
                version=str(version),
                line=line,
                evidence=f'"{package}": "{version}"',
            ))
    return dependencies
