from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ContainerReference:
    image: str
    line: int
    evidence: str


_DOCKERFILE_FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?([^\s#]+)", re.IGNORECASE)
_MANIFEST_IMAGE = re.compile(r"^\s*image\s*:\s*[\"']?([^\s\"'#]+)", re.IGNORECASE)


def discover_container_references(content: str, is_dockerfile: bool = False) -> list[ContainerReference]:
    """Extract declared image references only; no container image content is executed or pulled."""
    pattern = _DOCKERFILE_FROM if is_dockerfile else _MANIFEST_IMAGE
    references: list[ContainerReference] = []
    for number, line in enumerate(content.splitlines(), start=1):
        match = pattern.match(line)
        if match:
            references.append(ContainerReference(image=match.group(1), line=number, evidence=line.strip()))
    return references
