from __future__ import annotations

import ssl
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CertificateMetadata:
    subject: str | None
    issuer: str | None
    expires_at: str | None


def parse_pem_certificate(content: str) -> CertificateMetadata | None:
    """Parse public certificate metadata only; private key blocks are rejected."""
    if "-----BEGIN CERTIFICATE-----" not in content or "PRIVATE KEY" in content:
        return None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", encoding="utf-8") as pem_file:
            pem_file.write(content)
            pem_file.flush()
            decoded = ssl._ssl._test_decode_cert(pem_file.name)
    except (OSError, ssl.SSLError, ValueError):
        return CertificateMetadata(subject=None, issuer=None, expires_at=None)
    return CertificateMetadata(
        subject=_format_name(decoded.get("subject", ())),
        issuer=_format_name(decoded.get("issuer", ())),
        expires_at=decoded.get("notAfter"),
    )


def _format_name(name: tuple[tuple[tuple[str, str], ...], ...]) -> str | None:
    items = [f"{key}={value}" for group in name for key, value in group]
    return ", ".join(items) if items else None
