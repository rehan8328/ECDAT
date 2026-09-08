from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ConfigurationFinding:
    asset_type: str
    algorithm: str
    protocol: str | None
    library: str | None
    line: int
    evidence: str
    risk_score: int
    risk_level: str
    recommendation: str


TLS_VERSION = re.compile(r"\bTLSv?1\.(0|1|2|3)\b", re.IGNORECASE)
CIPHER_SUITE = re.compile(r"\bTLS_[A-Z0-9_]+\b")
PROVIDER = re.compile(r"\b(OpenSSL|Bouncy\s*Castle|libsodium)\b", re.IGNORECASE)


def discover_configuration(content: str) -> list[ConfigurationFinding]:
    findings: list[ConfigurationFinding] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        version = TLS_VERSION.search(line)
        if version:
            minor = version.group(1)
            legacy = minor in {"0", "1"}
            findings.append(
                ConfigurationFinding(
                    asset_type="tls_configuration", algorithm=f"TLS 1.{minor}", protocol="TLS", library=None,
                    line=line_number, evidence=line.strip(), risk_score=75 if legacy else 30,
                    risk_level="high" if legacy else "medium",
                    recommendation=(
                        "Disable TLS 1.0 and 1.1; require TLS 1.2 or TLS 1.3."
                        if legacy else "Prefer TLS 1.3 where supported and keep certificate and cipher policy under review."
                    ),
                )
            )
        cipher = CIPHER_SUITE.search(line)
        if cipher:
            findings.append(
                ConfigurationFinding(
                    asset_type="cipher_suite", algorithm=cipher.group(0), protocol="TLS", library=None,
                    line=line_number, evidence=line.strip(), risk_score=35, risk_level="medium",
                    recommendation="Review this suite with the deployed certificate and protocol policy; prefer TLS 1.3 suites where possible.",
                )
            )
        provider = PROVIDER.search(line)
        if provider:
            findings.append(
                ConfigurationFinding(
                    asset_type="crypto_provider", algorithm=provider.group(1), protocol=None,
                    library=provider.group(1), line=line_number, evidence=line.strip(), risk_score=10,
                    risk_level="low", recommendation="Track provider version and supported cryptographic policy in the CBOM.",
                )
            )
    return findings
