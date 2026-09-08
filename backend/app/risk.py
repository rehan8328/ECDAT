from __future__ import annotations

from .models import CryptoAsset, RiskLevel


QUANTUM_CLASSIFICATIONS = {
    "RSA": "shor-broken",
    "DSA": "shor-broken",
    "ECDSA": "shor-broken",
    "ECDH": "shor-broken",
    "DIFFIE-HELLMAN": "shor-broken",
    "ECC": "shor-broken",
    "AES-128": "grover-weakened",
    "AES-256": "grover-weakened",
    "AES-CBC": "classical-review",
    "SHA-1": "classical-review",
    "MD5": "classical-broken",
    "RC4": "classical-broken",
    "3DES": "classical-broken",
    "DES": "classical-broken",
    "HARDCODED CRYPTOGRAPHIC KEY": "classical-broken",
    "SHA-256": "grover-weakened",
    "SHA-384": "pqc-ready",
    "SHA-512": "pqc-ready",
    "ML-KEM": "pqc-ready",
    "ML-DSA": "pqc-ready",
    "SLH-DSA": "pqc-ready",
}


def quantum_classification_for(algorithm: str) -> str:
    """Return the maintained quantum-readiness classification for an algorithm."""
    return QUANTUM_CLASSIFICATIONS.get(algorithm.upper(), "classical-review")


ASYMMETRIC_QUANTUM_VULNERABLE = {
    "RSA",
    "DSA",
    "ECDSA",
    "ECDH",
    "DIFFIE-HELLMAN",
    "ECC",
}

RECOMMENDATIONS = {
    "RSA": "Use ML-DSA for signatures or ML-KEM for key establishment; prefer a hybrid migration where compatibility is required.",
    "DSA": "Replace with ML-DSA for digital signatures.",
    "ECDSA": "Replace with ML-DSA or SLH-DSA for digital signatures.",
    "ECDH": "Migrate key establishment to ML-KEM, initially in a hybrid ECDH + ML-KEM deployment.",
    "DIFFIE-HELLMAN": "Migrate key establishment to ML-KEM, initially in a hybrid deployment.",
    "AES-128": "Use AES-256 where performance and compatibility allow stronger quantum security margin.",
    "AES-CBC": "Prefer authenticated encryption such as AES-256-GCM and confirm the key size before migration planning.",
    "SHA-1": "Replace SHA-1 with SHA-384 or SHA-512 for security-sensitive use cases.",
    "MD5": "Replace MD5 with SHA-384 or SHA-512; rotate any value whose integrity relied on MD5.",
    "RC4": "Remove RC4 and use TLS 1.3 or an authenticated cipher such as AES-256-GCM or ChaCha20-Poly1305.",
    "3DES": "Replace 3DES with AES-256-GCM and plan a compatibility test for stored or partner data.",
    "DES": "Replace DES with AES-256-GCM and rotate affected encryption keys.",
    "HARDCODED CRYPTOGRAPHIC KEY": "Move the key to an approved secrets manager, rotate the exposed value, and use envelope encryption with a managed KMS or HSM.",
}


def assess_risk(
    algorithm: str,
    data_lifetime_years: int,
    migration_time_years: int,
    expected_crqc_years: int,
    business_criticality: str = "medium",
) -> tuple[bool, bool, int, RiskLevel, str]:
    normalized = algorithm.upper()
    quantum_vulnerable = quantum_classification_for(normalized) == "shor-broken"
    mosca_at_risk = data_lifetime_years + migration_time_years > expected_crqc_years

    score = 10
    if quantum_vulnerable:
        score += 45
    elif normalized == "AES-128":
        score += 25
    elif normalized == "SHA-1":
        score += 40
    elif normalized == "MD5":
        score += 45
    elif normalized in {"RC4", "3DES", "DES"}:
        score += 50
    elif normalized == "HARDCODED CRYPTOGRAPHIC KEY":
        score += 55
    elif normalized == "AES-CBC":
        score += 30
    elif normalized in {"AES-256", "SHA-256"}:
        score += 5

    if mosca_at_risk:
        score += 25
    if data_lifetime_years >= 15:
        score += 10
    score += {"low": -10, "medium": 0, "high": 8, "mission_critical": 15}.get(business_criticality, 0)
    score = min(score, 100)

    if score >= 80:
        level = RiskLevel.CRITICAL
    elif score >= 60:
        level = RiskLevel.HIGH
    elif score >= 35:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW

    recommendation = RECOMMENDATIONS.get(
        normalized,
        "Retain the asset in the CBOM and review its context, lifetime, and migration path.",
    )
    return quantum_vulnerable, mosca_at_risk, score, level, recommendation


def quantum_readiness(assets: list[CryptoAsset]) -> int:
    total = max(len(assets), 1)
    quantum = sum(asset.quantum_vulnerable for asset in assets)
    critical = sum(asset.risk_level is RiskLevel.CRITICAL for asset in assets)
    high = sum(asset.risk_level is RiskLevel.HIGH for asset in assets)
    mosca = sum(asset.mosca_at_risk for asset in assets)
    return max(0, round(100 - quantum / total * 45 - critical / total * 25 - high / total * 10 - mosca / total * 20))


def simulate_remediation(asset: CryptoAsset) -> CryptoAsset:
    """Project the post-remediation risk without modifying the source or persisted finding."""
    residual_score = max(0, min(100, 10 + {"low": -10, "medium": 0, "high": 8, "mission_critical": 15}.get(asset.business_criticality, 0)))
    if residual_score >= 80:
        level = RiskLevel.CRITICAL
    elif residual_score >= 60:
        level = RiskLevel.HIGH
    elif residual_score >= 35:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW
    return asset.model_copy(update={
        "risk_score": residual_score,
        "risk_level": level,
        "quantum_vulnerable": False,
        "mosca_at_risk": False,
    })
