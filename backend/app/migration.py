from __future__ import annotations

from .models import CryptoAsset, MigrationTask, RiskLevel


TARGETS = {
    "RSA": "Classify signature vs. key establishment, then pilot ML-DSA or ML-KEM in a hybrid deployment.",
    "ECDSA": "Pilot ML-DSA or SLH-DSA for signatures with compatibility testing.",
    "ECDH": "Pilot hybrid ECDH + ML-KEM key establishment.",
    "AES-128": "Upgrade to AES-256 after compatibility and performance review.",
    "AES-CBC": "Replace with authenticated encryption, preferably AES-256-GCM.",
    "SHA-1": "Replace with SHA-384 or SHA-512 and retire legacy verification paths.",
    "MD5": "Replace with SHA-384 or SHA-512, then regenerate integrity values and retire MD5 validation paths.",
    "RC4": "Disable RC4 and move the service to TLS 1.3 or AES-256-GCM / ChaCha20-Poly1305.",
    "3DES": "Move encrypted data to AES-256-GCM and rotate the encryption keys.",
    "DES": "Move encrypted data to AES-256-GCM and rotate the encryption keys.",
    "Hardcoded cryptographic key": "Move the secret to the approved vault, rotate it, and use a managed KMS or HSM for key lifecycle.",
}

PRIORITIES = {
    RiskLevel.CRITICAL: ("P0", "0-30 days"),
    RiskLevel.HIGH: ("P1", "30-90 days"),
    RiskLevel.MEDIUM: ("P2", "90-180 days"),
    RiskLevel.LOW: ("P3", "Backlog"),
}

DECISION_SUPPORT = {
    "RSA": ("ML-KEM or ML-DSA, based on use", "RSA + ML-KEM/ML-DSA during interoperability rollout", "Hybrid reduces compatibility risk but adds handshake size and latency.", "Large", ["Classify encryption vs signature use", "Reissue certificates where RSA is used in TLS", "Confirm HSM and client-library support"]),
    "ECDSA": ("ML-DSA or SLH-DSA", "ECDSA + ML-DSA during verifier migration", "Hybrid signatures increase payload size; pure PQC requires verifier support.", "Medium", ["Identify signing clients and verifiers", "Validate certificate-chain compatibility"]),
    "ECDH": ("ML-KEM", "ECDH + ML-KEM hybrid key establishment", "Hybrid protects long-lived secrets while maintaining older peer compatibility.", "Large", ["Confirm TLS/library support", "Test partner and mobile-client compatibility"]),
    "AES-128": ("AES-256-GCM", "AES-256-GCM with staged key rotation", "AES-256 has a modest performance cost and stronger Grover security margin.", "Medium", ["Rotate keys", "Benchmark critical data paths"]),
    "AES-CBC": ("AES-256-GCM", "Dual-read migration from CBC to GCM", "Authenticated encryption changes payload handling and requires compatibility testing.", "Medium", ["Plan data re-encryption", "Validate IV and authentication-tag handling"]),
    "SHA-1": ("SHA-384 or SHA-512", "Accept both old and new digest during transition", "Dual verification helps rollout but must have a fixed retirement date.", "Small", ["Regenerate integrity values", "Retire legacy validation paths"]),
    "MD5": ("SHA-384 or SHA-512", "Dual verification only for a time-boxed migration", "MD5 should be removed promptly; hybrid verification is temporary only.", "Small", ["Regenerate hashes", "Rotate trust decisions based on MD5"]),
}


def build_migration_plan(assets: list[CryptoAsset]) -> list[MigrationTask]:
    tasks = []
    for asset in sorted(assets, key=lambda item: (-item.risk_score, item.asset_id)):
        priority, planning_window = PRIORITIES[asset.risk_level]
        pure_pqc, hybrid, tradeoffs, effort, dependencies = DECISION_SUPPORT.get(
            asset.algorithm,
            ("Retain and review", "Stage compatibility validation", "Validate lifecycle, support policy, and operational impact.", "Small", ["Confirm owner", "Review deployment dependencies"]),
        )
        tasks.append(
            MigrationTask(
                asset_id=asset.asset_id,
                algorithm=asset.algorithm,
                priority=priority,
                status="Detected",
                planning_window=planning_window,
                owner="Unassigned",
                target=TARGETS.get(asset.algorithm, "Retain in CBOM and validate lifecycle, ownership, and crypto agility."),
                rationale=asset.recommendation,
                estimated_effort=effort,
                dependency_notes=dependencies,
                pure_pqc_option=pure_pqc,
                hybrid_option=hybrid,
                tradeoffs=tradeoffs,
            )
        )
    return tasks
