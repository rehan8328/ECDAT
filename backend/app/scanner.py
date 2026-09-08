from __future__ import annotations

import re
import os
from dataclasses import dataclass
from pathlib import Path

from .certificates import parse_pem_certificate
from .agility import enrich_crypto_agility
from .configuration import discover_configuration
from .containers import discover_container_references
from .dependencies import discover_javascript_dependencies, discover_python_dependencies
from .models import CryptoAsset
from .risk import assess_risk, quantum_classification_for


TEXT_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".java", ".c", ".cpp", ".h", ".go", ".json", ".yml", ".yaml", ".toml", ".txt", ".pem", ".crt", ".cer"}
SKIP_DIRECTORIES = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "dist", "build", "coverage", "__pycache__", ".pytest_cache", ".pytest-run", ".mypy_cache", ".ruff_cache", ".tox", ".ppt-build", ".npm-cache", ".cache", ".next", ".nuxt", "vendor", "target", "outputs", "tests", "test", "fixtures", "examples", "docs"}
MAX_TEXT_FILE_BYTES = 1_000_000


@dataclass(frozen=True)
class DetectionRule:
    algorithm: str
    asset_type: str
    pattern: re.Pattern[str]
    key_size_group: int | None = None
    mode: str | None = None
    library: str | None = None
    protocol: str | None = None
    confidence: int = 85


RULES = (
    DetectionRule("RSA", "asymmetric_algorithm", re.compile(r"rsa\.generate_private_key.*?(?:key_size\s*=\s*)?(1024|2048|3072|4096)", re.IGNORECASE | re.DOTALL), 1),
    DetectionRule("ECDSA", "asymmetric_algorithm", re.compile(r"\bECDSA\b|ec\.SECP(256|384|521)", re.IGNORECASE), 1),
    DetectionRule("ECDH", "asymmetric_algorithm", re.compile(r"\bECDH\b", re.IGNORECASE)),
    DetectionRule("AES-128", "symmetric_algorithm", re.compile(r"\bAES[-_ ]?128\b(?![-_ ]?(?:GCM|CBC))", re.IGNORECASE)),
    DetectionRule("AES-256", "symmetric_algorithm", re.compile(r"\bAES[-_ ]?256[-_ ]?GCM\b", re.IGNORECASE), mode="GCM", confidence=95),
    DetectionRule("AES-256", "symmetric_algorithm", re.compile(r"\bAES[-_ ]?256[-_ ]?CBC\b", re.IGNORECASE), mode="CBC", confidence=95),
    DetectionRule("AES-256", "symmetric_algorithm", re.compile(r"\bAES[-_ ]?256\b(?![-_ ]?(?:GCM|CBC))", re.IGNORECASE)),
    DetectionRule("AES-CBC", "symmetric_algorithm", re.compile(r"\bAES[-_ ]?CBC\b", re.IGNORECASE), mode="CBC", confidence=90),
    DetectionRule("SHA-1", "hash_algorithm", re.compile(r"\b(?:SHA[-_ ]?1|sha1)\b", re.IGNORECASE)),
    DetectionRule("MD5", "hash_algorithm", re.compile(r"\bmd5\b", re.IGNORECASE)),
    DetectionRule("SHA-256", "hash_algorithm", re.compile(r"\b(?:SHA[-_ ]?256|sha256)\b", re.IGNORECASE)),
    DetectionRule("RC4", "symmetric_algorithm", re.compile(r"\b(?:ARC4|RC4)\b", re.IGNORECASE)),
    DetectionRule("3DES", "symmetric_algorithm", re.compile(r"\b(?:3DES|TripleDES|DESede)\b", re.IGNORECASE)),
    DetectionRule("DES", "symmetric_algorithm", re.compile(r"\bDES\b", re.IGNORECASE)),
    DetectionRule("Hardcoded cryptographic key", "key_material", re.compile(r"\b(?:encryption|secret|private|api)_key\s*=\s*[\"'][^\"'\r\n]{8,}[\"']", re.IGNORECASE), confidence=90),
    DetectionRule("OpenSSL", "crypto_library", re.compile(r"\bOpenSSL\b", re.IGNORECASE)),
    DetectionRule("TLS", "protocol", re.compile(r"\bTLSv?1\.[23]\b", re.IGNORECASE), confidence=95),
    DetectionRule("RSA", "asymmetric_algorithm", re.compile(r"\bgenerateKeyPair(?:Sync)?\s*\(\s*['\"]rsa['\"]", re.IGNORECASE), confidence=95),
    DetectionRule("ECDSA", "asymmetric_algorithm", re.compile(r"\bgenerateKeyPair(?:Sync)?\s*\(\s*['\"](?:ec|ecdsa)['\"]", re.IGNORECASE), confidence=95),
    DetectionRule("DIFFIE-HELLMAN", "asymmetric_algorithm", re.compile(r"\bcreateDiffieHellman(?:Group)?\s*\(", re.IGNORECASE), confidence=95),
    DetectionRule("AES-128", "symmetric_algorithm", re.compile(r"\bcreateCipheriv\s*\(\s*['\"]aes-128-gcm['\"]", re.IGNORECASE), mode="GCM", confidence=95),
    DetectionRule("AES-128", "symmetric_algorithm", re.compile(r"\bcreateCipheriv\s*\(\s*['\"]aes-128-cbc['\"]", re.IGNORECASE), mode="CBC", confidence=95),
    DetectionRule("AES-256", "symmetric_algorithm", re.compile(r"\bcreateCipheriv\s*\(\s*['\"]aes-256-gcm['\"]", re.IGNORECASE), mode="GCM", confidence=95),
    DetectionRule("AES-256", "symmetric_algorithm", re.compile(r"\bcreateCipheriv\s*\(\s*['\"]aes-256-cbc['\"]", re.IGNORECASE), mode="CBC", confidence=95),
    DetectionRule("AES-256", "symmetric_algorithm", re.compile(r"\bcreateCipheriv\s*\(\s*['\"]aes-256-ctr['\"]", re.IGNORECASE), mode="CTR", confidence=95),
    DetectionRule("TLS", "protocol", re.compile(r"\b(?:https|tls)\.createServer\s*\(", re.IGNORECASE), protocol="TLS", confidence=95),
    DetectionRule("OpenSSL", "crypto_library", re.compile(r"\b(?:OpenSSL|crypto\.createCipheriv)\b", re.IGNORECASE), library="OpenSSL", confidence=90),
    DetectionRule("PyCryptodome", "crypto_library", re.compile(r"\b(?:Crypto\.Cipher|Cryptodome\.)\b"), library="PyCryptodome", confidence=95),
    DetectionRule("Bouncy Castle", "crypto_library", re.compile(r"\b(?:org\.bouncycastle|BouncyCastleProvider)\b"), library="Bouncy Castle", confidence=95),
    DetectionRule("libsodium", "crypto_library", re.compile(r"\b(?:libsodium|sodium_init|crypto_box)\b", re.IGNORECASE), library="libsodium", confidence=90),
    DetectionRule("RSA", "asymmetric_algorithm", re.compile(r"\bKeyPairGenerator\.getInstance\s*\(\s*[\"']RSA[\"']\s*\)", re.IGNORECASE), confidence=95),
    DetectionRule("ECDSA", "asymmetric_algorithm", re.compile(r"\bKeyPairGenerator\.getInstance\s*\(\s*[\"'](?:EC|ECDSA)[\"']\s*\)", re.IGNORECASE), confidence=95),
    DetectionRule("DIFFIE-HELLMAN", "asymmetric_algorithm", re.compile(r"\bKeyAgreement\.getInstance\s*\(\s*[\"'](?:DH|DiffieHellman)[\"']\s*\)", re.IGNORECASE), confidence=95),
    DetectionRule("AES-128", "symmetric_algorithm", re.compile(r"\bCipher\.getInstance\s*\(\s*[\"']AES(?:/GCM|/CBC)?[\"']\s*\)", re.IGNORECASE), confidence=90),
    DetectionRule("AES-256", "symmetric_algorithm", re.compile(r"\bAES_?256\b", re.IGNORECASE), confidence=85),
    DetectionRule("SHA-256", "hash_algorithm", re.compile(r"\bMessageDigest\.getInstance\s*\(\s*[\"']SHA-?256[\"']\s*\)", re.IGNORECASE), confidence=95),
    DetectionRule("SHA-1", "hash_algorithm", re.compile(r"\bMessageDigest\.getInstance\s*\(\s*[\"']SHA-?1[\"']\s*\)", re.IGNORECASE), confidence=95),
    DetectionRule("TLS", "protocol", re.compile(r"\bSSLContext\.getInstance\s*\(\s*[\"']TLS(?:v?1\.[23])?[\"']\s*\)", re.IGNORECASE), protocol="TLS", confidence=95),
)


def _line_number(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


CONTEXTUAL_PYTHON_ALGORITHMS = {"AES-128", "AES-256", "AES-CBC", "SHA-1", "SHA-256", "MD5", "RC4", "3DES", "DES", "ECDSA", "ECDH", "OpenSSL", "PyCryptodome", "Bouncy Castle", "libsodium"}


def _is_contextual_python_usage(content: str, match: re.Match[str], algorithm: str) -> bool:
    """Reject prose, policy tables, and test labels that merely name an algorithm."""
    if algorithm not in CONTEXTUAL_PYTHON_ALGORITHMS:
        return True
    line_start = content.rfind("\n", 0, match.start()) + 1
    line_end = content.find("\n", match.end())
    line = content[line_start:None if line_end == -1 else line_end].strip()
    prefix = content[line_start:match.start()]
    if line.startswith("#"):
        return False
    has_crypto_assignment = bool(re.search(r"\b(?:\w+_)?(?:algorithm|cipher|hash|digest|key|tls|ssl)\s*=(?!=)[^=]*$", prefix, re.IGNORECASE))
    has_crypto_call = bool(re.search(r"\b(?:hashlib\.(?:md5|sha\d+)|AES\.new|Cipher\s*\(|ec\.SECP\d+|ec\.ECDSA\s*\(|ssl\.SSLContext\s*\()", line))
    return has_crypto_assignment or has_crypto_call or line.casefold() == algorithm.casefold()


def scan_directory(
    directory: Path,
    data_lifetime_years: int = 10,
    migration_time_years: int = 3,
    expected_crqc_years: int = 10,
    business_criticality: str = "medium",
) -> tuple[int, list[CryptoAsset]]:
    if not directory.is_dir():
        raise ValueError(f"Scan path is not a directory: {directory}")

    assets: list[CryptoAsset] = []
    files_scanned = 0
    candidate_files: list[Path] = []
    for root, directories, filenames in os.walk(directory):
        directories[:] = [
            name for name in directories
            if name not in SKIP_DIRECTORIES and not name.startswith(("test-tmp", "test_"))
        ]
        root_path = Path(root)
        candidate_files.extend(root_path / name for name in filenames)

    for file_path in sorted(candidate_files):
        is_dockerfile = file_path.name.lower() == "dockerfile" or file_path.suffix.lower() == ".dockerfile"
        if (file_path.suffix.lower() not in TEXT_EXTENSIONS and not is_dockerfile) or file_path.stat().st_size > MAX_TEXT_FILE_BYTES:
            continue
        files_scanned += 1
        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        relative_path = str(file_path.relative_to(directory)).replace("\\", "/")
        for rule in RULES:
            if file_path.suffix.lower() in {".yml", ".yaml", ".json", ".toml", ".conf"} and rule.algorithm in {"OpenSSL", "TLS"}:
                continue
            for match in rule.pattern.finditer(content):
                if file_path.suffix.lower() in {".py", ".js", ".ts", ".tsx"} and not _is_contextual_python_usage(content, match, rule.algorithm):
                    continue
                key_size = int(match.group(rule.key_size_group)) if rule.key_size_group and match.lastindex else None
                quantum_vulnerable, mosca_at_risk, score, level, recommendation = assess_risk(
                    rule.algorithm,
                    data_lifetime_years,
                    migration_time_years,
                    expected_crqc_years,
                    business_criticality,
                )
                line = _line_number(content, match.start())
                evidence = content.splitlines()[line - 1].strip()
                assets.append(
                    CryptoAsset(
                        asset_id=f"CRYPTO-{len(assets) + 1:05d}",
                        asset_type=rule.asset_type,
                        algorithm=rule.algorithm,
                        key_size=key_size,
                        mode=rule.mode,
                        library=rule.library,
                        protocol=rule.protocol,
                        confidence=rule.confidence,
                        location=relative_path,
                        line=line,
                        evidence=evidence[:240],
                        quantum_vulnerable=quantum_vulnerable,
                        quantum_classification=quantum_classification_for(rule.algorithm),
                        risk_score=score,
                        risk_level=level,
                        mosca_at_risk=mosca_at_risk,
                        business_criticality=business_criticality,
                        recommendation=recommendation,
                    )
                )
        if file_path.name.lower() == "requirements.txt":
            for dependency in discover_python_dependencies(content):
                assets.append(
                    CryptoAsset(
                        asset_id=f"CRYPTO-{len(assets) + 1:05d}",
                        asset_type="crypto_dependency",
                        algorithm=dependency.package,
                        library=dependency.package,
                        version=dependency.version,
                        confidence=100,
                        location=relative_path,
                        line=dependency.line,
                        evidence=dependency.evidence[:240],
                        quantum_vulnerable=False,
                        risk_score=10,
                        risk_level="low",
                        mosca_at_risk=False,
                        recommendation="Track this cryptographic dependency in the CBOM and review its supported version policy.",
                    )
                )
        if file_path.name.lower() == "package.json":
            for dependency in discover_javascript_dependencies(content):
                assets.append(
                    CryptoAsset(
                        asset_id=f"CRYPTO-{len(assets) + 1:05d}",
                        asset_type="crypto_dependency",
                        algorithm=dependency.package,
                        library=dependency.package,
                        version=dependency.version,
                        confidence=100,
                        location=relative_path,
                        line=dependency.line,
                        evidence=dependency.evidence[:240],
                        quantum_vulnerable=False,
                        risk_score=10,
                        risk_level="low",
                        mosca_at_risk=False,
                        recommendation="Track this cryptographic dependency in the CBOM and review its supported version policy.",
                    )
                )
        certificate = parse_pem_certificate(content)
        if certificate is not None:
            assets.append(
                CryptoAsset(
                    asset_id=f"CRYPTO-{len(assets) + 1:05d}", asset_type="certificate",
                    algorithm="X.509 certificate", confidence=100, location=relative_path, line=1,
                    evidence="PEM certificate block", quantum_vulnerable=False, risk_score=10,
                    risk_level="low", mosca_at_risk=False,
                    certificate_subject=certificate.subject, certificate_issuer=certificate.issuer,
                    certificate_expires_at=certificate.expires_at,
                    recommendation="Track certificate lifecycle and validate its public-key algorithm and expiry policy.",
                )
            )
        if file_path.suffix.lower() in {".yml", ".yaml", ".json", ".toml", ".conf"}:
            for finding in discover_configuration(content):
                assets.append(
                    CryptoAsset(
                        asset_id=f"CRYPTO-{len(assets) + 1:05d}", asset_type=finding.asset_type,
                        algorithm=finding.algorithm, protocol=finding.protocol, library=finding.library,
                        confidence=90, location=relative_path, line=finding.line, evidence=finding.evidence[:240],
                        quantum_vulnerable=False, risk_score=finding.risk_score, risk_level=finding.risk_level,
                        mosca_at_risk=False, recommendation=finding.recommendation,
                    )
                )
        if is_dockerfile or file_path.suffix.lower() in {".yml", ".yaml"}:
            for reference in discover_container_references(content, is_dockerfile=is_dockerfile):
                assets.append(
                    CryptoAsset(
                        asset_id=f"CRYPTO-{len(assets) + 1:05d}", asset_type="container_image_reference",
                        algorithm="Container image", library=reference.image, confidence=100,
                        location=relative_path, line=reference.line, evidence=reference.evidence[:240],
                        quantum_vulnerable=False, risk_score=10, risk_level="low", mosca_at_risk=False,
                        recommendation="Record this deployment image in the CBOM and inspect its packaged cryptographic libraries with a container-image adapter.",
                    )
                )
    return files_scanned, enrich_crypto_agility(directory, assets)
