from __future__ import annotations

from typing import Any
from uuid import uuid4

from .models import CryptoAsset, ScanResult


def generate_cyclonedx_cbom(scan: ScanResult) -> dict[str, Any]:
    """Generate a standard-compliant CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)."""
    components = [_map_asset_to_cyclonedx(asset) for asset in scan.assets]

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": scan.created_at.isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "ECDAT",
                        "version": "0.1.0",
                        "description": "Enterprise Cryptographic Discovery & Analysis Tool",
                        "supplier": {
                            "name": "Team CipherX",
                        },
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": "ECDAT-Audit-Target",
                "description": f"Cryptographic inventory target: {scan.scanned_path}",
            },
        },
        "components": components,
    }


def _map_asset_to_cyclonedx(asset: CryptoAsset) -> dict[str, Any]:
    asset_type = asset.asset_type
    crypto_props: dict[str, Any] = {}

    if asset_type in {"asymmetric_algorithm", "symmetric_algorithm", "hash_algorithm"}:
        crypto_props["assetType"] = "algorithm"
        algo_props: dict[str, Any] = {
            "executionEnvironment": "software-plain-ram",
            "implementationPlatform": "generic",
        }
        if asset_type == "asymmetric_algorithm":
            algo_props["primitive"] = "signature" if asset.algorithm in {"ECDSA", "DSA"} else "pke"
        elif asset_type == "symmetric_algorithm":
            algo_props["primitive"] = "ae" if asset.mode == "GCM" else "block-cipher"
        elif asset_type == "hash_algorithm":
            algo_props["primitive"] = "hash"

        if asset.key_size:
            algo_props["parameterSetIdentifier"] = str(asset.key_size)
        if asset.mode:
            algo_props["mode"] = asset.mode

        if asset.quantum_vulnerable:
            algo_props["nistQuantumSecurityLevel"] = 0
        elif asset.algorithm in {"AES-256", "SHA-256", "SHA-384", "SHA-512"}:
            algo_props["nistQuantumSecurityLevel"] = 5
        elif asset.algorithm == "AES-128":
            algo_props["nistQuantumSecurityLevel"] = 1

        crypto_props["algorithmProperties"] = algo_props

    elif asset_type == "certificate":
        crypto_props["assetType"] = "certificate"
        cert_props: dict[str, Any] = {"certificateFormat": "X.509"}
        if asset.certificate_subject:
            cert_props["subjectName"] = asset.certificate_subject
        if asset.certificate_issuer:
            cert_props["issuerName"] = asset.certificate_issuer
        if asset.certificate_expires_at:
            cert_props["notValidAfter"] = asset.certificate_expires_at
        crypto_props["certificateProperties"] = cert_props

    elif asset_type in {"protocol", "tls_configuration", "cipher_suite"}:
        crypto_props["assetType"] = "protocol"
        proto_props: dict[str, Any] = {
            "type": "tls",
            "version": asset.protocol or asset.algorithm,
        }
        if asset_type == "cipher_suite":
            proto_props["cipherSuites"] = [{"name": asset.algorithm}]
        crypto_props["protocolProperties"] = proto_props

    elif asset_type == "key_material":
        crypto_props["assetType"] = "related-crypto-material"
        crypto_props["relatedCryptoMaterialProperties"] = {
            "type": "secret-key",
            "state": "active",
        }

    elif asset_type == "crypto_dependency":
        crypto_props["assetType"] = "algorithm"
        crypto_props["algorithmProperties"] = {
            "primitive": "library-provider",
            "executionEnvironment": "software-plain-ram",
        }

    elif asset_type == "container_image_reference":
        crypto_props["assetType"] = "protocol"
        crypto_props["protocolProperties"] = {
            "type": "container-runtime",
            "version": asset.library or "unknown",
        }

    else:
        crypto_props["assetType"] = "algorithm"

    risk_str = asset.risk_level.value if hasattr(asset.risk_level, "value") else str(asset.risk_level)

    return {
        "type": "cryptographic-asset",
        "bom-ref": asset.asset_id,
        "name": asset.algorithm,
        "version": asset.version or "1.0",
        "cryptoProperties": crypto_props,
        "evidence": {
            "occurrences": [
                {
                    "location": f"{asset.location}#L{asset.line}" if asset.line else asset.location,
                    "line": asset.line,
                }
            ]
        },
        "properties": [
            {"name": "ecdat:riskScore", "value": str(asset.risk_score)},
            {"name": "ecdat:riskLevel", "value": risk_str},
            {"name": "ecdat:quantumVulnerable", "value": "true" if asset.quantum_vulnerable else "false"},
            {"name": "ecdat:quantumClassification", "value": asset.quantum_classification},
            {"name": "ecdat:moscaAtRisk", "value": "true" if asset.mosca_at_risk else "false"},
            {"name": "ecdat:businessCriticality", "value": str(asset.business_criticality or "medium")},
            {"name": "ecdat:recommendation", "value": str(asset.recommendation)},
            {"name": "ecdat:confidence", "value": f"{asset.confidence}%"},
        ],
    }
