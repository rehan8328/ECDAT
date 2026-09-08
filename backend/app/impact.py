from __future__ import annotations

from pathlib import Path

from .models import CryptoAsset, ImpactAnalysis
from .static_analysis import build_python_call_graph, containing_function, trace_to_entry_points


def _standards(asset: CryptoAsset) -> list[str]:
    if asset.algorithm in {"RSA", "ECDH"}:
        return ["NIST FIPS 203 (ML-KEM)"]
    if asset.algorithm in {"ECDSA", "DSA"}:
        return ["NIST FIPS 204 (ML-DSA)", "NIST FIPS 205 (SLH-DSA)"]
    if asset.algorithm == "Hardcoded cryptographic key":
        return ["NIST SP 800-57 (key management)"]
    return ["NIST SP 800-131A Rev. 2 (transition guidance)"]


def analyze_impact(asset: CryptoAsset, scanned_path: Path, assets: list[CryptoAsset]) -> ImpactAnalysis:
    graph = build_python_call_graph(scanned_path)
    start = containing_function(graph, asset.location, asset.line)
    paths = trace_to_entry_points(graph, start) if start else []
    entry_nodes = [graph.nodes[path[-1]] for path in paths]
    call_chains = [[graph.nodes[node_id].display for node_id in path] for path in paths]
    services = sorted({node.entry_label for node in entry_nodes if node.entry_label})
    applications = sorted({node.path for node in entry_nodes})
    public_facing = bool(entry_nodes)
    exposure = "public-facing" if public_facing else "Internal / no direct external exposure found"
    business_units = ["Unclassified - ownership integration required"]
    data_sensitivity = "long-lived sensitive data" if asset.business_criticality in {"high", "mission_critical"} else "classification required"

    hndl_score = 0
    if asset.quantum_vulnerable:
        hndl_score += 45
    if asset.mosca_at_risk:
        hndl_score += 25
    if public_facing:
        hndl_score += 10
    if asset.business_criticality in {"high", "mission_critical"}:
        hndl_score += 15
    hndl_score = min(hndl_score, 100)

    certificates = sum(item.asset_type == "certificate" for item in assets)
    if asset.asset_type == "key_material" or (asset.quantum_vulnerable and public_facing and certificates):
        difficulty = "High"
    elif asset.quantum_vulnerable or asset.algorithm in {"RC4", "3DES", "DES", "AES-CBC"}:
        difficulty = "Medium"
    else:
        difficulty = "Low"
    migration_factors = [
        f"Exposure: {exposure}",
        "Mosca horizon exceeded" if asset.mosca_at_risk else "Within configured Mosca horizon",
    ]
    if asset.quantum_vulnerable:
        migration_factors.append("Protocol and library compatibility required for PQC/hybrid rollout")
    if certificates:
        migration_factors.append(f"{certificates} certificate asset(s) discovered in this scan")
    if not start:
        migration_factors.append("Finding is at module scope or outside a parsed Python function")
    elif not paths:
        migration_factors.append("No route, CLI, or detected entry point reaches this function within 6 call hops")

    return ImpactAnalysis(
        asset_id=asset.asset_id,
        source="read_only_python_call_graph",
        rationale="Impact is derived from parsed Python function calls and detected route or CLI entry points. It does not infer ownership from file-name keywords; confirm runtime reachability with telemetry before production change.",
        business_units=business_units,
        applications=applications or [asset.location],
        services=services or ["Internal / no direct external exposure found"],
        dependencies=[],
        certificates=certificates,
        migration_difficulty=difficulty,
        exposure=exposure,
        data_sensitivity=data_sensitivity,
        hndl_score=hndl_score,
        migration_factors=migration_factors,
        standards=_standards(asset),
        containing_function=graph.nodes[start].display if start else None,
        call_chains=call_chains,
    )
