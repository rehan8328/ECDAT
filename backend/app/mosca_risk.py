"""Mosca Risk Engine – Full implementation of Mosca's theorem for quantum risk assessment.

Mosca's theorem states: If x + y > z, start preparing now.
  x = data shelf-life (how long data must remain confidential)
  y = migration time (time needed to fully migrate the crypto)
  z = time until a cryptographically relevant quantum computer (CRQC)

This module computes granular Mosca risk metrics for each CryptoAsset and
provides an overall enterprise-level Mosca assessment.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone

from .models import CryptoAsset, RiskLevel


@dataclass(frozen=True)
class MoscaMetrics:
    """Result of a Mosca risk evaluation for a single asset."""
    data_lifetime_years: float
    migration_time_years: float
    quantum_arrival_years: float
    mosca_sum: float        # x + y
    mosca_deficit: float    # (x + y) - z — positive means at risk
    at_risk: bool
    urgency: str            # "immediate", "near-term", "monitor", "safe"
    risk_multiplier: float  # Used to adjust the base risk score


# Default estimates based on NIST and industry guidance
DEFAULT_QUANTUM_YEAR = 2035  # Conservative CRQC estimate
DEFAULT_MIGRATION_TIME = {
    "asymmetric_algorithm": 5,
    "symmetric_algorithm": 2,
    "hash_algorithm": 2,
    "certificate": 3,
    "protocol": 4,
    "tls_configuration": 3,
    "cipher_suite": 3,
    "crypto_library": 4,
    "crypto_provider": 3,
    "key_material": 3,
    "crypto_dependency": 3,
    "container_image_reference": 2,
}

DEFAULT_DATA_LIFETIME = {
    "low": 5,
    "medium": 10,
    "high": 15,
    "mission_critical": 20,
}


def compute_mosca_risk(
    asset: CryptoAsset,
    quantum_year: int = DEFAULT_QUANTUM_YEAR,
    current_year: int | None = None,
) -> MoscaMetrics:
    """Compute full Mosca risk metrics for a single CryptoAsset.

    Parameters
    ----------
    asset : CryptoAsset
        The cryptographic asset to evaluate.
    quantum_year : int
        Projected year when CRQC becomes available.
    current_year : int | None
        Override for the current year (defaults to the actual year).
    """
    if current_year is None:
        current_year = datetime.now(timezone.utc).year

    # z = years until CRQC
    z = max(quantum_year - current_year, 0)

    # x = data lifetime in years
    if asset.lifetime_days is not None:
        x = asset.lifetime_days / 365.25
    else:
        x = float(DEFAULT_DATA_LIFETIME.get(asset.business_criticality, 10))

    # If certificate has an expiry date, compute remaining lifetime
    if asset.expiry_date:
        try:
            expiry = datetime.fromisoformat(asset.expiry_date.replace("Z", "+00:00"))
            remaining = (expiry - datetime.now(timezone.utc)).days / 365.25
            x = max(remaining, x)
        except (ValueError, TypeError):
            pass

    # y = migration time in years
    y = float(DEFAULT_MIGRATION_TIME.get(asset.asset_type, 3))

    mosca_sum = x + y
    mosca_deficit = mosca_sum - z
    at_risk = mosca_deficit > 0

    # Urgency classification
    if mosca_deficit > 5:
        urgency = "immediate"
        risk_multiplier = 1.5
    elif mosca_deficit > 2:
        urgency = "near-term"
        risk_multiplier = 1.25
    elif mosca_deficit > 0:
        urgency = "monitor"
        risk_multiplier = 1.1
    else:
        urgency = "safe"
        risk_multiplier = 1.0

    return MoscaMetrics(
        data_lifetime_years=round(x, 1),
        migration_time_years=round(y, 1),
        quantum_arrival_years=round(z, 1),
        mosca_sum=round(mosca_sum, 1),
        mosca_deficit=round(mosca_deficit, 1),
        at_risk=at_risk,
        urgency=urgency,
        risk_multiplier=risk_multiplier,
    )


def apply_mosca_adjustment(asset: CryptoAsset, quantum_year: int = DEFAULT_QUANTUM_YEAR) -> CryptoAsset:
    """Recalculate an asset's risk score by factoring in full Mosca analysis.

    Returns a copy of the asset with updated risk_score, risk_level, and mosca_at_risk.
    """
    metrics = compute_mosca_risk(asset, quantum_year)

    adjusted_score = min(100, math.ceil(asset.risk_score * metrics.risk_multiplier))

    if adjusted_score >= 80:
        level = RiskLevel.CRITICAL
    elif adjusted_score >= 60:
        level = RiskLevel.HIGH
    elif adjusted_score >= 35:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW

    return asset.model_copy(update={
        "risk_score": adjusted_score,
        "risk_level": level,
        "mosca_at_risk": metrics.at_risk,
    })


@dataclass(frozen=True)
class EnterpriseMoscaSummary:
    """Enterprise-wide Mosca risk summary."""
    total_assets: int
    at_risk_count: int
    immediate_count: int
    near_term_count: int
    monitor_count: int
    safe_count: int
    average_deficit: float
    max_deficit: float
    overall_urgency: str


def enterprise_mosca_summary(
    assets: list[CryptoAsset],
    quantum_year: int = DEFAULT_QUANTUM_YEAR,
) -> EnterpriseMoscaSummary:
    """Compute an enterprise-wide Mosca risk summary."""
    if not assets:
        return EnterpriseMoscaSummary(
            total_assets=0, at_risk_count=0, immediate_count=0,
            near_term_count=0, monitor_count=0, safe_count=0,
            average_deficit=0.0, max_deficit=0.0, overall_urgency="safe",
        )

    metrics = [compute_mosca_risk(asset, quantum_year) for asset in assets]
    deficits = [m.mosca_deficit for m in metrics]

    immediate = sum(1 for m in metrics if m.urgency == "immediate")
    near_term = sum(1 for m in metrics if m.urgency == "near-term")
    monitor = sum(1 for m in metrics if m.urgency == "monitor")
    safe = sum(1 for m in metrics if m.urgency == "safe")
    at_risk = sum(1 for m in metrics if m.at_risk)

    if immediate > 0:
        overall = "immediate"
    elif near_term > 0:
        overall = "near-term"
    elif monitor > 0:
        overall = "monitor"
    else:
        overall = "safe"

    return EnterpriseMoscaSummary(
        total_assets=len(assets),
        at_risk_count=at_risk,
        immediate_count=immediate,
        near_term_count=near_term,
        monitor_count=monitor,
        safe_count=safe,
        average_deficit=round(sum(deficits) / len(deficits), 1),
        max_deficit=round(max(deficits), 1),
        overall_urgency=overall,
    )
