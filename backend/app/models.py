from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CryptoAsset(BaseModel):
    asset_id: str
    asset_type: str
    algorithm: str
    key_size: int | None = None
    mode: str | None = None
    library: str | None = None
    version: str | None = None
    certificate_subject: str | None = None
    certificate_issuer: str | None = None
    certificate_expires_at: str | None = None
    protocol: str | None = None
    confidence: int = Field(default=85, ge=0, le=100)
    location: str
    line: int | None = None
    evidence: str
    quantum_vulnerable: bool
    quantum_classification: str = "classical-review"
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    mosca_at_risk: bool
    business_criticality: str = Field(default="medium", pattern="^(low|medium|high|mission_critical)$")
    recommendation: str
    # New fields for Mosca risk calculation
    lifetime_days: int | None = None  # Expected data lifetime in days
    expiry_date: str | None = None    # ISO‑8601 date when certificate/key expires
    rotation_interval: int | None = None  # Recommended rotation interval in days
    crypto_agility_score: int | None = Field(default=None, ge=0, le=100)
    crypto_agility_reason: str | None = None
    algorithm_file_count: int | None = Field(default=None, ge=0)


class MoscaOverride(BaseModel):
    asset_id: str
    data_lifetime_years: int = Field(ge=0, le=100)
    migration_time_years: int = Field(ge=0, le=100)
    expected_crqc_years: int = Field(ge=1, le=100)


class MoscaScenarioProjection(BaseModel):
    asset_id: str
    data_lifetime_years: int
    migration_time_years: int
    expected_crqc_years: int
    projected_asset: CryptoAsset
    explanation: str


class ScanRequest(BaseModel):
    path: str = Field(description="Approved local directory or public GitHub repository URL to scan")
    data_lifetime_years: int = Field(default=10, ge=0, le=100)
    migration_time_years: int = Field(default=3, ge=0, le=100)
    expected_crqc_years: int = Field(default=10, ge=1, le=100)
    business_criticality: str = Field(default="medium", pattern="^(low|medium|high|mission_critical)$")


class ScanResult(BaseModel):
    scan_id: str
    created_at: datetime
    scanned_path: str
    files_scanned: int
    assets: list[CryptoAsset]
    risk_summary: dict[RiskLevel, int]


class ImpactAnalysis(BaseModel):
    asset_id: str
    source: str
    business_units: list[str]
    applications: list[str]
    services: list[str]
    dependencies: list[str]
    certificates: int
    migration_difficulty: str
    exposure: str
    data_sensitivity: str
    hndl_score: int = Field(ge=0, le=100)
    migration_factors: list[str]
    standards: list[str]
    containing_function: str | None = None
    call_chains: list[list[str]] = Field(default_factory=list)
    rationale: str


class MigrationTask(BaseModel):
    asset_id: str
    algorithm: str
    priority: str
    status: str
    planning_window: str
    owner: str
    target: str
    rationale: str
    estimated_effort: str
    dependency_notes: list[str] = Field(default_factory=list)
    pure_pqc_option: str
    hybrid_option: str
    tradeoffs: str


class MigrationPlanRequest(BaseModel):
    asset_ids: list[str] = Field(default_factory=list)
    mosca_overrides: list[MoscaOverride] = Field(default_factory=list)


class AssetPage(BaseModel):
    items: list[CryptoAsset]
    total: int
    limit: int
    offset: int


class ScanComparison(BaseModel):
    baseline_scan_id: str
    current_scan_id: str
    new_assets: list[CryptoAsset]
    resolved_assets: list[CryptoAsset]
    changed_assets: list[CryptoAsset]
    unchanged_count: int


class SimulateFixRequest(BaseModel):
    fixed_asset_ids: list[str] = Field(default_factory=list)


class SimulationProjection(BaseModel):
    scan_id: str
    simulated_asset_ids: list[str]
    current_readiness: int = Field(ge=0, le=100)
    projected_readiness: int = Field(ge=0, le=100)
    current_risk_summary: dict[RiskLevel, int]
    projected_risk_summary: dict[RiskLevel, int]
    projected_assets: list[CryptoAsset]
    disclaimer: str


class ExposureMatrixItem(BaseModel):
    asset_id: str
    algorithm: str
    risk_level: RiskLevel
    risk_score: int = Field(ge=0, le=100)
    exposure: str
    hndl_score: int = Field(ge=0, le=100)
    hndl_candidate: bool


class ComplianceSummary(BaseModel):
    framework: str
    deadline: str
    ready_percent: int = Field(ge=0, le=100)
    ready_assets: int
    total_assets: int
    explanation: str
