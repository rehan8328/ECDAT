from __future__ import annotations

from collections import Counter
import csv
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
from io import StringIO
import os
from pathlib import Path
import subprocess
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from .cyclonedx import generate_cyclonedx_cbom
from .impact import analyze_impact
from .config import FRONTEND_ORIGINS
from .migration import build_migration_plan
from .models import AssetPage, ComplianceSummary, ExposureMatrixItem, ImpactAnalysis, MigrationPlanRequest, MigrationTask, MoscaOverride, MoscaScenarioProjection, RiskLevel, ScanComparison, ScanRequest, ScanResult, SimulateFixRequest, SimulationProjection
from .risk import assess_risk, quantum_readiness, simulate_remediation
from .scanner import scan_directory
from .storage import CBOMStore


app = FastAPI(title="ECDAT API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCAN_ROOT = Path(os.getenv("ECDAT_SCAN_ROOT", PROJECT_ROOT)).expanduser().resolve()
store = CBOMStore(Path(os.getenv("ECDAT_DB_PATH", PROJECT_ROOT / "backend" / "data" / "ecdat.db")))


def resolve_scan_target(raw_target: str) -> tuple[Path, str]:
    """Return an approved local scan directory, cloning an explicit public GitHub URL when requested."""
    parsed = urlparse(raw_target)
    if parsed.scheme:
        if parsed.scheme != "https" or parsed.hostname not in {"github.com", "www.github.com"}:
            raise ValueError("Repository scans accept public https://github.com/<owner>/<repository> URLs only")
        if not parsed.path.strip("/") or len(parsed.path.strip("/").split("/")) != 2:
            raise ValueError("Repository URL must identify one GitHub owner and repository")
        clone_root = PROJECT_ROOT / "outputs" / "remote-scans"
        clone_root.mkdir(parents=True, exist_ok=True)
        destination = clone_root / sha256(raw_target.encode("utf-8")).hexdigest()[:16]
        if destination.is_dir() and (destination / ".git").exists():
            return destination, raw_target
        try:
            completed = subprocess.run(
                ["git", "clone", "--depth", "1", "--no-tags", raw_target, str(destination)],
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("Repository clone failed; confirm Git is installed and the repository is publicly reachable") from error
        if completed.returncode != 0:
            raise ValueError(f"Repository clone failed: {completed.stderr.strip()[:180] or 'unknown Git error'}")
        return destination, raw_target

    path = Path(raw_target).expanduser().resolve()
    if not path.is_relative_to(SCAN_ROOT):
        raise ValueError(f"Scan path must be inside configured scan root: {SCAN_ROOT}")
    return path, str(path)


def materialized_scan_path(stored_target: str) -> Path:
    """Resolve a stored local path or the stable local copy for a cloned GitHub scan."""
    parsed = urlparse(stored_target)
    if parsed.scheme == "https" and parsed.hostname in {"github.com", "www.github.com"}:
        return PROJECT_ROOT / "outputs" / "remote-scans" / sha256(stored_target.encode("utf-8")).hexdigest()[:16]
    return Path(stored_target)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/scans", response_model=ScanResult)
def create_scan(request: ScanRequest) -> ScanResult:
    try:
        path, display_path = resolve_scan_target(request.path)
        files_scanned, assets = scan_directory(
            path,
            request.data_lifetime_years,
            request.migration_time_years,
            request.expected_crqc_years,
            request.business_criticality,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    counts = Counter(asset.risk_level for asset in assets)
    result = ScanResult(
        scan_id=uuid4().hex,
        created_at=datetime.now(timezone.utc),
        scanned_path=display_path,
        files_scanned=files_scanned,
        assets=assets,
        risk_summary={level: counts.get(level, 0) for level in RiskLevel},
    )
    store.save_scan(result)
    return result


@app.get("/api/v1/scans", response_model=list[ScanResult])
def list_scans() -> list[ScanResult]:
    return store.list_scans()


@app.get("/api/v1/scans/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: str) -> ScanResult:
    result = store.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@app.get("/api/v1/scans/{scan_id}/compare", response_model=ScanComparison)
def compare_scans(scan_id: str, baseline_scan_id: str = Query(min_length=1)) -> ScanComparison:
    current = store.get_scan(scan_id)
    baseline = store.get_scan(baseline_scan_id)
    if current is None or baseline is None:
        raise HTTPException(status_code=404, detail="One or both scans were not found")

    def fingerprint(asset: object) -> tuple[object, ...]:
        item = asset
        return (item.asset_type, item.algorithm, item.location, item.line, item.mode, item.protocol, item.library)

    current_by_key = {fingerprint(asset): asset for asset in current.assets}
    baseline_by_key = {fingerprint(asset): asset for asset in baseline.assets}
    new_assets = [asset for key, asset in current_by_key.items() if key not in baseline_by_key]
    resolved_assets = [asset for key, asset in baseline_by_key.items() if key not in current_by_key]
    changed_assets = [
        asset for key, asset in current_by_key.items()
        if key in baseline_by_key and (
            asset.risk_score != baseline_by_key[key].risk_score
            or asset.risk_level != baseline_by_key[key].risk_level
            or asset.mosca_at_risk != baseline_by_key[key].mosca_at_risk
        )
    ]
    unchanged_count = len(current_by_key) - len(new_assets) - len(changed_assets)
    return ScanComparison(
        baseline_scan_id=baseline_scan_id, current_scan_id=scan_id, new_assets=new_assets,
        resolved_assets=resolved_assets, changed_assets=changed_assets, unchanged_count=unchanged_count,
    )


@app.get("/api/v1/assets", response_model=AssetPage)
def list_assets(
    scan_id: str | None = None,
    query: str | None = Query(default=None, min_length=1, max_length=100),
    risk_level: RiskLevel | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> AssetPage:
    items, total = store.list_assets(scan_id, query, risk_level, limit, offset)
    return AssetPage(items=items, total=total, limit=limit, offset=offset)


@app.get("/api/v1/scans/{scan_id}/report", response_class=PlainTextResponse)
def export_report(scan_id: str) -> str:
    result = store.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan report not found")

    return render_markdown_report(result)


@app.get("/api/v1/scans/{scan_id}/executive-brief", response_class=PlainTextResponse)
def export_executive_brief(scan_id: str) -> str:
    result = store.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan report not found")
    return render_executive_brief(result)


@app.get("/api/v1/scans/{scan_id}/executive-summary", response_class=HTMLResponse)
def export_executive_summary(scan_id: str) -> str:
    result = store.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan report not found")
    compliance = cnsa_compliance(scan_id)
    readiness = quantum_readiness(result.assets)
    priorities = build_migration_plan(result.assets)[:3]
    effort = {"Large": 0, "Medium": 1, "Small": 2}
    estimated_effort = min((task.estimated_effort for task in priorities), key=lambda value: effort.get(value, 3), default="Small")
    rows = "".join(
        f"<tr><td>{escape(task.priority)}</td><td>{escape(task.algorithm)}</td><td>{escape(task.target)}</td><td>{escape(task.estimated_effort)}</td></tr>"
        for task in priorities
    ) or "<tr><td colspan='4'>No findings detected.</td></tr>"
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>ECDAT Scan Summary</title>
    <style>body{{font-family:Arial,sans-serif;color:#18212f;max-width:900px;margin:40px auto;padding:0 28px}}h1{{margin-bottom:4px}}.muted{{color:#667085}}.stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:28px 0}}.stat{{padding:16px;border:1px solid #dce3eb;border-radius:6px}}.stat b{{display:block;font-size:30px;color:#175cd3}}table{{width:100%;border-collapse:collapse}}th,td{{padding:11px;text-align:left;border-bottom:1px solid #dce3eb;font-size:13px}}th{{color:#667085}}@media print{{body{{margin:0;max-width:none}}}}</style></head><body>
    <p class='muted'>ECDAT prototype | SIH 2026 | NTRO Problem Statement 26164</p><h1>Generated Scan Summary</h1><p class='muted'>Assessment target: {escape(result.scanned_path)} | Generated: {escape(result.created_at.isoformat())}</p>
    <section class='stats'><div class='stat'><span>Quantum-risk indicator</span><b>{readiness}/100</b><small>Calculated from discovered exposure, severity, and Mosca inputs.</small></div><div class='stat'><span>CNSA 2.0 planning indicator</span><b>{compliance.ready_percent}%</b><small>{compliance.ready_assets} of {compliance.total_assets} findings meet this prototype indicator.</small></div><div class='stat'><span>Sample effort band</span><b>{escape(estimated_effort)}</b><small>A coarse planning label for the displayed recommendations.</small></div></section>
    <h2>Highest-priority findings</h2><table><thead><tr><th>Priority</th><th>Finding</th><th>Suggested review</th><th>Effort band</th></tr></thead><tbody>{rows}</tbody></table>
    <h2>Interpretation notes</h2><p>{escape(compliance.explanation)}</p><p>This prototype performs read-only evidence discovery. Results, recommendations, and planning indicators require architecture, interoperability, policy, and validation review before any deployment decision.</p></body></html>"""


@app.get("/api/v1/scans/{scan_id}/export.json")
def export_json(scan_id: str) -> JSONResponse:
    result = store.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse(
        content=result.model_dump(mode="json"),
        headers={"Content-Disposition": f'attachment; filename="ecdat-cbom-{scan_id}.json"'},
    )


@app.get("/api/v1/scans/{scan_id}/export.cyclonedx.json")
def export_cyclonedx(scan_id: str) -> JSONResponse:
    result = store.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    cbom = generate_cyclonedx_cbom(result)
    return JSONResponse(
        content=cbom,
        media_type="application/vnd.cyclonedx+json",
        headers={"Content-Disposition": f'attachment; filename="ecdat-cyclonedx-cbom-{scan_id}.json"'},
    )


@app.get("/api/v1/scans/{scan_id}/export.csv")
def export_csv(scan_id: str) -> Response:
    result = store.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    fields = ["asset_id", "asset_type", "algorithm", "key_size", "mode", "protocol", "library", "version",
              "location", "line", "confidence", "quantum_vulnerable", "risk_score", "risk_level",
              "mosca_at_risk", "business_criticality", "recommendation"]
    output = StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for asset in result.assets:
        writer.writerow({field: getattr(asset, field) for field in fields})
    return Response(
        content=output.getvalue(), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="ecdat-cbom-{scan_id}.csv"'},
    )


@app.get("/api/v1/scans/{scan_id}/impact/{asset_id}", response_model=ImpactAnalysis)
def get_impact(scan_id: str, asset_id: str) -> ImpactAnalysis:
    result = store.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    asset = next((item for item in result.assets if item.asset_id == asset_id), None)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found in scan")
    return analyze_impact(asset, materialized_scan_path(result.scanned_path), result.assets)


@app.get("/api/v1/scans/{scan_id}/exposure-matrix", response_model=list[ExposureMatrixItem])
def exposure_matrix(scan_id: str) -> list[ExposureMatrixItem]:
    result = store.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    root = materialized_scan_path(result.scanned_path)
    items: list[ExposureMatrixItem] = []
    for asset in result.assets:
        impact = analyze_impact(asset, root, result.assets)
        items.append(ExposureMatrixItem(
            asset_id=asset.asset_id,
            algorithm=asset.algorithm,
            risk_level=asset.risk_level,
            risk_score=asset.risk_score,
            exposure=impact.exposure,
            hndl_score=impact.hndl_score,
            hndl_candidate=asset.quantum_vulnerable and asset.mosca_at_risk and asset.business_criticality in {"high", "mission_critical"},
        ))
    return items


@app.get("/api/v1/scans/{scan_id}/compliance/cnsa-2.0", response_model=ComplianceSummary)
def cnsa_compliance(scan_id: str) -> ComplianceSummary:
    result = store.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    total = len(result.assets)
    ready = sum(
        asset.quantum_classification == "pqc-ready" or (
            not asset.quantum_vulnerable and asset.algorithm not in {"MD5", "RC4", "3DES", "DES", "SHA-1", "AES-CBC"}
        )
        for asset in result.assets
    )
    return ComplianceSummary(
        framework="CNSA 2.0 readiness overlay",
        deadline="2035 planning horizon",
        ready_percent=round((ready / total) * 100) if total else 100,
        ready_assets=ready,
        total_assets=total,
        explanation="Readiness is a planning indicator: assets are counted where they are not Shor-vulnerable and do not use a detected legacy primitive. Validate deployment, protocol, and procurement requirements before declaring compliance.",
    )


@app.get("/api/v1/scans/{scan_id}/migration", response_model=list[MigrationTask])
def get_migration_plan(scan_id: str) -> list[MigrationTask]:
    result = store.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return build_migration_plan(result.assets)


@app.post("/api/v1/scans/{scan_id}/migration", response_model=list[MigrationTask])
def build_scoped_migration_plan(scan_id: str, request: MigrationPlanRequest) -> list[MigrationTask]:
    result = store.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    requested = set(request.asset_ids)
    if not requested:
        return []
    assets = [asset for asset in result.assets if asset.asset_id in requested]
    missing = requested - {asset.asset_id for asset in assets}
    if missing:
        raise HTTPException(status_code=404, detail=f"Finding not found in scan: {', '.join(sorted(missing))}")
    overrides = {override.asset_id: override for override in request.mosca_overrides}
    unknown_overrides = set(overrides) - requested
    if unknown_overrides:
        raise HTTPException(status_code=400, detail="Mosca overrides must refer to staged findings")
    return build_migration_plan([_apply_mosca_override(asset, overrides.get(asset.asset_id)) for asset in assets])


def _apply_mosca_override(asset, override: MoscaOverride | None):
    if override is None:
        return asset
    quantum_vulnerable, mosca_at_risk, score, level, recommendation = assess_risk(
        asset.algorithm,
        override.data_lifetime_years,
        override.migration_time_years,
        override.expected_crqc_years,
        asset.business_criticality,
    )
    return asset.model_copy(update={
        "quantum_vulnerable": quantum_vulnerable,
        "mosca_at_risk": mosca_at_risk,
        "risk_score": score,
        "risk_level": level,
        "recommendation": recommendation,
    })


@app.post("/api/v1/scans/{scan_id}/findings/{asset_id}/mosca-scenario", response_model=MoscaScenarioProjection)
def project_mosca_scenario(scan_id: str, asset_id: str, request: MoscaOverride) -> MoscaScenarioProjection:
    result = store.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if request.asset_id != asset_id:
        raise HTTPException(status_code=400, detail="Scenario asset must match the requested finding")
    asset = next((item for item in result.assets if item.asset_id == asset_id), None)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found in scan")
    projected = _apply_mosca_override(asset, request)
    return MoscaScenarioProjection(
        asset_id=asset_id,
        data_lifetime_years=request.data_lifetime_years,
        migration_time_years=request.migration_time_years,
        expected_crqc_years=request.expected_crqc_years,
        projected_asset=projected,
        explanation="What-if scenario only. Source code and the saved scan are unchanged; the adjusted score uses the same algorithm, criticality, and Mosca formula as a live assessment.",
    )


@app.post("/api/v1/scans/{scan_id}/findings/{asset_id}/simulate-fix", response_model=SimulationProjection)
def simulate_fix(scan_id: str, asset_id: str, request: SimulateFixRequest) -> SimulationProjection:
    result = store.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    ids = list(dict.fromkeys([asset_id, *request.fixed_asset_ids]))
    available = {asset.asset_id for asset in result.assets}
    unknown = sorted(set(ids) - available)
    if unknown:
        raise HTTPException(status_code=404, detail=f"Finding not found in scan: {', '.join(unknown)}")
    projected_assets = [simulate_remediation(asset) if asset.asset_id in ids else asset for asset in result.assets]
    current_counts = Counter(asset.risk_level for asset in result.assets)
    projected_counts = Counter(asset.risk_level for asset in projected_assets)
    return SimulationProjection(
        scan_id=scan_id,
        simulated_asset_ids=ids,
        current_readiness=quantum_readiness(result.assets),
        projected_readiness=quantum_readiness(projected_assets),
        current_risk_summary={level: current_counts.get(level, 0) for level in RiskLevel},
        projected_risk_summary={level: projected_counts.get(level, 0) for level in RiskLevel},
        projected_assets=[asset for asset in projected_assets if asset.asset_id in ids],
        disclaimer="Simulation only. No source file, repository, or persisted scan finding was modified; validate the recommended change with testing and a new scan.",
    )


def render_markdown_report(result: ScanResult) -> str:
    lines = [
        "# ECDAT Cryptographic Discovery Report",
        "",
        f"- Scan ID: `{result.scan_id}`",
        f"- Generated: {result.created_at.isoformat()}",
        f"- Target: `{result.scanned_path}`",
        f"- Files scanned: {result.files_scanned}",
        f"- Assets detected: {len(result.assets)}",
        "",
        "## Risk Summary",
    ]
    lines.extend(f"- {level.value.title()}: {result.risk_summary[level]}" for level in RiskLevel)
    lines.extend(["", "## Findings"])
    for asset in result.assets:
        lines.extend(
            [
                f"### {asset.asset_id}: {asset.algorithm} ({asset.risk_level.title()})",
                f"- Evidence: `{asset.location}:{asset.line}` - `{asset.evidence}`",
                f"- Risk score: {asset.risk_score}/100",
                f"- Quantum vulnerable: {'Yes' if asset.quantum_vulnerable else 'No'}",
                f"- Mosca horizon at risk: {'Yes' if asset.mosca_at_risk else 'No'}",
                f"- Recommendation: {asset.recommendation}",
                "",
            ]
        )
    return "\n".join(lines)


def render_executive_brief(result: ScanResult) -> str:
    critical = result.risk_summary[RiskLevel.CRITICAL]
    high = result.risk_summary[RiskLevel.HIGH]
    quantum_vulnerable = sum(asset.quantum_vulnerable for asset in result.assets)
    mosca_at_risk = sum(asset.mosca_at_risk for asset in result.assets)
    priorities = build_migration_plan(result.assets)[:5]
    lines = [
        "# ECDAT Generated Scan Summary",
        "",
        f"**Assessment target:** `{result.scanned_path}`",
        f"**Assessment date:** {result.created_at.isoformat()}",
        f"**Evidence reviewed:** {result.files_scanned} files and {len(result.assets)} cryptographic assets",
        "",
        "## Scan Summary",
        f"- **{critical} critical** and **{high} high** findings are present in this scan.",
        f"- **{quantum_vulnerable} public-key assets** are classified as quantum-vulnerable by the prototype rules.",
        f"- **{mosca_at_risk} assets** exceed the configured Mosca planning horizon.",
        "- The output links discovered evidence to a suggested PQC or hybrid review path.",
        "",
        "## Scope Note",
        "This report is generated from the selected local scan. It is a prototype output and is not a certification, audit result, or deployment recommendation.",
        "",
        "## Recommended First Actions",
    ]
    for task in priorities:
        lines.append(f"- **{task.priority} | {task.algorithm} | {task.planning_window}:** {task.target}")
    lines.extend([
        "",
        "## Validation Required",
        "Algorithm replacement remains subject to protocol, vendor, interoperability, security, and operational validation.",
    ])
    return "\n".join(lines)
