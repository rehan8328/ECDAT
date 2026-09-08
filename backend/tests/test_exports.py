from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import json
from app.main import export_csv, export_cyclonedx, export_json, store
from app.models import RiskLevel, ScanResult
from app.scanner import scan_directory


def test_cbom_exports_are_generated_from_persisted_scan(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "crypto.py").write_text("AES-128\n", encoding="utf-8")
    _, assets = scan_directory(target)
    scan = ScanResult(
        scan_id=uuid4().hex, created_at=datetime.now(timezone.utc), scanned_path=str(target),
        files_scanned=1, assets=assets, risk_summary={level: 0 for level in RiskLevel},
    )
    store.save_scan(scan)

    csv_export = export_csv(scan.scan_id)
    json_export = export_json(scan.scan_id)
    cyclonedx_export = export_cyclonedx(scan.scan_id)

    assert "algorithm" in csv_export.body.decode()
    assert "AES-128" in csv_export.body.decode()
    assert b"AES-128" in json_export.body

    cdx_data = json.loads(cyclonedx_export.body.decode())
    assert cdx_data["bomFormat"] == "CycloneDX"
    assert cdx_data["specVersion"] == "1.6"
    assert len(cdx_data["components"]) == 1
    comp = cdx_data["components"][0]
    assert comp["type"] == "cryptographic-asset"
    assert comp["name"] == "AES-128"
    assert "cryptoProperties" in comp
    assert comp["cryptoProperties"]["assetType"] == "algorithm"
    assert comp["cryptoProperties"]["algorithmProperties"]["primitive"] == "block-cipher"
