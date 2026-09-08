from datetime import datetime, timezone
from pathlib import Path

import app.main as main
from app.main import render_executive_brief, render_markdown_report
from app.models import MoscaOverride, RiskLevel, ScanResult, SimulateFixRequest
from app.config import FRONTEND_ORIGINS, FRONTEND_PORT
from app.impact import analyze_impact
from app.migration import build_migration_plan
from app.scanner import scan_directory
from app.storage import CBOMStore
from app.certificates import parse_pem_certificate
from app.configuration import discover_configuration
from app.containers import discover_container_references
from app.dependencies import discover_javascript_dependencies
from app.risk import quantum_classification_for


def test_scanner_finds_assets_and_prioritizes_quantum_risk() -> None:
    fixture = Path(__file__).parents[2] / "demo-enterprise"

    files_scanned, assets = scan_directory(
        fixture,
        data_lifetime_years=12,
        migration_time_years=5,
        expected_crqc_years=10,
    )

    algorithms = {asset.algorithm for asset in assets}
    assert files_scanned >= 3
    assert {"RSA", "AES-128", "SHA-1"}.issubset(algorithms)
    dependency = next(asset for asset in assets if asset.asset_type == "crypto_dependency")
    assert dependency.library == "cryptography"
    assert dependency.version == "44.0.0"

    rsa = next(asset for asset in assets if asset.algorithm == "RSA")
    assert rsa.quantum_vulnerable is True
    assert rsa.quantum_classification == "shor-broken"
    assert rsa.key_size == 2048
    assert rsa.confidence == 85
    assert rsa.location == "backend/auth.py"
    assert rsa.line == 11
    assert rsa.mosca_at_risk is True
    assert rsa.risk_level is RiskLevel.CRITICAL
    assert "ML-DSA" in rsa.recommendation


def test_synthetic_demo_proves_route_trace_for_the_submission_flow() -> None:
    fixture = Path(__file__).parents[2] / "demo-enterprise"
    _, assets = scan_directory(fixture, 12, 5, 10)

    rsa = next(asset for asset in assets if asset.algorithm == "RSA" and asset.location == "backend/auth.py")
    impact = analyze_impact(rsa, fixture, assets)

    assert impact.services == ["Route /sessions"]
    assert impact.call_chains == [["backend/auth.py:create_session_key", "backend/auth.py:login"]]
    assert impact.exposure == "public-facing"


def test_scanner_finds_legacy_algorithms_and_hardcoded_key_material(tmp_path: Path) -> None:
    (tmp_path / "legacy.py").write_text(
        'DIGEST = "MD5"\nCIPHER = "RC4"\nAPI_KEY = "demo-only-key-material-rotate-me"\n',
        encoding="utf-8",
    )

    _, assets = scan_directory(tmp_path)

    findings = {asset.algorithm: asset for asset in assets}
    assert {"MD5", "RC4", "Hardcoded cryptographic key"}.issubset(findings)
    assert findings["Hardcoded cryptographic key"].risk_level is RiskLevel.CRITICAL
    assert "secrets manager" in findings["Hardcoded cryptographic key"].recommendation


def test_scanner_discovers_javascript_crypto_apis_and_package_dependencies(tmp_path: Path) -> None:
    (tmp_path / "service.ts").write_text(
        "import { createCipheriv, createHash, generateKeyPairSync } from 'node:crypto';\n"
        "import https from 'https';\n"
        "const cipher = createCipheriv('aes-256-gcm', key, iv);\n"
        "const digest = createHash('sha256');\n"
        "const keyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });\n"
        "https.createServer({ key, cert }, handler);\n",
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"crypto-js":"^4.2.0","node-forge":"1.3.1","react":"19.0.0"}}',
        encoding="utf-8",
    )

    _, assets = scan_directory(tmp_path, 12, 5, 10)

    algorithms = {asset.algorithm for asset in assets}
    assert {"RSA", "AES-256", "SHA-256", "TLS", "crypto-js", "node-forge"}.issubset(algorithms)
    assert next(asset for asset in assets if asset.algorithm == "RSA").line == 5
    assert next(asset for asset in assets if asset.algorithm == "TLS").protocol == "TLS"
    assert next(asset for asset in assets if asset.algorithm == "crypto-js").version == "^4.2.0"
    assert discover_javascript_dependencies('{"dependencies":{"tweetnacl":"^1.0.3"}}')[0].package == "tweetnacl"


def test_scanner_discovers_java_crypto_apis_and_bouncy_castle(tmp_path: Path) -> None:
    (tmp_path / "Gateway.java").write_text(
        'import org.bouncycastle.jce.provider.BouncyCastleProvider;\n'
        'KeyPairGenerator.getInstance("RSA");\n'
        'KeyAgreement.getInstance("DH");\n'
        'MessageDigest.getInstance("SHA-256");\n'
        'SSLContext.getInstance("TLSv1.3");\n',
        encoding="utf-8",
    )

    _, assets = scan_directory(tmp_path, 12, 5, 10)

    algorithms = {asset.algorithm for asset in assets}
    assert {"RSA", "DIFFIE-HELLMAN", "SHA-256", "TLS", "Bouncy Castle"}.issubset(algorithms)
    assert next(asset for asset in assets if asset.algorithm == "RSA").location == "Gateway.java"


def test_crypto_agility_rewards_configuration_and_project_abstraction(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text('RSA_ALGORITHM = "RSA"\n', encoding="utf-8")
    (tmp_path / "crypto_provider.py").write_text(
        'class CryptoProvider:\n    def sign(self):\n        return rsa.generate_private_key(key_size=2048)\n', encoding="utf-8"
    )
    (tmp_path / "orders.py").write_text('key = rsa.generate_private_key(key_size=2048)\n', encoding="utf-8")

    _, assets = scan_directory(tmp_path)
    provider = next(asset for asset in assets if asset.location == "crypto_provider.py")
    order = next(asset for asset in assets if asset.location == "orders.py")

    assert provider.crypto_agility_score is not None
    assert provider.crypto_agility_score > order.crypto_agility_score
    assert "referenced in 3 file(s)" in provider.crypto_agility_reason
    assert order.algorithm_file_count == 3


def test_quantum_classification_catalogue_is_explicit_and_extendable() -> None:
    assert quantum_classification_for("RSA") == "shor-broken"
    assert quantum_classification_for("AES-256") == "grover-weakened"
    assert quantum_classification_for("ML-KEM") == "pqc-ready"
    assert quantum_classification_for("unclassified-provider") == "classical-review"


def test_scan_report_includes_evidence_and_recommendation(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "crypto.py").write_text("AES-128\n", encoding="utf-8")
    _, assets = scan_directory(target)
    report = render_markdown_report(
        ScanResult(
            scan_id="unit-test",
            created_at=datetime.now(timezone.utc),
            scanned_path=str(target),
            files_scanned=1,
            assets=assets,
            risk_summary={level: 0 for level in RiskLevel},
        )
    )

    assert "# ECDAT Cryptographic Discovery Report" in report
    assert "AES-128" in report
    assert "Recommendation:" in report


def test_executive_brief_summarizes_evidence_and_first_actions(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "crypto.py").write_text("rsa.generate_private_key(key_size=2048)\n", encoding="utf-8")
    _, assets = scan_directory(target, 12, 5, 10)
    brief = render_executive_brief(ScanResult(
        scan_id="brief", created_at=datetime.now(timezone.utc), scanned_path=str(target),
        files_scanned=1, assets=assets, risk_summary={level: 0 for level in RiskLevel},
    ))

    assert "Generated Scan Summary" in brief
    assert "Recommended First Actions" in brief
    assert "P0" in brief


def test_impact_maps_a_crypto_call_inside_a_route_to_that_route(tmp_path: Path):
    (tmp_path / "api.py").write_text(
            "import hashlib\nfrom fastapi import FastAPI\napp = FastAPI()\n@app.get('/status')\ndef status():\n    return hashlib.md5(b'payload').hexdigest()\n",
        encoding="utf-8",
    )
    _, assets = scan_directory(tmp_path)

    impact = analyze_impact(next(asset for asset in assets if asset.algorithm == "MD5"), tmp_path, assets)

    assert impact.services == ["Route /status"]
    assert impact.call_chains == [["api.py:status"]]
    assert impact.exposure == "public-facing"


def test_impact_traces_multiple_call_hops_to_fixture_route():
    fixture = Path(__file__).parents[2] / "impact-fixtures" / "warehouse_api"
    _, assets = scan_directory(fixture, 12, 5, 10)

    impact = analyze_impact(next(asset for asset in assets if asset.algorithm == "RSA"), fixture, assets)

    assert impact.services == ["Route /warehouse/manifests"]
    assert impact.call_chains == [[
        "crypto_helpers.py:sign_manifest",
        "fulfillment_service.py:dispatch_manifest",
        "web_api.py:submit_manifest",
    ]]
    assert impact.applications == ["web_api.py"]


def test_impact_marks_unreachable_crypto_function_as_internal(tmp_path: Path):
    (tmp_path / "maintenance.py").write_text(
            "import hashlib\ndef refresh_key():\n    return hashlib.md5(b'payload').hexdigest()\n", encoding="utf-8"
    )
    _, assets = scan_directory(tmp_path)

    impact = analyze_impact(next(asset for asset in assets if asset.algorithm == "MD5"), tmp_path, assets)

    assert impact.services == ["Internal / no direct external exposure found"]
    assert impact.call_chains == []
    assert impact.exposure == "Internal / no direct external exposure found"


def test_migration_plan_prioritizes_critical_quantum_assets(tmp_path: Path):
    target = tmp_path / "backend"
    target.mkdir()
    (target / "auth.py").write_text(
        "rsa.generate_private_key(public_exponent=65537, key_size=2048)", encoding="utf-8"
    )
    _, assets = scan_directory(tmp_path, 12, 5, 10)

    plan = build_migration_plan(assets)

    assert plan[0].priority == "P0"
    assert plan[0].planning_window == "0-30 days"
    assert "hybrid" in plan[0].target
    assert plan[0].estimated_effort == "Large"
    assert "ML-KEM" in plan[0].hybrid_option
    assert plan[0].dependency_notes


def test_scoped_migration_plan_only_contains_staged_findings(tmp_path: Path, monkeypatch):
    (tmp_path / "crypto.py").write_text("SHA-1\nAES-128\n", encoding="utf-8")
    _, assets = scan_directory(tmp_path)
    store = CBOMStore(tmp_path / "scoped-plan.db")
    store.save_scan(ScanResult(
        scan_id="scoped", created_at=datetime.now(timezone.utc), scanned_path=str(tmp_path),
        files_scanned=1, assets=assets, risk_summary={level: 0 for level in RiskLevel},
    ))
    monkeypatch.setattr(main, "store", store)

    staged = main.build_scoped_migration_plan("scoped", main.MigrationPlanRequest(asset_ids=[assets[0].asset_id]))

    assert [task.asset_id for task in staged] == [assets[0].asset_id]


def test_per_asset_mosca_scenario_recalculates_and_scoped_plan_uses_it(tmp_path: Path, monkeypatch):
    (tmp_path / "crypto.py").write_text("AES-128\n", encoding="utf-8")
    _, assets = scan_directory(tmp_path, 2, 1, 10)
    store = CBOMStore(tmp_path / "mosca.db")
    store.save_scan(ScanResult(
        scan_id="mosca", created_at=datetime.now(timezone.utc), scanned_path=str(tmp_path),
        files_scanned=1, assets=assets, risk_summary={level: 0 for level in RiskLevel},
    ))
    monkeypatch.setattr(main, "store", store)
    override = MoscaOverride(asset_id=assets[0].asset_id, data_lifetime_years=18, migration_time_years=5, expected_crqc_years=10)

    scenario = main.project_mosca_scenario("mosca", assets[0].asset_id, override)
    plan = main.build_scoped_migration_plan("mosca", main.MigrationPlanRequest(asset_ids=[assets[0].asset_id], mosca_overrides=[override]))

    assert scenario.projected_asset.mosca_at_risk is True
    assert scenario.projected_asset.risk_score > assets[0].risk_score
    assert plan[0].priority == "P1"


def test_repository_targets_reject_non_github_urls_without_network_access():
    try:
        main.resolve_scan_target("https://example.com/not-a-repository")
    except ValueError as error:
        assert "github.com" in str(error)
    else:
        raise AssertionError("Non-GitHub repository target should be rejected")


def test_cbom_store_persists_scan_and_assets(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "crypto.py").write_text("AES-128\n", encoding="utf-8")
    _, assets = scan_directory(target)
    result = ScanResult(
        scan_id="persisted", created_at=datetime.now(timezone.utc), scanned_path=str(target),
        files_scanned=1, assets=assets, risk_summary={level: 0 for level in RiskLevel},
    )
    store = CBOMStore(tmp_path / "cbom.db")
    store.save_scan(result)

    restored = store.get_scan("persisted")

    assert restored is not None
    assert restored.assets[0].algorithm == "AES-128"
    assert restored.assets[0].version is None
    assert store.list_scans()[0].scan_id == "persisted"


def test_cbom_store_preserves_dependency_version(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "requirements.txt").write_text("cryptography==44.0.0\n", encoding="utf-8")
    _, assets = scan_directory(target)
    result = ScanResult(
        scan_id="dependency", created_at=datetime.now(timezone.utc), scanned_path=str(target),
        files_scanned=1, assets=assets, risk_summary={level: 0 for level in RiskLevel},
    )
    store = CBOMStore(tmp_path / "cbom.db")
    store.save_scan(result)

    restored = store.get_scan("dependency")

    assert restored is not None
    assert restored.assets[0].version == "44.0.0"


def test_certificate_parser_rejects_private_key_material():
    assert parse_pem_certificate("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----") is None


def test_configuration_scanner_detects_tls_policy_and_provider():
    findings = discover_configuration(
        "minimum_version: TLSv1.2\n- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\nprovider: OpenSSL\n"
    )

    assert [(finding.asset_type, finding.protocol) for finding in findings] == [
        ("tls_configuration", "TLS"), ("cipher_suite", "TLS"), ("crypto_provider", None)
    ]


def test_scanner_skips_generated_dependency_trees_and_oversized_files(tmp_path: Path):
    (tmp_path / "source.py").write_text("SHA-1\n", encoding="utf-8")
    generated = tmp_path / "node_modules" / "package"
    generated.mkdir(parents=True)
    (generated / "crypto.js").write_text("RSA\n", encoding="utf-8")
    (tmp_path / "large.txt").write_text("AES-128\n" * 150_000, encoding="utf-8")

    files_scanned, assets = scan_directory(tmp_path)

    assert files_scanned == 1
    assert [asset.algorithm for asset in assets] == ["SHA-1"]


def test_scanner_ignores_algorithm_names_in_comments_and_policy_tables(tmp_path: Path):
    (tmp_path / "policy.py").write_text(
        '# Legacy primitives: MD5, RC4, and DES are blocked.\n'
        'RULES = {"MD5": "replace", "AES-128": "review"}\n'
        'ALGORITHM = "AES-256-GCM"\n',
        encoding="utf-8",
    )

    _, assets = scan_directory(tmp_path)

    assert [asset.algorithm for asset in assets] == ["AES-256"]


def test_business_criticality_is_recorded_and_influences_risk(tmp_path: Path):
    (tmp_path / "crypto.py").write_text("AES-128\n", encoding="utf-8")

    _, low_assets = scan_directory(tmp_path, business_criticality="low")
    _, critical_assets = scan_directory(tmp_path, business_criticality="mission_critical")

    assert low_assets[0].business_criticality == "low"
    assert critical_assets[0].business_criticality == "mission_critical"
    assert critical_assets[0].risk_score > low_assets[0].risk_score


def test_container_manifest_references_are_catalogued_without_image_execution(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")
    (tmp_path / "deploy.yml").write_text("image: registry.example/ecdat:1.0\n", encoding="utf-8")

    _, assets = scan_directory(tmp_path)

    references = [asset for asset in assets if asset.asset_type == "container_image_reference"]
    assert {asset.library for asset in references} == {"python:3.12-slim", "registry.example/ecdat:1.0"}
    assert "container-image adapter" in references[0].recommendation
    assert discover_container_references("FROM alpine:3.20\n", is_dockerfile=True)[0].image == "alpine:3.20"


def test_cbom_store_filters_and_paginates_assets(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "crypto.py").write_text("AES-128\nSHA-1\n", encoding="utf-8")
    _, assets = scan_directory(target)
    store = CBOMStore(tmp_path / "cbom.db")
    store.save_scan(ScanResult(
        scan_id="search", created_at=datetime.now(timezone.utc), scanned_path=str(target),
        files_scanned=1, assets=assets, risk_summary={level: 0 for level in RiskLevel},
    ))

    items, total = store.list_assets("search", "SHA", RiskLevel.HIGH, limit=1, offset=0)

    assert total == 1
    assert items[0].algorithm == "SHA-1"


def test_scan_comparison_reports_new_and_resolved_assets(tmp_path: Path, monkeypatch):
    baseline_target = tmp_path / "baseline"
    current_target = tmp_path / "current"
    baseline_target.mkdir()
    current_target.mkdir()
    (baseline_target / "crypto.py").write_text("SHA-1\n", encoding="utf-8")
    (current_target / "crypto.py").write_text("AES-128\n", encoding="utf-8")
    _, baseline_assets = scan_directory(baseline_target)
    _, current_assets = scan_directory(current_target)
    isolated_store = CBOMStore(tmp_path / "compare.db")
    isolated_store.save_scan(ScanResult(
        scan_id="baseline", created_at=datetime.now(timezone.utc), scanned_path=str(baseline_target),
        files_scanned=1, assets=baseline_assets, risk_summary={level: 0 for level in RiskLevel},
    ))
    isolated_store.save_scan(ScanResult(
        scan_id="current", created_at=datetime.now(timezone.utc), scanned_path=str(current_target),
        files_scanned=1, assets=current_assets, risk_summary={level: 0 for level in RiskLevel},
    ))
    monkeypatch.setattr(main, "store", isolated_store)

    comparison = main.compare_scans("current", "baseline")

    assert [asset.algorithm for asset in comparison.new_assets] == ["AES-128"]
    assert [asset.algorithm for asset in comparison.resolved_assets] == ["SHA-1"]
    assert comparison.unchanged_count == 0


def test_simulate_fix_recalculates_rsa_and_md5_and_supports_multiple_findings(tmp_path: Path, monkeypatch):
    (tmp_path / "crypto.py").write_text(
        "rsa.generate_private_key(key_size=2048)\nDIGEST = 'MD5'\n", encoding="utf-8"
    )
    _, assets = scan_directory(tmp_path, 12, 5, 10, "high")
    isolated_store = CBOMStore(tmp_path / "simulation.db")
    isolated_store.save_scan(ScanResult(
        scan_id="simulation", created_at=datetime.now(timezone.utc), scanned_path=str(tmp_path),
        files_scanned=1, assets=assets, risk_summary={level: 0 for level in RiskLevel},
    ))
    monkeypatch.setattr(main, "store", isolated_store)
    rsa = next(asset for asset in assets if asset.algorithm == "RSA")
    md5 = next(asset for asset in assets if asset.algorithm == "MD5")

    rsa_projection = main.simulate_fix("simulation", rsa.asset_id, SimulateFixRequest())
    md5_projection = main.simulate_fix("simulation", md5.asset_id, SimulateFixRequest())
    combined = main.simulate_fix("simulation", rsa.asset_id, SimulateFixRequest(fixed_asset_ids=[md5.asset_id]))

    assert rsa_projection.projected_assets[0].risk_score < rsa.risk_score
    assert md5_projection.projected_assets[0].risk_score < md5.risk_score
    assert rsa_projection.projected_readiness > rsa_projection.current_readiness
    assert combined.projected_readiness > rsa_projection.projected_readiness
    assert combined.projected_risk_summary[RiskLevel.CRITICAL] < combined.current_risk_summary[RiskLevel.CRITICAL]


def test_cors_origin_uses_root_frontend_port_config():
    assert FRONTEND_ORIGINS == [f"http://127.0.0.1:{FRONTEND_PORT}", f"http://localhost:{FRONTEND_PORT}"]
    cors_middleware = next(item for item in main.app.user_middleware if item.cls.__name__ == "CORSMiddleware")
    assert cors_middleware.kwargs["allow_origins"] == FRONTEND_ORIGINS
