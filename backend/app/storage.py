from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import CryptoAsset, RiskLevel, ScanResult


class CBOMStore:
    """Small offline-first persistence layer; replaceable with PostgreSQL in deployment."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    scanned_path TEXT NOT NULL,
                    files_scanned INTEGER NOT NULL,
                    risk_summary TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS crypto_assets (
                    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
                    asset_id TEXT NOT NULL,
                    asset_type TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    key_size INTEGER,
                    mode TEXT,
                    library TEXT,
                    version TEXT,
                    certificate_subject TEXT,
                    certificate_issuer TEXT,
                    certificate_expires_at TEXT,
                    protocol TEXT,
                    confidence INTEGER NOT NULL,
                    location TEXT NOT NULL,
                    line INTEGER,
                    evidence TEXT NOT NULL,
                    quantum_vulnerable INTEGER NOT NULL,
                    quantum_classification TEXT NOT NULL DEFAULT 'classical-review',
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    mosca_at_risk INTEGER NOT NULL,
                    business_criticality TEXT NOT NULL DEFAULT 'medium',
                    crypto_agility_score INTEGER,
                    crypto_agility_reason TEXT,
                    algorithm_file_count INTEGER,
                    recommendation TEXT NOT NULL,
                    PRIMARY KEY (scan_id, asset_id)
                );
                CREATE INDEX IF NOT EXISTS idx_assets_algorithm ON crypto_assets(algorithm);
                CREATE INDEX IF NOT EXISTS idx_assets_risk ON crypto_assets(risk_level);
                """
            )
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(crypto_assets)")}
            if "version" not in columns:
                connection.execute("ALTER TABLE crypto_assets ADD COLUMN version TEXT")
            for column in ("certificate_subject", "certificate_issuer", "certificate_expires_at"):
                if column not in columns:
                    connection.execute(f"ALTER TABLE crypto_assets ADD COLUMN {column} TEXT")
            if "protocol" not in columns:
                connection.execute("ALTER TABLE crypto_assets ADD COLUMN protocol TEXT")
            if "business_criticality" not in columns:
                connection.execute("ALTER TABLE crypto_assets ADD COLUMN business_criticality TEXT NOT NULL DEFAULT 'medium'")
            if "quantum_classification" not in columns:
                connection.execute("ALTER TABLE crypto_assets ADD COLUMN quantum_classification TEXT NOT NULL DEFAULT 'classical-review'")
            if "crypto_agility_score" not in columns:
                connection.execute("ALTER TABLE crypto_assets ADD COLUMN crypto_agility_score INTEGER")
            if "crypto_agility_reason" not in columns:
                connection.execute("ALTER TABLE crypto_assets ADD COLUMN crypto_agility_reason TEXT")
            if "algorithm_file_count" not in columns:
                connection.execute("ALTER TABLE crypto_assets ADD COLUMN algorithm_file_count INTEGER")

    def save_scan(self, result: ScanResult) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO scans VALUES (?, ?, ?, ?, ?)",
                (result.scan_id, result.created_at.isoformat(), result.scanned_path, result.files_scanned,
                 json.dumps({level.value: count for level, count in result.risk_summary.items()})),
            )
            connection.executemany(
                """INSERT INTO crypto_assets (
                    scan_id, asset_id, asset_type, algorithm, key_size, mode, library, version, certificate_subject,
                    certificate_issuer, certificate_expires_at, protocol, confidence, location, line, evidence,
                    quantum_vulnerable, quantum_classification, risk_score, risk_level, mosca_at_risk, business_criticality, crypto_agility_score, crypto_agility_reason, algorithm_file_count, recommendation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (result.scan_id, asset.asset_id, asset.asset_type, asset.algorithm, asset.key_size, asset.mode,
                     asset.library, asset.version, asset.certificate_subject, asset.certificate_issuer,
                     asset.certificate_expires_at, asset.protocol, asset.confidence, asset.location, asset.line, asset.evidence,
                     int(asset.quantum_vulnerable), asset.quantum_classification, asset.risk_score, asset.risk_level.value,
                     int(asset.mosca_at_risk), asset.business_criticality, asset.crypto_agility_score, asset.crypto_agility_reason, asset.algorithm_file_count, asset.recommendation)
                    for asset in result.assets
                ],
            )

    def get_scan(self, scan_id: str) -> ScanResult | None:
        with self._connect() as connection:
            scan = connection.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
            if scan is None:
                return None
            rows = connection.execute(
                "SELECT * FROM crypto_assets WHERE scan_id = ? ORDER BY asset_id", (scan_id,)
            ).fetchall()
        summary = json.loads(scan["risk_summary"])
        return ScanResult(
            scan_id=scan["scan_id"], created_at=scan["created_at"], scanned_path=scan["scanned_path"],
            files_scanned=scan["files_scanned"],
            assets=[self._asset_from_row(row) for row in rows],
            risk_summary={level: summary.get(level.value, 0) for level in RiskLevel},
        )

    def list_scans(self) -> list[ScanResult]:
        with self._connect() as connection:
            ids = [row["scan_id"] for row in connection.execute("SELECT scan_id FROM scans ORDER BY created_at DESC")]
        return [scan for scan_id in ids if (scan := self.get_scan(scan_id)) is not None]

    def list_assets(
        self, scan_id: str | None, query: str | None, risk_level: RiskLevel | None, limit: int, offset: int
    ) -> tuple[list[CryptoAsset], int]:
        clauses: list[str] = []
        values: list[str | int] = []
        if scan_id:
            clauses.append("scan_id = ?")
            values.append(scan_id)
        if risk_level:
            clauses.append("risk_level = ?")
            values.append(risk_level.value)
        if query:
            clauses.append("(algorithm LIKE ? OR location LIKE ? OR library LIKE ? OR asset_id LIKE ?)")
            values.extend([f"%{query}%"] * 4)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as connection:
            total = connection.execute(f"SELECT COUNT(*) FROM crypto_assets{where}", values).fetchone()[0]
            rows = connection.execute(
                f"""SELECT * FROM crypto_assets{where}
                ORDER BY risk_score DESC, asset_id ASC LIMIT ? OFFSET ?""", [*values, limit, offset]
            ).fetchall()
        return [self._asset_from_row(row) for row in rows], total

    @staticmethod
    def _asset_from_row(row: sqlite3.Row) -> CryptoAsset:
        return CryptoAsset(
            asset_id=row["asset_id"], asset_type=row["asset_type"], algorithm=row["algorithm"],
            key_size=row["key_size"], mode=row["mode"], library=row["library"], version=row["version"],
            certificate_subject=row["certificate_subject"], certificate_issuer=row["certificate_issuer"],
            certificate_expires_at=row["certificate_expires_at"], protocol=row["protocol"], confidence=row["confidence"],
            location=row["location"], line=row["line"], evidence=row["evidence"],
            quantum_vulnerable=bool(row["quantum_vulnerable"]), quantum_classification=row["quantum_classification"], risk_score=row["risk_score"],
            risk_level=RiskLevel(row["risk_level"]), mosca_at_risk=bool(row["mosca_at_risk"]),
            business_criticality=row["business_criticality"],
            crypto_agility_score=row["crypto_agility_score"], crypto_agility_reason=row["crypto_agility_reason"], algorithm_file_count=row["algorithm_file_count"],
            recommendation=row["recommendation"],
        )
