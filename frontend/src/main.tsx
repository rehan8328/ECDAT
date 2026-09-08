import { FormEvent, MouseEvent, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { ArrowUpRight, Check, Download, FileSearch, History, LayoutDashboard, ListChecks, Network, PlayCircle, ShieldAlert, SlidersHorizontal, Sparkles } from "lucide-react";
import { MoscaTimeline, QuantumReadinessGauge, RiskScoreBar, SeverityStack } from "./visualizations";
import { severityColors } from "./severityColors";
import "./styles.css";

type Level = "critical" | "high" | "medium" | "low";
type Asset = { asset_id: string; algorithm: string; asset_type: string; key_size?: number | null; mode?: string | null; library?: string | null; protocol?: string | null; confidence?: number; location: string; line: number | null; risk_level: Level; risk_score: number; quantum_vulnerable: boolean; quantum_classification?: string; mosca_at_risk: boolean; business_criticality?: string; crypto_agility_score?: number | null; crypto_agility_reason?: string | null; algorithm_file_count?: number | null; recommendation: string };
type ScanResult = { scan_id: string; created_at: string; scanned_path: string; files_scanned: number; assets: Asset[]; risk_summary: Record<Level, number> };
type Impact = { source: string; business_units: string[]; applications: string[]; services: string[]; dependencies: string[]; certificates: number; migration_difficulty: string; exposure: string; data_sensitivity: string; hndl_score: number; migration_factors: string[]; standards: string[]; containing_function?: string | null; call_chains: string[][]; rationale: string };
type MigrationTask = { asset_id: string; algorithm: string; priority: string; status: string; planning_window: string; owner: string; target: string; estimated_effort: string; dependency_notes: string[]; pure_pqc_option: string; hybrid_option: string; tradeoffs: string };
type ScanComparison = { baseline_scan_id: string; current_scan_id: string; new_assets: Asset[]; resolved_assets: Asset[]; changed_assets: Asset[]; unchanged_count: number };
type Projection = { scan_id: string; simulated_asset_ids: string[]; current_readiness: number; projected_readiness: number; current_risk_summary: Record<Level, number>; projected_risk_summary: Record<Level, number>; projected_assets: Asset[]; disclaimer: string };
type MoscaScenario = { asset_id: string; data_lifetime_years: number; migration_time_years: number; expected_crqc_years: number; projected_asset: Asset; explanation: string };
type ExposureMatrixItem = { asset_id: string; algorithm: string; risk_level: Level; risk_score: number; exposure: string; hndl_score: number; hndl_candidate: boolean };
type Workspace = "overview" | "discovery" | "prioritize" | "inventory" | "migration" | "workflow" | "demo";

const apiUrl = import.meta.env.VITE_ECDAT_API_URL;
const demoAssets: Asset[] = [
  { asset_id: "CRYPTO-00001", algorithm: "RSA", asset_type: "asymmetric_algorithm", key_size: 2048, confidence: 85, location: "backend/auth.py", line: 11, risk_level: "critical", risk_score: 80, quantum_vulnerable: true, quantum_classification: "shor-broken", mosca_at_risk: true, business_criticality: "medium", crypto_agility_score: 50, crypto_agility_reason: "configuration-managed; referenced in 3 file(s); no project abstraction detected", algorithm_file_count: 3, recommendation: "Use ML-DSA for signatures or ML-KEM for key establishment; prefer a hybrid migration where compatibility is required." },
  { asset_id: "CRYPTO-00002", algorithm: "AES-128", asset_type: "symmetric_algorithm", confidence: 85, location: "backend/encryption.py", line: 1, risk_level: "high", risk_score: 60, quantum_vulnerable: false, quantum_classification: "grover-weakened", mosca_at_risk: true, business_criticality: "medium", crypto_agility_score: 45, crypto_agility_reason: "inline or unlinked configuration; referenced in 1 file(s); no project abstraction detected", algorithm_file_count: 1, recommendation: "Use AES-256 where performance and compatibility allow stronger quantum security margin." },
  { asset_id: "CRYPTO-00003", algorithm: "SHA-1", asset_type: "hash_algorithm", confidence: 85, location: "backend/encryption.py", line: 2, risk_level: "high", risk_score: 75, quantum_vulnerable: false, quantum_classification: "classical-review", mosca_at_risk: true, business_criticality: "medium", crypto_agility_score: 45, crypto_agility_reason: "inline or unlinked configuration; referenced in 1 file(s); no project abstraction detected", algorithm_file_count: 1, recommendation: "Replace SHA-1 with SHA-384 or SHA-512 for security-sensitive use cases." },
  { asset_id: "CRYPTO-00004", algorithm: "MD5", asset_type: "hash_algorithm", confidence: 85, location: "backend/encryption.py", line: 3, risk_level: "critical", risk_score: 80, quantum_vulnerable: false, quantum_classification: "classical-broken", mosca_at_risk: true, business_criticality: "medium", crypto_agility_score: 45, crypto_agility_reason: "inline or unlinked configuration; referenced in 1 file(s); no project abstraction detected", algorithm_file_count: 1, recommendation: "Replace MD5 with SHA-384 or SHA-512; rotate any value whose integrity relied on MD5." },
  { asset_id: "CRYPTO-00005", algorithm: "Hardcoded cryptographic key", asset_type: "key_material", confidence: 90, location: "backend/encryption.py", line: 4, risk_level: "critical", risk_score: 90, quantum_vulnerable: false, quantum_classification: "classical-broken", mosca_at_risk: true, business_criticality: "medium", crypto_agility_score: 45, crypto_agility_reason: "inline or unlinked configuration; referenced in 1 file(s); no project abstraction detected", algorithm_file_count: 1, recommendation: "Move the key to an approved secrets manager, rotate the exposed value, and use envelope encryption with a managed KMS or HSM." },
  { asset_id: "CRYPTO-00006", algorithm: "RSA", asset_type: "asymmetric_algorithm", key_size: 4096, confidence: 85, location: "backend/payments.py", line: 13, risk_level: "critical", risk_score: 80, quantum_vulnerable: true, quantum_classification: "shor-broken", mosca_at_risk: true, business_criticality: "medium", crypto_agility_score: 50, crypto_agility_reason: "configuration-managed; referenced in 3 file(s); no project abstraction detected", algorithm_file_count: 3, recommendation: "Use ML-DSA for signatures or ML-KEM for key establishment; prefer a hybrid migration where compatibility is required." },
  { asset_id: "CRYPTO-00007", algorithm: "ECDSA", asset_type: "asymmetric_algorithm", key_size: 256, confidence: 85, location: "backend/payments.py", line: 14, risk_level: "critical", risk_score: 80, quantum_vulnerable: true, quantum_classification: "shor-broken", mosca_at_risk: true, business_criticality: "medium", crypto_agility_score: 30, crypto_agility_reason: "inline or unlinked configuration; referenced in 1 file(s); no project abstraction detected", algorithm_file_count: 1, recommendation: "Replace with ML-DSA or SLH-DSA for digital signatures." },
  { asset_id: "CRYPTO-00008", algorithm: "AES-256", asset_type: "symmetric_algorithm", mode: "GCM", confidence: 95, location: "backend/payments.py", line: 24, risk_level: "medium", risk_score: 40, quantum_vulnerable: false, quantum_classification: "grover-weakened", mosca_at_risk: true, business_criticality: "medium", crypto_agility_score: 55, crypto_agility_reason: "configuration-managed; referenced in 2 file(s); no project abstraction detected", algorithm_file_count: 2, recommendation: "Retain the asset in the CBOM and review its context, lifetime, and migration path." },
  { asset_id: "CRYPTO-00009", algorithm: "AES-CBC", asset_type: "symmetric_algorithm", mode: "CBC", confidence: 90, location: "backend/payments.py", line: 25, risk_level: "high", risk_score: 65, quantum_vulnerable: false, quantum_classification: "classical-review", mosca_at_risk: true, business_criticality: "medium", crypto_agility_score: 30, crypto_agility_reason: "inline or unlinked configuration; referenced in 1 file(s); no project abstraction detected", algorithm_file_count: 1, recommendation: "Prefer authenticated encryption such as AES-256-GCM and confirm the key size before migration planning." },
  { asset_id: "CRYPTO-00010", algorithm: "SHA-256", asset_type: "hash_algorithm", confidence: 85, location: "backend/payments.py", line: 26, risk_level: "medium", risk_score: 40, quantum_vulnerable: false, quantum_classification: "grover-weakened", mosca_at_risk: true, business_criticality: "medium", crypto_agility_score: 30, crypto_agility_reason: "inline or unlinked configuration; referenced in 1 file(s); no project abstraction detected", algorithm_file_count: 1, recommendation: "Retain the asset in the CBOM and review its context, lifetime, and migration path." },
  { asset_id: "CRYPTO-00011", algorithm: "TLS 1.2", asset_type: "tls_configuration", protocol: "TLS", confidence: 90, location: "infrastructure/tls.yml", line: 2, risk_level: "medium", risk_score: 30, quantum_vulnerable: false, quantum_classification: "classical-review", mosca_at_risk: false, business_criticality: "medium", crypto_agility_score: 30, crypto_agility_reason: "inline or unlinked configuration; referenced in 1 file(s); no project abstraction detected", algorithm_file_count: 1, recommendation: "Prefer TLS 1.3 where supported and keep certificate and cipher policy under review." },
  { asset_id: "CRYPTO-00012", algorithm: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", asset_type: "cipher_suite", protocol: "TLS", confidence: 90, location: "infrastructure/tls.yml", line: 4, risk_level: "medium", risk_score: 35, quantum_vulnerable: false, quantum_classification: "classical-review", mosca_at_risk: false, business_criticality: "medium", crypto_agility_score: 60, crypto_agility_reason: "configuration-managed; referenced in 1 file(s); no project abstraction detected", algorithm_file_count: 1, recommendation: "Review this suite with the deployed certificate and protocol policy; prefer TLS 1.3 suites where possible." },
  { asset_id: "CRYPTO-00013", algorithm: "OpenSSL", asset_type: "crypto_provider", library: "OpenSSL", confidence: 90, location: "infrastructure/tls.yml", line: 5, risk_level: "low", risk_score: 10, quantum_vulnerable: false, quantum_classification: "classical-review", mosca_at_risk: false, business_criticality: "medium", crypto_agility_score: 55, crypto_agility_reason: "configuration-managed; referenced in 2 file(s); no project abstraction detected", algorithm_file_count: 2, recommendation: "Track provider version and supported cryptographic policy in the CBOM." },
  { asset_id: "CRYPTO-00014", algorithm: "cryptography", asset_type: "crypto_dependency", library: "cryptography", confidence: 100, location: "requirements.txt", line: 1, risk_level: "low", risk_score: 10, quantum_vulnerable: false, quantum_classification: "classical-review", mosca_at_risk: false, business_criticality: "medium", crypto_agility_score: 20, crypto_agility_reason: "inline or unlinked configuration; referenced in 3 file(s); no project abstraction detected", algorithm_file_count: 3, recommendation: "Track this cryptographic dependency in the CBOM and review its supported version policy." },
  { asset_id: "CRYPTO-00015", algorithm: "pyopenssl", asset_type: "crypto_dependency", library: "pyopenssl", confidence: 100, location: "requirements.txt", line: 2, risk_level: "low", risk_score: 10, quantum_vulnerable: false, quantum_classification: "classical-review", mosca_at_risk: false, business_criticality: "medium", crypto_agility_score: 30, crypto_agility_reason: "inline or unlinked configuration; referenced in 1 file(s); no project abstraction detected", algorithm_file_count: 1, recommendation: "Track this cryptographic dependency in the CBOM and review its supported version policy." },
];
const riskOrder: Level[] = ["critical", "high", "medium", "low"];
const remediationPreview = (algorithm: string) => {
  if (["RSA", "ECDH", "ECDSA"].includes(algorithm)) return { before: `# Existing ${algorithm} use\nkey = generate_${algorithm.toLowerCase()}_key()`, after: "# Illustrative hybrid migration\nkem = oqs.KeyEncapsulation('ML-KEM-768')\nshared_secret = kem.generate_keypair()" };
  if (["MD5", "SHA-1"].includes(algorithm)) return { before: `digest = ${algorithm.toLowerCase().replace("-", "")} (payload)`, after: "digest = sha512(payload)  # validate compatibility before cutover" };
  if (algorithm.startsWith("AES")) return { before: "cipher = AES-CBC(key, iv)", after: "cipher = AES-256-GCM(key, nonce)  # authenticated encryption" };
  return { before: "# Detected cryptographic configuration", after: "# Apply the documented PQC or hybrid migration plan" };
};
const organisationalUseFor = (algorithm: string, assetType: string) => {
  const normalized = algorithm.toUpperCase();
  if (["RSA", "ECDSA", "ED25519", "ECDH", "DH"].some((name) => normalized.includes(name))) return "Certificates, digital signatures, identity services, or key establishment.";
  if (normalized.startsWith("AES") || normalized.includes("CHACHA")) return "Data-at-rest, service-to-service, backup, or application payload encryption.";
  if (["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"].some((name) => normalized.includes(name))) return "Integrity checks, signatures, artifact validation, or password/token processing depending on context.";
  if (assetType.includes("tls") || assetType.includes("cipher")) return "Transport security between services, clients, gateways, or partner endpoints.";
  if (assetType.includes("certificate")) return "Service identity and trust establishment for internal or external endpoints.";
  return "Cryptographic provider or configuration used by an application or platform component.";
};

function WorkflowCoverage() {
  return <section className="workflow-coverage" aria-label="ECDAT workflow coverage">
    <div className="workflow-heading"><div><p className="eyebrow">Operational workflow</p><h2>From source evidence to migration review</h2></div><small>Read-only analysis. Target code is never executed.</small></div>
    <ol className="workflow-steps">
      <li><b>1. Discover</b><span>Source, dependency manifests, TLS configuration, certificate metadata, and container image references.</span><small>Binary and cloud/HSM connectors are outside this prototype.</small></li>
      <li><b>2. Trace</b><span>Python function and route call chains connect a finding to a detected entry point.</span><small>Other languages currently provide source-level detection only.</small></li>
      <li><b>3. Prioritize</b><span>Algorithm classification plus configured Mosca inputs calculate the review order.</span><small>Scores are planning indicators, not audit findings.</small></li>
      <li><b>4. Recommend</b><span>Rule-based PQC or hybrid options are linked to the detected algorithm.</span><small>Protocol, vendor, and compatibility validation remains required.</small></li>
      <li><b>5. Verify</b><span>A simulation recalculates risk without modifying the source repository.</span><small>Exports are generated from the persisted scan evidence.</small></li>
    </ol>
    <p className="workflow-output"><b>Output</b> Scan-specific CBOM, file-and-line evidence, detected Python call chains, planning inputs, and generated reports.</p>
    <section className="evidence-chain-technique" aria-label="ECDAT evidence-chain method">
      <div className="technique-heading"><div><p className="eyebrow">Why the evidence chain matters</p><h3>Move from a file match to a traceable review path</h3></div><small>Call-chain derivation is available for supported Python analysis.</small></div>
      <div className="evidence-chain-comparison">
        <article><p>File-level detection</p><strong>Algorithm + file + line</strong><span>Useful for inventory, but it does not establish runtime reachability or ownership.</span></article>
        <div className="evidence-arrow" aria-hidden="true">-&gt;</div>
        <article className="evidence-chain-card"><p>ECDAT Python evidence chain</p><strong>Crypto call -&gt; containing function -&gt; callers -&gt; route or CLI entry</strong><span>Impact is derived from parsed call relations. When no entry point is reached, ECDAT reports internal or unresolved exposure instead of inventing a service name.</span></article>
      </div>
      <div className="technique-pill-grid">
        <article><b>Transparent</b><span>File and line evidence, detection confidence, and a call chain where one is found.</span></article>
        <article><b>PQC planning</b><span>Mosca inputs, an HNDL planning signal, and estimated migration difficulty.</span></article>
        <article><b>Actionable output</b><span>CycloneDX CBOM, scan report, and rule-based migration guidance for review.</span></article>
      </div>
    </section>
  </section>;
}

function DiscoveryWorkspace({ assets, filesScanned, scanId }: { assets: Asset[]; filesScanned: number; scanId: string | null }) {
  const categories = [
    { name: "Source cryptography", detail: "Algorithms, key material, and source-level crypto calls.", count: assets.filter((asset) => /algorithm|key_material|hash/i.test(asset.asset_type)).length },
    { name: "Transport and protocols", detail: "TLS configuration and detected cipher-suite evidence.", count: assets.filter((asset) => /tls|cipher|protocol/i.test(asset.asset_type)).length },
    { name: "Certificates", detail: "Public certificate metadata present in the scanned files.", count: assets.filter((asset) => /certificate/i.test(asset.asset_type)).length },
    { name: "Libraries and providers", detail: "Dependency or provider references discovered in the repository.", count: assets.filter((asset) => /dependency|provider|library/i.test(asset.asset_type)).length },
    { name: "Container references", detail: "Container or image references detected in supported manifests.", count: assets.filter((asset) => /container|image/i.test(asset.asset_type)).length },
  ];
  const preview = assets.slice(0, 3).map((asset) => ({ algorithm: asset.algorithm, type: asset.asset_type, evidence: `${asset.location}:${asset.line ?? "?"}` }));
  return <section className="discovery-workspace" aria-label="Discovery and CBOM">
    <div className="discovery-heading"><div><p className="eyebrow">Plan Alpha / Discovery</p><h2>Build a CBOM from observed evidence</h2><p>Every count below is derived from the current read-only scan. A zero means no matching evidence was found, not that the organisation does not use it.</p></div><div className="discovery-stat"><b>{assets.length}</b><span>findings across {filesScanned} files</span></div></div>
    <div className="discovery-flow"><span>Inspect</span><i>-&gt;</i><span>Detect</span><i>-&gt;</i><span>Normalize</span><i>-&gt;</i><span>CBOM</span></div>
    <div className="discovery-cards">{categories.map((category) => <article key={category.name}><p>{category.count ? "Evidence found" : "No evidence found"}</p><strong>{category.name}</strong><b>{category.count}</b><small>{category.detail}</small></article>)}</div>
    <section className="cbom-preview"><div><p className="eyebrow">Generated CBOM preview</p><h3>Scan-specific inventory record</h3><small>Fields shown below come from the current evidence register. No owner, business unit, or deployment claim is invented.</small></div><pre>{JSON.stringify(preview, null, 2)}</pre>{scanId && <div className="cbom-actions"><a href={`${apiUrl}/api/v1/scans/${scanId}/export.cyclonedx.json`}>Export CycloneDX</a><a href={`${apiUrl}/api/v1/scans/${scanId}/export.csv`}>Export CSV</a></div>}</section>
  </section>;
}

function PriorityWorkspace({ assets, matrix, openEvidence }: { assets: Asset[]; matrix: ExposureMatrixItem[]; openEvidence: (asset: Asset) => void }) {
  const ordered = [...assets].sort((left, right) => right.risk_score - left.risk_score);
  const hndlIds = new Set(matrix.filter((item) => item.hndl_candidate).map((item) => item.asset_id));
  return <section className="priority-workspace" aria-label="Prioritized quantum risk">
    <div className="priority-heading"><div><p className="eyebrow">Plan Alpha / Prioritize</p><h2>Rank the findings that need review first</h2><p>Rankings come from the current scan's deterministic risk score. Supporting signals show why a finding is placed in the queue; they are not a security certification.</p></div><div className="priority-summary"><b>{ordered.filter((asset) => asset.risk_level === "critical" || asset.risk_level === "high").length}</b><span>critical or high findings</span></div></div>
    <div className="priority-columns"><section className="priority-list"><div className="priority-list-heading"><b>Review queue</b><span>{ordered.length} current findings</span></div>{ordered.length ? ordered.map((asset) => <button key={asset.asset_id} className="priority-row" onClick={() => openEvidence(asset)}><b>{asset.risk_score}</b><span><strong>{asset.algorithm}</strong><small>{asset.location}:{asset.line ?? "?"}</small></span><em className={asset.risk_level}>{asset.risk_level}</em></button>) : <p className="empty-state">Run a scan to create a prioritized review queue.</p>}</section><section className="priority-method"><p className="eyebrow">Ranking method</p><h3>Signals shown per finding</h3><dl><div><dt>Algorithm status</dt><dd>Quantum classification from the detected primitive.</dd></div><div><dt>Mosca window</dt><dd>Configured data lifetime plus migration time against the threat horizon.</dd></div><div><dt>Evidence confidence</dt><dd>Detection confidence retained with every finding.</dd></div><div><dt>HNDL signal</dt><dd>{hndlIds.size ? `${hndlIds.size} current candidate(s) meet the computed HNDL conditions.` : "No current candidates meet the computed HNDL conditions."}</dd></div></dl><small>Open a finding to inspect its evidence, organisational-use context, and available impact trace.</small></section></div>
  </section>;
}

function App() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [filesScanned, setFilesScanned] = useState(0);
  const [selected, setSelected] = useState<Asset>(demoAssets[0]);
  const [filter, setFilter] = useState<Level | "all">("all");
  const [workspace, setWorkspace] = useState<Workspace>("overview");
  const [inventoryQuery, setInventoryQuery] = useState("");
  const [scanning, setScanning] = useState(false);
  const [target, setTarget] = useState("../demo-enterprise");
  const [source, setSource] = useState("No persisted scan loaded");
  const [notice, setNotice] = useState("Run the bundled sample scan or select an authorized local repository. Results are shown only after a read-only scan completes.");
  const [scanId, setScanId] = useState<string | null>(null);
  const [impact, setImpact] = useState<Impact | null>(null);
  const [loadingImpact, setLoadingImpact] = useState(false);
  const [plan, setPlan] = useState<MigrationTask[] | null>(null);
  const [loadingPlan, setLoadingPlan] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [lifetime, setLifetime] = useState(12);
  const [migrationTime, setMigrationTime] = useState(5);
  const [crqc, setCrqc] = useState(10);
  const [criticality, setCriticality] = useState("medium");
  const [reviewed, setReviewed] = useState<string[]>([]);
  const [queued, setQueued] = useState<string[]>([]);
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [comparison, setComparison] = useState<ScanComparison | null>(null);
  const [loadingComparison, setLoadingComparison] = useState(false);
  const [projection, setProjection] = useState<Projection | null>(null);
  const [simulatedIds, setSimulatedIds] = useState<string[]>([]);
  const [simulatingFix, setSimulatingFix] = useState(false);
  const [moscaScenario, setMoscaScenario] = useState<MoscaScenario | null>(null);
  const [moscaLifetime, setMoscaLifetime] = useState(12);
  const [moscaMigration, setMoscaMigration] = useState(5);
  const [moscaHorizon, setMoscaHorizon] = useState(10);
  const [calculatingMosca, setCalculatingMosca] = useState(false);
  const [matrix, setMatrix] = useState<ExposureMatrixItem[]>([]);
  const summary = useMemo(() => riskOrder.reduce((acc, level) => ({ ...acc, [level]: assets.filter((asset) => asset.risk_level === level).length }), {} as Record<Level, number>), [assets]);
  const readiness = useMemo(() => Math.max(0, Math.round(100 - (assets.filter((asset) => asset.quantum_vulnerable).length / Math.max(assets.length, 1)) * 45 - (assets.filter((asset) => asset.risk_level === "critical").length / Math.max(assets.length, 1)) * 25 - (assets.filter((asset) => asset.risk_level === "high").length / Math.max(assets.length, 1)) * 10 - (assets.filter((asset) => asset.mosca_at_risk).length / Math.max(assets.length, 1)) * 20)), [assets]);
  const visible = assets.filter((asset) =>
    (filter === "all" || asset.risk_level === filter) &&
    `${asset.algorithm} ${asset.asset_type} ${asset.location} ${asset.library ?? ""}`.toLowerCase().includes(inventoryQuery.toLowerCase())
  ).map((asset) => matrix.some((item) => item.asset_id === asset.asset_id && item.hndl_candidate)
    ? { ...asset, asset_type: `${asset.asset_type} | HNDL candidate` }
    : asset
  ).sort((left, right) => right.risk_score - left.risk_score);
  const topPriority = assets.find((asset) => asset.risk_level === "critical") ?? assets[0];
  const isDemoScan = source.includes("demo-enterprise") || source === "Synthetic local demo scan";
  const scanLabel = scanId ? (isDemoScan ? "SYNTHETIC DEMO" : "LOCAL SCAN") : "LOCAL MODE";

  async function runScan(event: FormEvent) {
    event.preventDefault();
    setScanning(true);
    setNotice("Scanning repository and calculating quantum exposure...");
    try {
      const response = await fetch(`${apiUrl}/api/v1/scans`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ path: target, data_lifetime_years: lifetime, migration_time_years: migrationTime, expected_crqc_years: crqc, business_criticality: criticality }) });
      const body = await response.json() as ScanResult | { detail?: string };
      if (!response.ok || !("assets" in body)) throw new Error("detail" in body ? body.detail ?? "Scan failed" : "Scan failed");
      setAssets(body.assets); setFilesScanned(body.files_scanned); setSelected(body.assets[0] ?? demoAssets[0]); setSource(body.scanned_path); setScanId(body.scan_id); setImpact(null); setPlan(null); setReviewed([]); setQueued([]); setProjection(null); setSimulatedIds([]); void loadAssessmentExtensions(body.scan_id);
      setNotice(`${body.files_scanned} files scanned. ${body.assets.length} cryptographic assets found.`);
    } catch (error) {
      setNotice(error instanceof Error ? `${error.message}. Check the local API at ${apiUrl}, then try again.` : `Scan failed. Check the local API at ${apiUrl}, then try again.`);
    } finally { setScanning(false); }
  }

  async function runSampleScan() {
    const sampleTarget = "../demo-enterprise";
    setTarget(sampleTarget);
    setScanning(true);
    setNotice("Scanning the synthetic demo repository...");
    try {
      const response = await fetch(`${apiUrl}/api/v1/scans`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ path: sampleTarget, data_lifetime_years: lifetime, migration_time_years: migrationTime, expected_crqc_years: crqc, business_criticality: criticality }) });
      const body = await response.json() as ScanResult | { detail?: string };
      if (!response.ok || !("assets" in body)) throw new Error("detail" in body ? body.detail ?? "Sample scan failed" : "Sample scan failed");
      setAssets(body.assets); setFilesScanned(body.files_scanned); setSelected(body.assets[0] ?? demoAssets[0]); setSource("Synthetic local demo scan"); setScanId(body.scan_id); setImpact(null); setPlan(null); setReviewed([]); setQueued([]); setProjection(null); setSimulatedIds([]); void loadAssessmentExtensions(body.scan_id);
      setNotice(`Synthetic demo scan complete: ${body.files_scanned} files scanned and ${body.assets.length} cryptographic assets found.`);
    } catch (error) {
      setNotice(error instanceof Error ? `${error.message}. Check the local API at ${apiUrl}, then try again.` : `Sample scan failed. Check the local API at ${apiUrl}, then try again.`);
    } finally { setScanning(false); }
  }

  async function loadAssessmentExtensions(id = scanId) {
    if (!id) return;
    try {
      const matrixResponse = await fetch(`${apiUrl}/api/v1/scans/${id}/exposure-matrix`);
      if (!matrixResponse.ok) throw new Error("Exposure signals are unavailable");
      setMatrix(await matrixResponse.json() as ExposureMatrixItem[]);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Exposure signals failed"); }
  }

  async function loadImpact(assetIdOrEvent?: string | MouseEvent<HTMLButtonElement>) {
    if (!scanId) return;
    const assetId = typeof assetIdOrEvent === "string" ? assetIdOrEvent : selected.asset_id;
    setLoadingImpact(true);
    try {
      const response = await fetch(`${apiUrl}/api/v1/scans/${scanId}/impact/${assetId}`);
      if (!response.ok) throw new Error("Impact analysis is unavailable");
      setImpact(await response.json() as Impact);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Impact analysis failed"); } finally { setLoadingImpact(false); }
  }

  async function loadPlan() {
    if (!scanId) return;
    setLoadingPlan(true);
    try {
      const overrides = moscaScenario && queued.includes(moscaScenario.asset_id) ? [{ asset_id: moscaScenario.asset_id, data_lifetime_years: moscaScenario.data_lifetime_years, migration_time_years: moscaScenario.migration_time_years, expected_crqc_years: moscaScenario.expected_crqc_years }] : [];
      const response = await fetch(`${apiUrl}/api/v1/scans/${scanId}/migration`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ asset_ids: queued, mosca_overrides: overrides }) });
      if (!response.ok) throw new Error("Migration plan is unavailable");
      setPlan(await response.json() as MigrationTask[]);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Migration plan failed"); } finally { setLoadingPlan(false); }
  }

  async function projectMoscaScenario() {
    if (!scanId) return;
    setCalculatingMosca(true);
    try {
      const response = await fetch(`${apiUrl}/api/v1/scans/${scanId}/findings/${selected.asset_id}/mosca-scenario`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ asset_id: selected.asset_id, data_lifetime_years: moscaLifetime, migration_time_years: moscaMigration, expected_crqc_years: moscaHorizon }) });
      if (!response.ok) throw new Error("Mosca scenario is unavailable");
      setMoscaScenario(await response.json() as MoscaScenario);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Mosca scenario failed"); } finally { setCalculatingMosca(false); }
  }

  async function loadHistory() {
    setLoadingHistory(true);
    try {
      const response = await fetch(`${apiUrl}/api/v1/scans`);
      if (!response.ok) throw new Error("Saved scan history is unavailable");
      setHistory(await response.json() as ScanResult[]);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Could not load saved scans"); } finally { setLoadingHistory(false); }
  }

  async function simulateFix(assetId = topPriority?.asset_id) {
    if (!scanId || !assetId || simulatedIds.includes(assetId)) return;
    setSimulatingFix(true);
    try {
      const response = await fetch(`${apiUrl}/api/v1/scans/${scanId}/findings/${assetId}/simulate-fix`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ fixed_asset_ids: simulatedIds }) });
      if (!response.ok) throw new Error("Remediation projection is unavailable");
      const body = await response.json() as Projection;
      setProjection(body); setSimulatedIds(body.simulated_asset_ids);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Remediation projection failed"); } finally { setSimulatingFix(false); }
  }

  function reopenScan(scan: ScanResult) {
    setAssets(scan.assets); setFilesScanned(scan.files_scanned); setSelected(scan.assets[0] ?? demoAssets[0]); setScanId(scan.scan_id); setSource(scan.scanned_path); setPlan(null); setImpact(null); setComparison(null); setReviewed([]); setQueued([]); setProjection(null); setSimulatedIds([]); setNotice(`Reopened saved scan from ${new Date(scan.created_at).toLocaleString()}.`);
  }

  async function compareWith(scan: ScanResult) {
    if (!scanId || scan.scan_id === scanId) return;
    setLoadingComparison(true);
    try {
      const response = await fetch(`${apiUrl}/api/v1/scans/${scanId}/compare?baseline_scan_id=${encodeURIComponent(scan.scan_id)}`);
      if (!response.ok) throw new Error("Scan comparison is unavailable");
      setComparison(await response.json() as ScanComparison);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Could not compare scans"); } finally { setLoadingComparison(false); }
  }

  function toggleReviewed() { setReviewed((items) => items.includes(selected.asset_id) ? items.filter((id) => id !== selected.asset_id) : [...items, selected.asset_id]); }
  function toggleQueued() { setQueued((items) => items.includes(selected.asset_id) ? items.filter((id) => id !== selected.asset_id) : [...items, selected.asset_id]); }

  return <main className={`${scanId ? "has-scan" : "awaiting-scan"} ${workspace === "workflow" ? "workflow-active" : ""} ${workspace === "discovery" ? "discovery-active" : ""} ${workspace === "prioritize" ? "priority-active" : ""}`}>
    <header className="topbar"><div className="brand"><span className="brand-mark">E</span><span>ECDAT</span><small>Local cryptographic analysis prototype</small></div><div className="session"><span className="status-dot" /> {scanLabel} <span className="session-divider" /> {source}</div><button className="workflow-entry" onClick={() => setWorkspace("workflow")}><Network size={15} />Workflow</button></header>
    {workspace === "workflow" && <WorkflowCoverage />}
    <nav className="workspace-nav" aria-label="ECDAT workspace"><button className={workspace === "overview" ? "active" : ""} onClick={() => setWorkspace("overview")}><LayoutDashboard size={15} />Assessment</button><button className={workspace === "discovery" ? "active" : ""} onClick={() => setWorkspace("discovery")}><FileSearch size={15} />Discovery</button><button className={workspace === "prioritize" ? "active" : ""} onClick={() => setWorkspace("prioritize")}><ShieldAlert size={15} />Prioritize</button><button className={workspace === "inventory" ? "active" : ""} onClick={() => setWorkspace("inventory")}><FileSearch size={15} />Evidence</button><button className={workspace === "migration" ? "active" : ""} onClick={() => setWorkspace("migration")}><ListChecks size={15} />Migration</button><button className={workspace === "demo" ? "active" : ""} onClick={() => setWorkspace("demo")}><PlayCircle size={15} />Guided demo</button>{scanId && <div className="export-actions"><a href={`${apiUrl}/api/v1/scans/${scanId}/executive-brief`} target="_blank" rel="noreferrer"><Download size={14} />Executive brief</a><a href={`${apiUrl}/api/v1/scans/${scanId}/export.csv`}><Download size={14} />CBOM CSV</a><a href={`${apiUrl}/api/v1/scans/${scanId}/export.cyclonedx.json`}><Download size={14} />Export CBOM</a><a href={`${apiUrl}/api/v1/scans/${scanId}/export.json`}><Download size={14} />JSON</a></div>}</nav>
    {workspace === "discovery" && <DiscoveryWorkspace assets={assets} filesScanned={filesScanned} scanId={scanId} />}
    {workspace === "prioritize" && <PriorityWorkspace assets={assets} matrix={matrix} openEvidence={(asset) => { setSelected(asset); setImpact(null); setWorkspace("inventory"); }} />}
    <section className="masthead"><div><p className="eyebrow">SIH 2026 | NTRO | Problem Statement 26164</p><h1>ECDAT Prototype</h1><p className="masthead-note">Read-only discovery and risk-analysis outputs for an authorized local repository.</p></div><form className="scan-control" onSubmit={runScan}><div className="scan-heading"><label htmlFor="scan-target">Local scan target</label><button type="button" className="settings-button" title="Edit risk assumptions" aria-label="Edit risk assumptions" onClick={() => setProfileOpen(!profileOpen)}><SlidersHorizontal size={16} /></button></div><input id="scan-target" value={target} onChange={(event) => setTarget(event.target.value)} aria-label="Local scan target" /><div className="scan-actions"><button type="button" className="sample-button" disabled={scanning} onClick={() => void runSampleScan()}>{scanning ? "Scanning sample..." : "Run sample scan"}</button><button disabled={scanning}>{scanning ? "Scanning assets..." : "Run local scan"}<ArrowUpRight size={16} /></button></div><p className={`scan-feedback ${scanning ? "working" : ""}`}>{notice}</p>{profileOpen && <div className="risk-profile"><b>Risk assumptions</b><label>Data lifetime <input type="number" min="1" value={lifetime} onChange={(event) => setLifetime(Number(event.target.value))} /> years</label><label>Migration time <input type="number" min="1" value={migrationTime} onChange={(event) => setMigrationTime(Number(event.target.value))} /> years</label><label>CRQC horizon <input type="number" min="1" value={crqc} onChange={(event) => setCrqc(Number(event.target.value))} /> years</label><label className="criticality-field">Business criticality <select value={criticality} onChange={(event) => setCriticality(event.target.value)}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="mission_critical">Mission critical</option></select></label></div>}</form></section>
    {workspace !== "migration" && workspace !== "demo" && <section className="overview" aria-label="Scan overview"><div className="signal"><span>Quantum-risk indicator</span><QuantumReadinessGauge score={readiness} /><p>Prototype score derived from severity, criticality and Mosca inputs.</p></div><div className="risk-strip"><SeverityStack counts={summary} /><div className="risk-fallback" aria-label="Severity details">{riskOrder.map((level) => <button className={`risk-token ${level} ${filter === level ? "active" : ""}`} key={level} onClick={() => { setFilter(filter === level ? "all" : level); setWorkspace("inventory"); }}><span>{level}</span><b>{summary[level]}</b></button>)}</div></div><div className="mosca"><ShieldAlert size={20} /><div><b>{assets.filter((asset) => asset.mosca_at_risk).length} assets need a Mosca review.</b><MoscaTimeline lifetimeYears={lifetime} migrationYears={migrationTime} horizonYears={crqc} /></div>{scanId && <a className="report-link" href={`${apiUrl}/api/v1/scans/${scanId}/report`} target="_blank" rel="noreferrer"><Download size={15} /> Read report</a>}</div></section>}
    {workspace === "overview" && <section className="decision-brief"><div className="brief-heading"><div><p className="eyebrow">Scan summary</p><h2>Observed outputs from the selected repository</h2></div><span>{isDemoScan ? "Synthetic demo results are clearly labeled" : "Results came from the current local scan"}</span></div><div className="decision-grid"><article><span className="step-number">01</span><h3>Discover</h3><p><b>{assets.length} cryptographic assets</b> were identified in source code, libraries, TLS configuration, certificates, and deployment references.</p><button className="text-action" onClick={() => setWorkspace("inventory")}>View findings</button></article><article><span className="step-number">02</span><h3>Classify</h3><p><b>{summary.critical} critical findings</b> are scored with configured lifetime, migration-time, and criticality inputs.</p><button className="text-action" onClick={() => { setFilter("critical"); setWorkspace("inventory"); }}>View critical findings</button></article><article className="recommendation-card"><span className="step-number">03</span><h3>Review</h3><p><b>{topPriority?.algorithm ?? "No finding selected"}</b> is the current highest-risk finding. {topPriority?.recommendation}</p><button className="text-action" onClick={() => { if (topPriority) setSelected(topPriority); setWorkspace("migration"); }}>Open review queue</button></article></div></section>}
    {workspace === "demo" && <section className="demo-guide"><div><p className="eyebrow">Prototype walkthrough</p><h2>Local synthetic scan walkthrough</h2><p>Use the bundled repository to inspect the scanner outputs. It is a demonstration dataset, not an organization assessment.</p></div><section className="manual-contrast"><div><b>Input</b><span>Synthetic local source and configuration files</span><small>Read-only analysis · no code execution · no external upload</small></div><strong>→</strong><div><b>Output</b><span>Findings, route trace, score, and generated reports</span><small>All remediation and effort values are planning simulations</small></div></section><ol><li><span>1</span><div><b>Run the sample scan</b><p>Use the local synthetic repository. ECDAT reads files and does not execute target code.</p></div><button onClick={() => setWorkspace("overview")}>Open scan</button></li><li><span>2</span><div><b>View findings</b><p>Filter critical results and open source-linked algorithm, key-material, or configuration evidence.</p></div><button onClick={() => { setFilter("critical"); setWorkspace("inventory"); }}>View findings</button></li><li><span>3</span><div><b>View the static trace</b><p>Open the selected finding to inspect any detected Python call chain and route context.</p></div><button disabled={!scanId} onClick={() => { if (topPriority) { setSelected(topPriority); setWorkspace("inventory"); void loadImpact(topPriority.asset_id); } }}>View trace</button></li><li><span>4</span><div><b>Open the review queue</b><p>Mark a finding reviewed, add it to migration, then generate the scoped sample roadmap.</p></div><button onClick={() => { if (topPriority) setSelected(topPriority); setWorkspace("inventory"); }}>Open queue</button></li><li><span>5</span><div><b>Preview a simulated change</b><p>Compare projected score and severity after a simulated remediation. No source file is changed.</p></div><button disabled={!scanId || !topPriority || simulatedIds.includes(topPriority.asset_id) || simulatingFix} onClick={() => void simulateFix()}>{simulatingFix ? "Calculating..." : simulatedIds.includes(topPriority?.asset_id ?? "") ? "Simulation shown" : "Run simulation"}</button></li><li><span>6</span><div><b>Open the generated report</b><p>The report records scan findings and planning outputs from this synthetic run.</p></div>{scanId ? <a href={`${apiUrl}/api/v1/scans/${scanId}/executive-brief`} target="_blank" rel="noreferrer">Open generated report</a> : <button disabled>Run sample scan first</button>}</li>{projection && <li className="confidence-result"><span><Check size={15} /></span><div><b>Projected indicator {projection.current_readiness} → {projection.projected_readiness}</b><p>Critical {projection.current_risk_summary.critical} → {projection.projected_risk_summary.critical} · High {projection.current_risk_summary.high} → {projection.projected_risk_summary.high}</p><small>{projection.disclaimer}</small></div></li>}</ol></section>}
    {workspace !== "migration" && <section className="workbench"><div className="assets-panel"><div className="panel-heading"><div><p className="eyebrow">Evidence register</p><h2>Detected assets <span>{visible.length} of {assets.length}</span></h2></div><FileSearch size={19} /></div><div className="inventory-search"><label htmlFor="asset-search">Filter</label><input id="asset-search" value={inventoryQuery} onChange={(event) => setInventoryQuery(event.target.value)} placeholder="Algorithm, library, location" /></div><div className="table-head"><span>Finding</span><span>Evidence & risk</span><span>State</span></div><div className="asset-list">{visible.length ? visible.map((asset) => <button className={`asset-row ${selected.asset_id === asset.asset_id ? "selected" : ""}`} key={asset.asset_id} onClick={() => { setSelected(asset); setImpact(null); }}><span className="finding-name"><i className="severity-dot" style={{ backgroundColor: severityColors[asset.risk_level] }} /><span><b>{asset.algorithm}</b><small>{asset.asset_type.replaceAll("_", " ")}</small></span></span><span className="asset-evidence"><code>{asset.location}:{asset.line ?? "?"}</code><RiskScoreBar score={asset.risk_score} /></span><span className="row-status"><em className={asset.risk_level}>{asset.risk_level}</em>{reviewed.includes(asset.asset_id) && <Check size={14} />}</span></button>) : <p className="empty-state">No cryptographic assets match this filter.</p>}</div></div><aside className="detail-panel"><p className="eyebrow">Finding brief <span>{selected.asset_id}</span></p><h2>{selected.algorithm}</h2><div className="score"><span>Risk score</span><b>{selected.risk_score}<small>/100</small></b><RiskScoreBar score={selected.risk_score} /></div><dl><div><dt>Quantum status</dt><dd>{selected.quantum_vulnerable ? "Public-key vulnerable" : "Security margin reduced"}</dd></div><div><dt>Quantum classification</dt><dd>{(selected.quantum_classification ?? "classical-review").replaceAll("-", " ")}</dd></div><div><dt>Mosca assessment</dt><dd>{selected.mosca_at_risk ? "Migration window at risk" : "Within horizon"}</dd></div><div><dt>CBOM context</dt><dd>{[selected.key_size && `${selected.key_size}-bit`, selected.mode, selected.library, selected.protocol].filter(Boolean).join(" · ") || "Algorithm evidence"}</dd></div><div><dt>Detection confidence</dt><dd>{selected.confidence ?? 85}%</dd></div><div><dt>Evidence</dt><dd><code>{selected.location}:{selected.line ?? "?"}</code></dd></div></dl><div className="org-context"><p>Typical organisational use</p><strong>{organisationalUseFor(selected.algorithm, selected.asset_type)}</strong><small>Context inferred from the algorithm family. Confirm the actual data flow and owner with the organisation.</small></div><div className="review-actions"><button className={reviewed.includes(selected.asset_id) ? "impact-button reviewed" : "impact-button"} onClick={toggleReviewed}><Check size={16} />{reviewed.includes(selected.asset_id) ? "Reviewed" : "Mark reviewed"}</button><button className={queued.includes(selected.asset_id) ? "queue-button queued" : "queue-button"} onClick={toggleQueued}>{queued.includes(selected.asset_id) ? "Queued" : "Add to migration"}</button></div>{scanId && <button className="impact-button" onClick={loadImpact} disabled={loadingImpact}><Network size={16} />{loadingImpact ? "Mapping impact..." : "Assess blast radius"}</button>}{impact && <div className="impact"><p>Impact analysis <span>{impact.source.replaceAll("_", " ")}</span></p><strong>{impact.applications.join(", ")}</strong><small>{impact.business_units.join(" · ")} / {impact.services.join(" · ")}</small><div className="impact-metrics"><b>HNDL {impact.hndl_score}<small>/100</small></b><b>{impact.exposure}<small>exposure</small></b><b>{impact.migration_difficulty}<small>migration effort</small></b></div><small>{impact.migration_factors.join(" · ")}</small><p className="impact-rationale">{impact.rationale}</p><div className="standards">{impact.standards.map((standard) => <a key={standard} href={standard.includes("203") ? "https://csrc.nist.gov/pubs/fips/203/final" : standard.includes("204") ? "https://csrc.nist.gov/pubs/fips/204/final" : standard.includes("205") ? "https://csrc.nist.gov/pubs/fips/205/final" : standard.includes("800-57") ? "https://csrc.nist.gov/pubs/sp/800/57/r5/final" : "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"} target="_blank" rel="noreferrer">{standard}</a>)}</div></div>}<div className="recommendation"><Sparkles size={18} /><div><p>Migration recommendation</p><strong>{selected.recommendation}</strong></div></div></aside></section>}
    {workspace !== "migration" && <section className="mosca-scenario"><div><p className="eyebrow">Per-finding Mosca what-if</p><h2>Test the migration window for {selected.algorithm}</h2><small>Uses the existing risk formula. It changes only this projected scenario, never the source or saved scan.</small></div><div className="mosca-inputs"><label>Data lifetime <input type="number" min="0" value={moscaLifetime} onChange={(event) => setMoscaLifetime(Number(event.target.value))} /> years</label><label>Migration time <input type="number" min="0" value={moscaMigration} onChange={(event) => setMoscaMigration(Number(event.target.value))} /> years</label><label>Threat horizon <input type="number" min="1" value={moscaHorizon} onChange={(event) => setMoscaHorizon(Number(event.target.value))} /> years</label></div><button className="impact-button" onClick={() => void projectMoscaScenario()} disabled={!scanId || calculatingMosca}>{calculatingMosca ? "Calculating..." : "Calculate scenario"}</button>{!scanId && <small className="scenario-note">Run a live assessment to calculate a per-finding scenario.</small>}{moscaScenario?.asset_id === selected.asset_id && <p className="mosca-result">Projected: <b>{moscaScenario.projected_asset.risk_score}/100 {moscaScenario.projected_asset.risk_level}</b> | {moscaScenario.projected_asset.mosca_at_risk ? "Mosca window at risk" : "Within Mosca horizon"}</p>}</section>}
    {workspace === "migration" && <section className="migration-panel"><div className="migration-heading"><div><p className="eyebrow">Migration review</p><h2>Review queue <span>{queued.length} staged</span></h2><span>Stage selected findings to generate a sample planning roadmap.</span></div><div className="migration-controls"><button className="impact-button" onClick={loadHistory} disabled={loadingHistory}><History size={16} />{loadingHistory ? "Loading..." : "Saved scans"}</button>{scanId && <button className="impact-button" onClick={loadPlan} disabled={loadingPlan || !queued.length}><ListChecks size={16} />{loadingPlan ? "Building roadmap..." : "Build sample roadmap"}</button>}</div></div>{history.length > 0 && <div className="scan-history"><p className="eyebrow">Saved scan history</p>{history.slice(0, 4).map((scan) => <article key={scan.scan_id}><span>{new Date(scan.created_at).toLocaleString()}</span><b>{scan.assets.length} assets</b><small>{scan.risk_summary.critical ?? 0} critical · {scan.scanned_path}</small><div><button onClick={() => reopenScan(scan)}>Open</button>{scanId && scan.scan_id !== scanId && <button onClick={() => compareWith(scan)}>{loadingComparison ? "Comparing..." : "Compare"}</button>}</div></article>)}</div>}{comparison && <section className="comparison-strip"><p className="eyebrow">Comparison against saved baseline</p><div><b>{comparison.new_assets.length}<small>new findings</small></b><b>{comparison.resolved_assets.length}<small>resolved</small></b><b>{comparison.changed_assets.length}<small>risk changes</small></b><b>{comparison.unchanged_count}<small>unchanged</small></b></div></section>}{queued.length ? <div className="local-queue">{assets.filter((asset) => queued.includes(asset.asset_id)).map((asset) => <article key={asset.asset_id}><em className={asset.risk_level}>{asset.risk_level}</em><div><strong>{asset.algorithm} <small>{asset.asset_id}</small></strong><p>{asset.location} · {asset.recommendation}</p></div><button className="text-action" onClick={() => setQueued((items) => items.filter((id) => id !== asset.asset_id))}>Remove</button></article>)}</div> : <p className="empty-state">No findings are staged. Open evidence, validate the finding, then add it to the review queue.</p>}{plan && <div className="migration-list">{plan.map((task) => <article key={task.asset_id}><b className={`priority ${task.priority.toLowerCase()}`}>{task.priority}</b><div><strong>{task.algorithm} <small>{task.asset_id}</small></strong><p>{task.target}</p><dl className="decision-options"><div><dt>Pure PQC</dt><dd>{task.pure_pqc_option}</dd></div><div><dt>Hybrid</dt><dd>{task.hybrid_option}</dd></div><div><dt>Tradeoff</dt><dd>{task.tradeoffs}</dd></div><div><dt>Dependencies</dt><dd>{task.dependency_notes.join(" · ")}</dd></div></dl></div><span>{task.planning_window}<small>{task.estimated_effort} effort</small></span></article>)}</div>}</section>}
    {impact && impact.call_chains.length > 0 && <section className="call-chains"><b>Call chain evidence</b>{impact.call_chains.map((chain, index) => <code key={index}>{chain.join("  →  ")}</code>)}</section>}
    {workspace === "overview" && <section className="remediation-preview"><p className="eyebrow">Illustrative remediation preview</p><h2>{selected.algorithm} migration pattern</h2><small>Example only: validate library availability, protocol compatibility, and tests before making a source change.</small><div><pre><b>Before</b>{remediationPreview(selected.algorithm).before}</pre><pre><b>After</b>{remediationPreview(selected.algorithm).after}</pre></div></section>}
    {workspace === "demo" && <section className="demo-payoff"><p className="eyebrow">Prototype outputs</p><h2>Files and calculations from the sample run</h2><div className="payoff-grid"><article><b>1. Findings</b><span>File, line, algorithm, and detection context from the local scan.</span></article><article><b>2. Risk inputs</b><span>Mosca inputs and static-analysis output where they are detected.</span></article><article><b>3. Simulation</b><span>A projected result using the current risk formula; no repository change is made.</span></article><article><b>4. Reports</b><span>Generated CBOM and summary files for the synthetic scan record.</span></article></div>{scanId ? <a className="executive-payoff" href={`${apiUrl}/api/v1/scans/${scanId}/executive-summary`} target="_blank" rel="noreferrer"><Download size={16} />Open generated summary</a> : <p className="empty-state">Run the sample scan first. Reports are available only for a persisted scan.</p>}</section>}
  </main>;
}
createRoot(document.getElementById("root")!).render(<App />);
