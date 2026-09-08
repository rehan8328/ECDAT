# ECDAT

**Enterprise Cryptographic Discovery & Analysis Tool**

ECDAT is a local-first cryptographic assurance workspace for discovering cryptographic assets in source repositories, assessing quantum-era exposure, and planning evidence-backed Post-Quantum Cryptography (PQC) migration.

Built for **Smart India Hackathon 2026**, Problem Statement **26164** for NTRO.

## Problem Alignment

ECDAT addresses the NTRO requirement to discover and catalogue cryptographic artefacts across applications and infrastructure, assess quantum risk, classify artefacts by lifetime and business criticality, and recommend viable PQC or hybrid replacements.

| SIH requirement | ECDAT implementation |
| --- | --- |
| Discover cryptographic artefacts | Read-only source, configuration, certificate, dependency, and container-reference scanning with file-and-line evidence. |
| Produce a CBOM | JSON, CSV, executive brief, and CycloneDX 1.6 CBOM exports. |
| Assess quantum exposure | Algorithm classification, risk score, business criticality, and configurable Mosca calculation: `X + Y > Z`. |
| Suggest replacements | Pure-PQC and hybrid options with effort, compatibility, latency/cost tradeoffs, and dependencies. |
| Interactive visualisation | Assessment, Evidence, Migration, and Guided Demo workspaces with a simulated remediation confidence loop. |

## Why ECDAT

Traditional cryptographic reviews are manual, expensive, and quickly become stale. ECDAT turns discovery into an auditable workflow:

1. **Discover** cryptographic algorithms, protocols, libraries, certificates, and configuration evidence.
2. **Prioritize** findings with severity, business criticality, confidence, and Mosca-style quantum exposure analysis.
3. **Explain impact** through static-analysis call paths instead of untraceable business labels.
4. **Recommend migration** options such as ML-KEM, ML-DSA, hybrid TLS, and stronger symmetric configurations.
5. **Demonstrate confidence** by simulating remediation and projecting the improved quantum-readiness score without changing source code.

## Capabilities

- Cryptographic Bill of Materials (CBOM) generation for source repositories
- Evidence register with file, line, detection confidence, and risk context
- Quantum-readiness score and Mosca migration-window assessment
- Function-level call-graph impact mapping for Python code
- Migration plan with implementation guidance and priority ordering
- Guided demo journey: Discover -> Prioritize -> Recommend -> Confidence
- JSON, CSV, Markdown executive brief, and CycloneDX 1.6 CBOM exports
- Local-only operation: source files are read for analysis and are never executed

## Architecture

```text
Repository / demo inventory
          |
          v
  Python discovery engine
          |
          +--> CBOM + evidence + risk scoring + impact analysis
          |
          v
  FastAPI assessment API
          |
          v
React + Vite operator workspace
```

## Quick Start

### Prerequisites

- Python 3.11 or later
- Node.js 20 or later
- npm

### 1. Configure local ports

The root [`.env`](./.env) is the single source of truth for the frontend and API addresses.

```dotenv
FRONTEND_PORT=5174
API_PORT=8001
API_BASE_URL=http://127.0.0.1:8001
```

### 2. Install dependencies

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

cd ..\frontend
npm install
```

### 3. Start ECDAT

Open two PowerShell terminals at the project root.

```powershell
.\scripts\start-api.ps1
```

```powershell
.\scripts\start-frontend.ps1
```

Open [http://127.0.0.1:5174](http://127.0.0.1:5174). The API health endpoint is available at [http://127.0.0.1:8001/health](http://127.0.0.1:8001/health).

### Containerized demo deployment

For a repeatable hackathon demonstration, run the local-first deployment with Docker Desktop:

```powershell
docker compose up --build
```

Open [http://127.0.0.1:5174](http://127.0.0.1:5174), then select **Run sample scan**. The browser talks only to the local web container; the API scans the bundled synthetic repository through a read-only mount. Stop the demonstration with `docker compose down`.

This compose deployment is deliberately local-first. Do not expose the scanner publicly or mount an organization repository without explicit authorization and an approved isolation boundary.

## Demo Workflow

Use the bundled `demo-enterprise` inventory to present the product flow:

1. Select **Run sample scan** to create a persisted assessment from the synthetic local target.
2. Open evidence for the top cryptographic finding.
3. Review the impact chain and migration recommendation.
4. Simulate remediation in the Confidence step.
5. Export the executive brief or CycloneDX CBOM for stakeholders.

The demo data is explicitly labelled as synthetic. This keeps the distinction between a walkthrough and a real repository assessment clear.

## Quality Checks

```powershell
# Backend tests
.\backend\.venv\Scripts\python.exe -m pytest backend\tests -q

# Production frontend build
cd frontend
npm run build
```

## Repository Structure

```text
backend/             FastAPI service, discovery engine, risk and export modules
frontend/            React assessment workspace
demo-enterprise/     Synthetic inventory for demonstrations
impact-fixtures/     Independent fixtures for impact-mapping tests
docs/                Demo script and supporting material
scripts/             Local startup scripts
```

## Team CipherX

- Shaik Rehan
- Rangareddygari Yasashwini
- Lahari K.
- Yathiraju Shanmukha Lakshmi Vibhav Simha
- Yesheshwan
- Karthikeya Vyaschand

## Security Note

ECDAT is a discovery and decision-support tool. It does not execute scanned code, apply code changes, or claim that a simulated remediation has been deployed. Migration recommendations should be validated against the organisation's architecture, interoperability requirements, and security policy.
