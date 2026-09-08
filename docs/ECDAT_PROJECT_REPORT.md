# ECDAT Project Report

**Enterprise Cryptographic Discovery & Analysis Tool**  
**SIH 2026 | Problem Statement 26164 | NTRO**  
**Team CipherX**

## 1. Executive Summary

Organisations cannot plan post-quantum migration from an algorithm list alone. They need to know where cryptography is used, which code paths can reach it, what data lifetime and migration constraints apply, and what evidence supports each decision.

ECDAT is a local-first, read-only prototype that turns an authorised repository scan into a persistent Cryptography Bill of Materials (CBOM), explainable risk indicators, impact evidence, migration guidance, and exportable reports. The prototype is designed to demonstrate a complete decision path without pretending that simulated remediation changed production code.

## 2. Problem Alignment

| NTRO requirement | ECDAT response |
| --- | --- |
| Discover cryptographic artefacts | Scans supported source files, dependency manifests, TLS/configuration references, certificates, and container references. |
| Catalogue evidence | Stores algorithm, type, location, line, confidence, severity, classification, and recommendation. |
| Assess quantum risk | Uses algorithm classification, severity, criticality, HNDL planning signals, and configurable Mosca inputs. |
| Recommend alternatives | Provides deterministic PQC or hybrid guidance for supported algorithm families. |
| Produce standard output | Exports JSON, CSV, Markdown, executive brief, and CycloneDX 1.6 CBOM. |
| Provide an interactive interface | Assessment, Evidence, Migration, Guided demo, and Workflow workspaces. |

## 3. Product Workflow

```text
Discover -> Trace -> Prioritise -> Recommend -> Prove
```

1. **Discover:** Read approved repository content without executing target code.
2. **Trace:** Attach a finding to its containing Python function and trace actual callers toward a route or CLI entry point where parser support exists.
3. **Prioritise:** Calculate deterministic risk indicators using algorithm weakness, severity, criticality, exposure, and Mosca-style planning inputs.
4. **Recommend:** Show a rule-based PQC or hybrid migration direction with compatibility caveats.
5. **Prove:** Simulate remediation, recalculate the projected score, and export the evidence. Source files remain unchanged.

## 4. Technical Architecture

```text
Authorised local repository / synthetic demo
              |
              v
     Python discovery and AST analysis
              |
              +--> evidence register and CBOM
              +--> risk, Mosca and HNDL indicators
              +--> Python impact call chains
              +--> migration and simulation projections
              |
              v
          FastAPI API
              |
              v
          React + Vite UI
```

The backend persists scan records in SQLite. The frontend consumes the API and keeps the core demonstration usable in local/offline mode. Ports and CORS are configured from the root environment configuration rather than per-session hardcoding.

## 5. Evidence and Impact Method

A file-level match answers **what** and **where**. ECDAT adds **why it matters** only when the source structure supports that conclusion:

```text
crypto call -> containing function -> callers -> route or CLI entry point
```

Python findings use AST-derived function and call relations, with a bounded reverse traversal. If no entry point is reached, the finding is reported as internal or unresolved rather than assigned a fabricated business service. Other supported languages currently provide source-level detection and are labelled accordingly.

## 6. Risk and Migration Model

The risk engine is deterministic and inspectable. It uses an algorithm risk lookup (for example, Shor-broken public-key families, Grover-weakened symmetric/hash margins, and PQC-ready classifications) together with severity and contextual inputs.

Mosca planning is represented as:

```text
data lifetime + migration time > expected CRQC horizon
```

The CRQC horizon is a configurable planning assumption, not a prediction of when a quantum computer will arrive. HNDL and migration-effort values are planning indicators and should be validated against an organisation's data classification and architecture.

## 7. Demonstration Outputs

- Evidence Register with file-and-line findings
- Finding detail with quantum classification and recommendation
- Python impact trace and rationale
- Exposure/severity prioritisation views
- Simulated remediation confidence loop
- CycloneDX CBOM, JSON, CSV, Markdown, and executive report exports

The bundled `demo-enterprise` repository is synthetic and visibly labelled as demo data. An independent fixture repository is used to verify that impact names and call chains are derived from its own structure rather than copied from the demo.

## 8. Security and Trust Boundaries

- Target code is read as text and is never executed by the scanner.
- Private-key material is not collected as an inventory artefact.
- Simulation does not mutate source files.
- Results are decision-support evidence, not a security certification.
- Live or external repository scanning requires explicit authorisation and an approved isolation boundary.

## 9. Current Scope and Honest Limitations

Implemented prototype scope includes local source/configuration discovery, Python call-graph impact mapping, deterministic risk planning, and report exports. JavaScript/TypeScript/Java discovery is source-pattern based rather than full function-level call-graph analysis. Binary, cloud, HSM, and live infrastructure connectors are extension points, not completed capabilities. Recommendations are rule-based and require protocol, vendor, performance, and interoperability validation before deployment.

## 10. Validation Plan

```powershell
\.backend\.venv\Scripts\python.exe -m pytest backend\tests -q
cd frontend
npm run build
```

For the live walkthrough, run the sample scan, inspect the top finding, open its evidence trace, review the migration recommendation, run the confidence simulation, and export the CBOM and executive brief. Repeat the scan against the independent fixture to demonstrate generic impact mapping.

## 11. Team

- Shaik Rehan
- Rangareddygari Yasashwini
- Lahari K.
- Yathiraju Shanmukha Lakshmi Vibhav Simha
- Yesheshwan
- Karthikeya Vyaschand

