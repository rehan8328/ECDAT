# SIH 2026 Problem Statement 26164: ECDAT Solution

**Organization:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity  
**Category:** Software

## Problem Interpretation

Post-quantum migration cannot begin with an algorithm replacement list. An
enterprise first needs an evidence-backed inventory of where cryptography is
used, what protects sensitive data, who depends on it, and which systems need
to move before a cryptographically relevant quantum computer can compromise
long-lived data.

ECDAT is an offline-capable enterprise cryptographic intelligence platform. It
converts discovery evidence into a persistent Cryptography Bill of Materials
(CBOM), explains quantum and classical risk, and generates a defensible
migration roadmap.

## Exact Solution

### Discover

ECDAT scans approved local repositories, and optionally public GitHub repository URLs, without executing scanned content. Its
modular discovery engine identifies Python, JavaScript/TypeScript and Java source-code algorithms, key sizes, modes
and API evidence; Python and JavaScript cryptographic dependencies and versions; TLS versions,
cipher suites and crypto providers; and PEM certificate public metadata.

Private-key material is explicitly rejected. Binary, container, cloud and HSM
connectors are extension points, not capabilities we falsely claim today.

### Catalogue: CBOM

Every finding is saved in an offline SQLite CBOM with standardized fields:
asset type, algorithm, key size, mode, protocol, library, version, confidence,
risk, recommendation, and line-level evidence. The CBOM is searchable and
exportable in JSON, CSV, Markdown and CycloneDX 1.6.

### Assess Quantum Risk

ECDAT uses a deterministic, explainable risk engine. It considers algorithm
family, quantum exposure, deprecated primitives, severity and the Mosca
condition:

`data lifetime + migration time > expected CRQC horizon`

The CRQC horizon is an explicit configurable planning assumption, never a
claim about an exact quantum-computer arrival date. At-risk assets contribute
to the Quantum Readiness Score.

### Recommend and Migrate

ECDAT maps findings to PQC or hybrid guidance while preserving the distinction
between signing and key establishment. RSA is classified by usage before
recommending ML-DSA or ML-KEM. The migration planner assigns P0-P3 priority and
planning windows based on deterministic risk. Ownership remains `Unassigned`
until verified enterprise data is connected.

### Explain Business Impact

`What Breaks?` maps technical assets to business units, applications, services,
dependencies and certificates. The demo is clearly labeled as a synthetic
synthetic repository mapping; a future deployment would use verified CMDB and inventory data.

## Interactive GUI

ECDAT provides an executive overview, searchable inventory, evidence drill-down,
live scan, function-level impact analysis, exposure-by-severity matrix, HNDL candidate indicators,
per-finding Mosca scenarios, migration workspace and persisted exports.

## Requirement Evidence

| Requirement | ECDAT implementation |
| --- | --- |
| Source repository scanning | Implemented, safe local text scanning |
| Algorithms, keys, modes, protocols, libraries, versions | Implemented for supported discovery sources |
| Certificate catalogue | Implemented for public PEM metadata; no private-key exposure |
| Quantum risk and Mosca analysis | Implemented, deterministic and configurable |
| PQC/hybrid recommendations | Implemented for supported algorithm families |
| Standardized CBOM report | Implemented: SQLite, CSV, JSON, Markdown |
| Interactive GUI | Implemented: overview, inventory, impact, migration |
| Binaries, containers, cloud and HSM | Integration-ready scope; not claimed as live scanning |

## Submission Demonstration

1. Open the synthetic local inventory and show Quantum Readiness.
2. Run a live scan of the synthetic local `demo-enterprise` repository.
3. Inspect algorithm, mode, version, TLS and dependency evidence in the CBOM.
4. Filter critical and quantum-vulnerable findings.
5. Show Mosca assessment and `What Breaks?` impact.
6. Build the P0-P3 migration roadmap.
7. Export the CBOM as CSV/JSON and the technical report as Markdown.

The full workflow works locally without an LLM, internet access or cloud
availability.
