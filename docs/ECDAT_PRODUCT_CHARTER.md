# ECDAT Product Charter

## Purpose

ECDAT is an enterprise cryptographic intelligence platform for the SIH 2026 NTRO
problem statement 26164. It discovers cryptographic assets, creates a
Cryptography Bill of Materials (CBOM), explains classical and quantum risk, and
helps teams plan credible post-quantum migration.

## Product Principles

- Treat source code, dependencies, configuration, certificates, containers and
  infrastructure as discovery sources in a connected enterprise ecosystem.
- Keep detection, scoring, CBOM facts and recommendations deterministic and
  traceable to evidence. AI may explain findings but is not the authority.
- Never expose private keys, execute uploaded binaries, or represent demo-only
  integrations as production capability.
- Keep the offline demo functional without GitHub, cloud services or an LLM.

## Current Implementation

- FastAPI scanner for local repositories with evidence and line-level locations.
- Deterministic risk engine with quantum exposure and configurable Mosca inputs.
- React dashboard for live scans, risk filtering, drill-down and Markdown report
  export.
- Synthetic `demo-enterprise` target, explicitly non-production.

## Build Priorities

1. Expand source, configuration, dependency and certificate discovery.
2. Enrich the CBOM with mode, library, version, confidence and enterprise
   traceability.
3. Add explainable quantum readiness, impact analysis and migration planning.
4. Add persistence, security controls, reporting and reliable offline demo flows.

## Demo Story

Discover a local synthetic enterprise repository, generate CBOM findings,
prioritize quantum-vulnerable assets using Mosca assumptions, export the report,
then show the affected applications and proposed PQC or hybrid migration path.
