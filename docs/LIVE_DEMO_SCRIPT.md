# ECDAT Live Demonstration Script

## Goal

Show that ECDAT turns a difficult, manual cryptographic inventory exercise into an evidence-led migration decision. The product identifies what exists, explains why it matters before a cryptographically relevant quantum computer arrives, and gives the organization a practical next action.

## Opening (30 seconds)

"Most organizations cannot confidently answer where their RSA, ECC, certificates, TLS configurations, or cryptographic libraries are used. A spreadsheet inventory is incomplete the moment a release changes. ECDAT continuously creates a Cryptographic Bill of Materials from the engineering evidence and prioritizes the migration work."

## Demonstration Flow (5 minutes)

1. **Assessment**: Select **Run sample scan**. Explain that ECDAT scans the bundled synthetic repository locally, reads source and deployment evidence, and never executes target code or pulls container images.
2. **Evidence**: Open **Guided demo**, then select **Show evidence**. Filter the critical findings and open a public-key cryptographic asset. Point out the file, line, algorithm, library/protocol context, detection confidence, and exact recommendation.
3. **Prioritize**: Explain the readiness score and Mosca review. Use **Per-finding Mosca what-if** to compare data lifetime plus migration time with the expected quantum threat horizon. Emphasize that it is a simulation, not a source-code change.
4. **Expose**: Open **Exposure and compliance**. Point out the upper-right quadrant: severe, internet-facing evidence. Explain that exposure is derived from parsed Python route and call-chain analysis where detectable. Markers labelled **HNDL** are high-criticality, long-horizon candidates that need data-classification confirmation.
5. **Business impact**: Select **Assess blast radius** for the chosen asset. Show the call-chain evidence and HNDL score. ECDAT never fabricates an owner or public service when a reachable entry point cannot be established.
6. **Migration**: Mark the finding reviewed, select **Add to migration**, and open **Migration**. Generate the roadmap. Show the pure-PQC, hybrid, dependency, and tradeoff options. Return to Assessment to show the illustrative remediation preview; it is a pattern for engineering review, not an automatic patch.
7. **Prove and hand over**: Use **Simulate remediation** in Guided demo to show the readiness improvement. Finish with **Open Executive Summary**, which gives leadership readiness, CNSA planning status, top risks, and estimated remediation effort.

## Close (20 seconds)

"ECDAT does not ask an organization to replace all cryptography blindly. It gives them a defensible, measurable sequence: discover, expose, prioritize, pilot, and migrate. The first investment is a scoped assessment; the output is a CBOM, a quantum-readiness view, and an executive decision brief the organization can own."

## Presenter Notes

- Use a controlled sample repository or an approved internal pilot target. Never scan a production target without authorization.
- Do not claim that ECDAT makes a system quantum safe. It identifies exposure and supports a managed transition to suitable PQC or hybrid controls.
- Lead with evidence and operational value, then show the technology. Avoid leading with model names or implementation details unless the jury asks.
