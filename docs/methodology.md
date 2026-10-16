# Methodology

VSAS performs **static, read-only assurance testing** of a vendor-supplied binary. It is
modelled on the way a GRC analyst conducts vendor due diligence, expressed as repeatable,
evidence-producing control tests.

## Pipeline

1. **Ingest & extract (`formats.py`).** The artifact is identified by magic bytes
   (PE / ELF / Mach-O / ZIP-based APK/JAR). We extract: printable ASCII and UTF-16LE
   strings (with byte offsets), symbols/imports, and platform hardening metadata
   (NX, PIE/ASLR, RELRO, stack canary / Authenticode, CFG). Nothing is executed.

2. **Control testing (`detectors/`).** Each detector is one or more control tests. A test
   examines the extracted evidence and returns:
   - **PASS** — the control objective is met;
   - **FAIL** — an exception was found (evidence recorded with offsets);
   - **MANUAL** — evidence was found that a human must adjudicate (e.g. personal-data
     markers, which require a data-flow and lawful-basis review).

3. **Attestation reconciliation (`attestation.py`).** The vendor's questionnaire answers
   are compared to the evidence. A contradiction (e.g. "encryption in transit = true" while
   an `http://` endpoint is present) raises an `attestation-gap` — the classic due-diligence
   red flag.

4. **Mapping & risk (`frameworks/`, `risk.py`).** Each finding is mapped to the relevant
   control in all supported frameworks (`controls.yaml`) and scored with **NIST SP 800-30**:
   an assessed *likelihood* and *impact* are combined via a 5×5 matrix into an overall risk.

5. **Reporting (`report/`).** Results are emitted as an executive HTML report, JSON, a
   CycloneDX SBOM, an OSCAL-style assessment-results document, and a CSV crosswalk.

## How results become a verdict

The overall recommendation is derived from the highest open (non-PASS) risk:

| Highest open risk | Recommendation |
|---|---|
| High / Very High | **Reject** — remediate before approval |
| Moderate | **Approve with conditions** (time-bound remediation) |
| Low / Very Low / none | **Approve** |

## Evidence & reproducibility

Every FAIL/MANUAL records the exact string or metadata and, where available, the byte
offset in the file, so a second assessor can reproduce the finding independently with a hex
editor or `strings`. This is what makes the output *audit evidence* rather than an opinion.

## Known limitations

- **Static only.** VSAS does not run the software, so it cannot observe runtime behaviour,
  dynamically generated secrets, or packed/encrypted payloads. A packer will hide strings;
  that itself is reported as low signal (few strings extracted).
- **Signature-based detectors.** Detection uses patterns and version strings; expect false
  positives (e.g. an algorithm name in an unrelated context) and false negatives (an
  obfuscated component). Results are indicators to confirm, never a certification.
- **SBOM completeness.** Component inventory depends on version strings being present; a
  statically stripped binary may yield an incomplete SBOM.
- **Mach-O** support is limited to string extraction in this version.

These limitations are deliberately surfaced in the report's methodology footer so a reader
never mistakes an automated indicator for an assessor's conclusion.
