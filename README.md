# Vendor Software Assurance Scanner (VSAS)

**Static, read-only compliance testing of third-party software — turning a vendor's
compiled binary into evidence for a GRC risk decision.**

![status](https://img.shields.io/badge/status-portfolio%20project-blue)
![python](https://img.shields.io/badge/python-3.9%2B-informational)
![license](https://img.shields.io/badge/license-MIT-green)
![frameworks](https://img.shields.io/badge/frameworks-NIST%20%C2%B7%20GDPR%20%C2%B7%20HIPAA%20%C2%B7%20SOC%202%20%C2%B7%20PCI%20%C2%B7%20CCPA%20%C2%B7%20FedRAMP%20%C2%B7%20CMMC%20%C2%B7%20DORA%20%C2%B7%20ISO%2027001-6f42c1)

> Companion to [identity-governance-audit-framework](https://github.com/ahuttener/identity-governance-audit-framework).
> That project audits *identity and access controls*; this one audits the **software a vendor ships you**
> — the Third-Party Risk Management (TPRM) gap in most compliance programmes.

---

## The problem

When you onboard a vendor, you send them a security questionnaire and you get back a
PDF full of green ticks: *"all data encrypted in transit", "no hardcoded secrets",
"we maintain an SBOM", "binaries are code-signed."* You then install their software and
trust those answers.

**VSAS checks the answers against the binary.** It reads the compiled artifact the vendor
actually delivers — an `.exe`, an ELF binary, an `.apk` or a `.jar` — and tests whether
the evidence inside it matches what the vendor attested. It never runs the file, modifies
it, or attacks anything: it is a static, read-only *document review* for compiled software.

This is the same job a GRC analyst does by hand during vendor due diligence, expressed as
repeatable, evidence-producing control tests and mapped to every major framework.

## What it tests

Each detector is an automated **control test** that produces evidence and a result
(`PASS` / `FAIL` / `MANUAL` review):

| Control test | What it looks for | Default severity |
|---|---|---|
| `hardcoded-secret` | Embedded credentials, API keys, tokens, private keys | High |
| `weak-crypto` | Deprecated primitives (MD5, SHA-1, DES/3DES, RC4, ECB) | High |
| `plaintext-transport` | Non-TLS endpoints (`http://`, `ftp://`, `telnet://`) | High |
| `personal-data-marker` | PII / special-category (health) data markers | High / Medium |
| `data-egress-endpoint` | Embedded hosts/IPs for data-flow & transfer review | Medium |
| `outdated-component` | End-of-life / vulnerable bundled libraries (→ SBOM) | High |
| `missing-hardening` | No NX, PIE/ASLR, RELRO, stack canary, CFG | Medium |
| `unsigned-binary` | No code signature / integrity cannot be verified | Medium |
| `attestation-gap` | A vendor claim contradicted by the evidence | High |

## Frameworks covered

Every finding is mapped to the relevant control in each framework, so a finding becomes an
auditable line item rather than an opinion. Jurisdiction is stated plainly — the US / EU /
state-level distinction is never blurred.

| Framework | Version | Jurisdiction | Example controls used |
|---|---|---|---|
| NIST Cybersecurity Framework | 2.0 | US (voluntary) | `GV.SC-07`, `PR.DS-02`, `ID.RA-01` |
| NIST SP 800-53 | Rev. 5 | US federal | `IA-5`, `SC-8`, `SR-3`, `RA-5`, `SI-7` |
| NIST SP 800-161 (C-SCRM) | Rev. 1 | US federal | supplier provenance & assessment |
| NIST SP 800-30 | Rev. 1 | US federal | risk scoring method (likelihood × impact) |
| GDPR | (EU) 2016/679 | **European Union** | `Art. 32`, `Art. 9`, `Art. 44–49`, `Art. 28` |
| HIPAA Security Rule | 45 CFR 164 Subpart C *(in force)* | US (health) | `164.312(e)`, `164.308(b)(1)` |
| SOC 2 (AICPA TSC) | 2017 / rev. 2022 | US | `CC6.1`, `CC6.7`, `CC7.1`, `CC9.2` |
| CCPA / CPRA | Cal. Civ. Code 1798.100+ | **US – California** | `1798.81.5`, `1798.140(ag)` |
| PCI DSS | 4.0.1 | Global (cards) | `4.2.1`, `6.3.2`, `12.8` |
| FedRAMP | Rev. 5 Moderate | US federal cloud | `SC-8`, `RA-5`, `SI-7` |
| CMMC | 32 CFR + 48 CFR final | US DoD supply chain | `SC.L2-3.13.8`, `RA.L2-3.11.2` |
| DORA | (EU) 2022/2554 | **European Union** | `Art. 9`, `Art. 28–30` |
| ISO/IEC 27001 Annex A | 2022 | International | `A.8.24`, `A.8.8`, `A.5.19–A.5.23` |

> **HIPAA note:** the January-2025 NPRM proposing major Security Rule changes is still
> *proposed* (final penciled for ~2027 and may change); VSAS cites the rule **in force**.
> See [`docs/framework-coverage.md`](docs/framework-coverage.md) for every mapping and its primary source.

## How it works

```
 artifact (PE / ELF / APK / JAR)
        │
        ▼
 formats.py  ── parse headers, extract strings, symbols, hardening metadata
        │
        ▼
 detectors/  ── 6 control-test modules → PASS / FAIL / MANUAL + evidence (byte offsets)
        │
        ▼
 attestation.py ── reconcile the vendor questionnaire against the evidence
        │
        ▼
 frameworks/mapping.py ── attach control IDs (11 frameworks) + NIST 800-30 risk score
        │
        ▼
 report/  ── HTML report · JSON · CycloneDX SBOM · OSCAL assessment-results · CSV crosswalk
```

## Quickstart

```bash
pip install -r requirements.txt

# build the inert test fixtures (see samples/)
bash samples/build.sh

# scan the vulnerable fixture and reconcile the vendor's attestation
python -m vsas samples/bin/demo_vendor_app \
    --attestation samples/vendor_attestation.yaml \
    --out vsas-report

# open vsas-report/report.html
```

Prove the detectors catch what they should (CI-friendly, exits non-zero on regression):

```bash
python -m vsas samples/bin/demo_vendor_app --answer-key samples/answer_key.yaml
# SELF-TEST: PASS (8 expectations met)
```

## Example output

The repository ships an inert fixture in two builds to show a full before/after:

| Build | Result | Verdict |
|---|---|---|
| `demo_vendor_app` (vulnerable) | 11 FAIL · 2 MANUAL · 0 PASS | **Reject — remediate before approval** |
| `demo_vendor_app_hardened` (remediated) | 1 FAIL · 1 MANUAL · 6 PASS | **Approve with conditions** |

A rendered sample report is in [`docs/sample-report.html`](docs/sample-report.html).

## Reports produced

- **`report.html`** — executive compliance report: verdict, attestation reconciliation,
  per-finding control mappings, SBOM, framework-coverage matrix.
- **`report.json`** — full machine-readable results.
- **`sbom.cdx.json`** — CycloneDX 1.5 Software Bill of Materials.
- **`assessment-results.oscal.json`** — NIST OSCAL-style assessment results.
- **`crosswalk.csv`** — flat finding × framework × control-ID crosswalk.

## Project layout

```
vsas/
  formats.py            artifact parsing & feature extraction (PE/ELF/APK/JAR)
  detectors/            one module per control test
  attestation.py        vendor questionnaire reconciliation
  frameworks/
    controls.yaml       the crosswalk (findings → controls, all frameworks)
    mapping.py          attaches controls + risk to findings
  risk.py               NIST SP 800-30 scoring
  report/               html / json / sbom / oscal / csv writers
  cli.py                `python -m vsas ...`
samples/                inert test fixture (source, build script, attestation, answer key)
docs/                   methodology, framework coverage, legal & ethics, sample report
tests/                  unit tests + answer-key self-test
```

## The test fixture

`samples/src/demo_vendor_app.c` is an **inert** program: it prints one line and exits. It
exists only so the detectors have a target with a known answer key. Every "sensitive" value
is synthetic and non-functional — the AWS keys are [AWS's own public documentation
examples](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html),
URLs use the reserved `.test` domain space (RFC 2606), and the "patient" record is an
obvious placeholder. It makes no network connections and attacks nothing.

## Scope, legal & ethics

VSAS is a **defensive** tool for software you are authorised to assess (your own, or a
vendor's with permission). Static analysis of third-party binaries can touch licence terms
and anti-circumvention law — e.g. the EU Software Directive (2009/24/EC) permits certain
analysis, while the US DMCA §1201 restricts circumvention. The scanner never defeats a
protection: it reads metadata and strings only. See
[`docs/legal-and-ethics.md`](docs/legal-and-ethics.md). This is a portfolio/educational
project; automated results are indicators, not a certification — every finding must be
confirmed by a qualified assessor before a risk decision.

## Author

**Adriano Huttener** — MSc Cybersecurity (National College of Ireland) · [CyberSecInfo](https://cybersecinfo.com) ·
[github.com/ahuttener](https://github.com/ahuttener)

Licensed under the [MIT License](LICENSE).
