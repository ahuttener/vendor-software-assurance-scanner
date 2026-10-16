# Framework coverage

Every control test maps to the relevant control in each framework. IDs are written as the
source framework writes them. This page is the human-readable view of
[`vsas/frameworks/controls.yaml`](../vsas/frameworks/controls.yaml), which is the machine
source of truth.

> **Jurisdiction matters.** GDPR and DORA are **EU** law; CCPA/CPRA is **US–California**;
> HIPAA, SOC 2, PCI DSS, FedRAMP and CMMC are **US** (PCI is card-brand, global in reach);
> NIST is US federal guidance used internationally; ISO/IEC 27001 is international.

## Primary sources

| Framework | Version | Source |
|---|---|---|
| NIST CSF | 2.0 (2024) | https://doi.org/10.6028/NIST.CSWP.29 |
| NIST SP 800-53 | Rev. 5 | https://doi.org/10.6028/NIST.SP.800-53r5 |
| NIST SP 800-161 | Rev. 1 | https://doi.org/10.6028/NIST.SP.800-161r1 |
| NIST SP 800-30 | Rev. 1 | https://doi.org/10.6028/NIST.SP.800-30r1 |
| GDPR | Reg. (EU) 2016/679 | https://eur-lex.europa.eu/eli/reg/2016/679/oj |
| HIPAA Security Rule | 45 CFR 164 Subpart C | https://www.ecfr.gov/current/title-45/part-164 |
| SOC 2 (AICPA TSC) | 2017 rev. 2022 | https://www.aicpa-cima.com/resources/landing/trust-services-criteria |
| CCPA / CPRA | Cal. Civ. Code 1798.100+ | https://oag.ca.gov/privacy/ccpa |
| PCI DSS | 4.0.1 | https://www.pcisecuritystandards.org/document_library/ |
| FedRAMP | Rev. 5 baselines | https://www.fedramp.gov/ |
| CMMC | 32 CFR + 48 CFR final | https://dodcio.defense.gov/CMMC/ |
| DORA | Reg. (EU) 2022/2554 | https://eur-lex.europa.eu/eli/reg/2022/2554/oj |
| ISO/IEC 27001 | 2022 | https://www.iso.org/standard/27001 |

## Mappings by control test

### `hardcoded-secret`
- **NIST CSF** PR.AA-01, PR.AA-05, PR.DS-01 · **800-53** IA-5, IA-5(7), SA-15
- **GDPR** Art. 32(1) · **HIPAA** 164.312(a)(2)(i), 164.312(d), 164.308(a)(5)(ii)(D)
- **SOC 2** CC6.1, CC6.6 · **CCPA** 1798.100(e), 1798.81.5 · **PCI DSS** 6.2.4, 8.3.1, 8.6.2
- **FedRAMP** IA-5 · **CMMC** IA.L2-3.5.7/3.5.8 · **DORA** Art. 9(2),(4) · **ISO 27001** A.5.17, A.8.24

### `weak-crypto`
- **NIST CSF** PR.DS-01/02 · **800-53** SC-13, SC-8, SC-8(1), SC-28
- **GDPR** Art. 32(1)(a) · **HIPAA** 164.312(a)(2)(iv), 164.312(e)(2)(ii)
- **SOC 2** CC6.1, CC6.7 · **CCPA** 1798.81.5 · **PCI DSS** 4.2.1, 3.6.1, 3.7.1, 6.2.4
- **FedRAMP** SC-13, SC-8 · **CMMC** SC.L2-3.13.8/3.13.11 · **DORA** Art. 9(2) · **ISO 27001** A.8.24

### `plaintext-transport`
- **NIST CSF** PR.DS-02 · **800-53** SC-8, SC-8(1), SC-23
- **GDPR** Art. 32(1) · **HIPAA** 164.312(e)(1), 164.312(e)(2)(ii)
- **SOC 2** CC6.7 · **CCPA** 1798.81.5 · **PCI DSS** 4.2.1
- **FedRAMP** SC-8 · **CMMC** SC.L2-3.13.8 · **DORA** Art. 9(2) · **ISO 27001** A.8.24, A.5.14

### `personal-data-marker`
- **NIST CSF** ID.AM-07, PR.DS-01 · **800-53** PT-2, PT-3, PM-5
- **GDPR** Art. 5, 6, **9 (special category)**, 25, 30 · **HIPAA** 164.502, 164.514, 164.306
- **SOC 2** P3.1, P4.1, C1.1 · **CCPA** 1798.100, 1798.140(ae) sensitive PI, 1798.140(v)
- **PCI DSS** 3.2.1/3.3/3.4 (only if PAN present) · **CMMC** MP.L2-3.8.x (if CUI)
- **DORA** Art. 8, 9(3) · **ISO 27001** A.5.12, A.5.34, A.8.11

### `data-egress-endpoint`
- **NIST CSF** ID.AM-04, GV.SC-07, DE.CM-06 · **800-53** SA-9, CA-3, SR-3
- **GDPR** Art. 28, 30, **44, 46, 49 (transfers)** · **HIPAA** 164.308(b)(1), 164.314(a)
- **SOC 2** CC9.2, CC3.2 · **CCPA** 1798.140(ag), 1798.140(j) · **PCI DSS** 12.8, 12.8.1, 12.8.5
- **FedRAMP** SA-9, CA-3 · **CMMC** SA-9 flow-down · **DORA** Art. 28, 29, 30 · **ISO 27001** A.5.19, A.5.20, A.5.14

### `outdated-component`
- **NIST CSF** ID.AM-02, ID.RA-01, GV.SC-04 · **800-53** CM-8, RA-5, SA-22, SR-3, SR-4
- **GDPR** Art. 32(1) · **HIPAA** 164.308(a)(1)(ii)(A), 164.308(a)(8)
- **SOC 2** CC7.1, CC3.2 · **CCPA** 1798.81.5 · **PCI DSS** 6.3.1, 6.3.2, 6.3.3, 12.3.4
- **FedRAMP** RA-5, CM-8, SA-22 · **CMMC** RA.L2-3.11.2, SI.L2-3.14.1 · **DORA** Art. 8, 9(4) · **ISO 27001** A.8.8, A.5.9, A.8.32

### `missing-hardening`
- **NIST CSF** PR.PS-01 · **800-53** SI-16, CM-6, SA-11, SA-15
- **GDPR** Art. 25, 32(1) · **HIPAA** 164.312(c)(1)
- **SOC 2** CC7.1, CC8.1, CC6.8 · **CCPA** 1798.81.5 · **PCI DSS** 6.2.4, 2.2
- **FedRAMP** SI-16, CM-6 · **CMMC** CM.L2-3.4.1, SI.L2-3.14.1 · **DORA** Art. 9(4) · **ISO 27001** A.8.27, A.8.28, A.8.9

### `unsigned-binary`
- **NIST CSF** PR.DS-06 · **800-53** SI-7, SI-7(1), CM-14 · **800-161** SR-11
- **GDPR** Art. 5(1)(f), 32(1) · **HIPAA** 164.312(c)(1), 164.312(c)(2)
- **SOC 2** CC6.8, CC7.1 · **CCPA** 1798.81.5 · **PCI DSS** 6.3.2, 11.5
- **FedRAMP** SI-7, CM-14 · **CMMC** SI.L2-3.14.1 · **DORA** Art. 9(4) · **ISO 27001** A.8.19, A.8.28

### `attestation-gap`
- **NIST CSF** GV.SC-06, GV.SC-07, GV.SC-04 · **800-53** SR-6, SR-3, SA-9(3)
- **GDPR** Art. 24, 28(1), 28(3)(h) · **HIPAA** 164.308(b)(1), 164.314(a)
- **SOC 2** CC9.2, CC3.2 · **CCPA** 1798.140(ag), CCR 7051 due diligence · **PCI DSS** 12.8.4, 12.8.5
- **FedRAMP** SR-6, SA-9 · **CMMC** flow-down SR; C3PAO · **DORA** Art. 28(4), 29, 30 · **ISO 27001** A.5.19, A.5.20, A.5.22

## A note on HIPAA currency

The Office for Civil Rights published an NPRM on **6 January 2025** proposing substantial
changes to the Security Rule (mandatory MFA, encryption, asset inventories, removal of the
"addressable" distinction). As of this writing it remains **proposed**, with the final rule
delayed (press reporting points to ~2027) and subject to change. VSAS therefore maps to the
Security Rule **currently in force** (45 CFR Part 164, Subpart C) and flags this explicitly.
