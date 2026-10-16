# Test fixture

This folder contains an **inert** test target used to validate the scanner's detectors
against a known answer key. It is not malware and does nothing harmful.

## Files

| File | Purpose |
|---|---|
| `src/demo_vendor_app.c` | Source of the fixture. `main()` prints one line and exits. |
| `build.sh` | Builds two ELF binaries into `bin/`. |
| `vendor_attestation.yaml` | A fictitious vendor's (deliberately optimistic) security questionnaire. |
| `answer_key.yaml` | Expected control-test results for the vulnerable build. |

## The two builds

```bash
bash build.sh
```

- **`bin/demo_vendor_app`** — the *vulnerable* build. Compiled without hardening and
  containing synthetic markers (an AWS-documented example key, an `http://` endpoint to a
  reserved `.test` domain, a legacy `MD5` config string, fake `patient/ssn/dob` fields, and
  an end-of-life `OpenSSL 1.0.1` version string). Expected to **FAIL** several controls.
- **`bin/demo_vendor_app_hardened`** — the *remediated* build. Markers removed, TLS instead
  of cleartext, a modern hash, and compiled with PIE + full RELRO + stack canary. Expected
  to **PASS**, demonstrating the before/after remediation story.

## Why the values are safe

Every "sensitive" value is chosen precisely so it is recognisable as a test value:

- **AWS keys** are AWS's own public documentation examples (`AKIAIOSFODNN7EXAMPLE`), which
  are non-functional by design.
- **URLs** use the RFC 2606 / RFC 6761 reserved `.test` and `example.*` space, which can
  never resolve to a real host.
- **The "patient" record** is an obvious placeholder (`TEST-0001`, `1900-01-01`, all-zero SSN).

The program makes no network connections, reads no real data, and attacks nothing — the
markers exist only as string constants so the detectors have something to find.

## Validate the detectors

```bash
python -m vsas bin/demo_vendor_app --answer-key answer_key.yaml
# SELF-TEST: PASS (8 expectations met)
```
