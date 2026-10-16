/*
 * demo_vendor_app.c  --  INERT TEST FIXTURE for the Vendor Software Assurance Scanner (VSAS)
 * -----------------------------------------------------------------------------------------
 * WHY THIS FILE EXISTS
 *   The scanner needs a binary with a KNOWN, DOCUMENTED set of detectable anti-pattern
 *   markers so its detectors can be validated against an answer key (samples/answer_key.yaml).
 *   This program is that target. It is deliberately boring: main() prints one line and exits 0.
 *
 * THIS IS NOT MALWARE AND DOES NOTHING HARMFUL
 *   - It makes no network connections, opens no files, reads no real data, attacks nothing.
 *   - Every "sensitive" value below is SYNTHETIC and NON-FUNCTIONAL, chosen precisely so it
 *     is recognisable as a test value:
 *       * The AWS keys are AWS's own PUBLIC DOCUMENTATION example credentials.
 *       * URLs use the RFC 2606 / RFC 6761 reserved ".test" and "example.*" space, which can
 *         never resolve to a real host.
 *       * The "patient" record is an obvious placeholder (all zeros / 1900-01-01).
 *   - The markers exist only as string constants so the scanner's signature layer finds them.
 *
 * BUILD
 *   Default build keeps the markers and is compiled WITHOUT hardening  -> fails several controls.
 *   Defining REMEDIATED removes the markers and is compiled WITH hardening -> passes, to show
 *   the before/after remediation story. See samples/build.sh.
 */

#include <stdio.h>

#ifndef REMEDIATED
/* ---- "vulnerable" build: synthetic markers the scanner is expected to flag --------------- */

/* [MARKER: hardcoded-secret] AWS-documented example credentials (non-functional) */
const char *demo_access_key_id     = "AKIAIOSFODNN7EXAMPLE";
const char *demo_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

/* [MARKER: plaintext-transport] config fetched over http:// from a reserved .test domain */
const char *demo_update_url = "http://updates.example-vendor.test/config.json";

/* [MARKER: weak-crypto] reference to a deprecated hash algorithm */
const char *demo_hash_algorithm = "checksum algorithm = MD5 (legacy)";

/* [MARKER: data-handling] field names that trigger a privacy review (values are fake) */
const char *demo_record =
    "patient_id=TEST-0001;dob=1900-01-01;ssn=000-00-0000;note=SYNTHETIC-TEST-RECORD";

/* [MARKER: outdated-component] version string of an end-of-life component (fixture only) */
const char *demo_component = "OpenSSL 1.0.1 (fixture string; this program is not linked to it)";

#define BUILD_LABEL "vulnerable"
#else
/* ---- "remediated" build: markers removed, transport over https, modern hash ------------- */
const char *demo_update_url     = "https://updates.example-vendor.test/config.json";
const char *demo_hash_algorithm = "checksum algorithm = SHA-256";
const char *demo_component       = "OpenSSL 3.0.14 (fixture string; not linked)";

#define BUILD_LABEL "remediated"
#endif

int main(void)
{
    /* A small stack buffer so -fstack-protector-strong inserts a canary in the
       hardened build; the non-hardened build (-fno-stack-protector) has none.
       This makes the before/after hardening contrast visible to the scanner. */
    char banner[128];
    snprintf(banner, sizeof banner,
             "demo_vendor_app: inert test fixture for VSAS (%s build). It does nothing.",
             BUILD_LABEL);
    puts(banner);
    return 0;
}
