# Legal & ethical scope

VSAS is a **defensive** assurance tool. Use it only on software you are authorised to
assess: your own, or a third party's with permission (for example, under a vendor evaluation
agreement, a right-to-audit clause, or a bug-bounty / assessment scope).

## Authorisation first

Analysing someone else's software can implicate:

- **Licence / EULA terms.** Many EULAs restrict reverse engineering. Check the agreement and
  any right-to-audit clause before assessing a vendor's binary.
- **EU Software Directive 2009/24/EC.** Articles 5–6 permit certain observation, study and
  (limited) decompilation for interoperability and error correction — a lawful basis for
  analysis that exists in EU law.
- **US DMCA §1201.** Prohibits *circumventing* technical protection measures. VSAS is
  designed to stay on the right side of this line: it reads headers, strings and metadata
  only. **It does not unpack, decrypt, defeat, or bypass any protection mechanism.**

When in doubt, get written authorisation. This project is for learning and for assessing
software you have the right to assess.

## Handling what you find

- **Treat discovered secrets as live.** If a scan surfaces a credential, assume it is real,
  notify the vendor through a responsible-disclosure channel, and support rotation. Do not
  use, store, or share it. VSAS records only a truncated excerpt as evidence.
- **Personal / health data markers** trigger a review, not a conclusion. Do not extract or
  retain any real personal data encountered.
- **Report, don't exploit.** Findings feed a risk decision and a vendor conversation, not an
  attack.

## Not a certification

Automated static analysis produces **indicators**, not assurance opinions. A FAIL is a lead
to confirm; a PASS is the absence of a signal, not proof of security. Every material finding
must be validated by a qualified assessor before it informs a contract or risk decision.
Nothing here is legal advice.

## This repository

The only binary analysed in this repo is the **inert fixture** in `samples/`, built from
source we ship, containing synthetic non-functional values. No third-party or proprietary
software is included or targeted.
