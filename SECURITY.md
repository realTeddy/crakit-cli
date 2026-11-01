# Coordinated Vulnerability Disclosure Policy - crakit

_Last updated: 2026-11-01. Policy drafted with crakit to support Annex I Part II (5) and Annex I Part II (6) (coordinated vulnerability disclosure policy and contact address for reporting) and Art. 13(17) (single point of contact) of Regulation (EU) 2024/2847._

## 1. Scope

This policy covers security vulnerabilities in the products with digital elements that crakit makes available on the market, including their remote data processing solutions (Art. 3(1)), and the associated update and distribution infrastructure.

## 2. How to report

Report vulnerabilities to our single point of contact (Art. 13(17), Annex I Part II (6)):

1. mailto:crakit@tewodros.me

A machine-readable version of this contact information is published at `/.well-known/security.txt` (RFC 9116).

## 3. What to include

- Product name and version(s) affected
- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof of concept
- Any known mitigations
- Whether you believe the vulnerability is being actively exploited
- How you would like to be credited, if at all

## 4. What we commit to

- We acknowledge receipt within 5 business days.
- We investigate, keep you informed of progress, and address and remediate the vulnerability without delay, including by providing security updates (Annex I Part II (2)).
- Security updates are distributed securely (Annex I Part II (7)) and provided without delay and free of charge, together with advisory messages (Annex I Part II (8)).
- Once a security update is available we publicly disclose information about the fixed vulnerability: a description, its impact and severity, and remediation guidance (Annex I Part II (4)).
- Where a vulnerability is found to be actively exploited, we notify it via the ENISA single reporting platform within the deadlines of Art. 14(2) (early warning within 24 hours, notification within 72 hours, final report within 14 days of a fix being available) and inform impacted users (Art. 14(8)). That judgement and submission is ours, not the reporter's.

## 5. Disclosure timeline

We ask reporters to allow up to 90 days from acknowledgement before public disclosure, so that a fix can be developed, tested and distributed. We will coordinate an earlier or later date with you where a fix is ready sooner, where the vulnerability is already public or actively exploited, or where remediation genuinely needs more time. Reporters may share the vulnerability with the relevant CSIRT or ENISA at any time (Art. 15).

## 6. Safe harbour

We will not pursue legal action against, or report to law enforcement, researchers who act in good faith under this policy: who avoid privacy violations, data destruction and service disruption, who do not exploit a vulnerability beyond what is needed to demonstrate it, who do not access or modify other users' data, and who give us a reasonable time to remediate before disclosure. If in doubt, ask us first.

## 7. Out of scope

- Reports from automated scanners without a demonstrated impact
- Social engineering, physical attacks and denial-of-service testing against production systems
- Issues in third-party services we do not operate (please report them to the respective vendor)

## 8. Recognition

With your consent we credit reporters in our security advisories.

---

_This is a checklist and drafting aid, not legal advice and not a guarantee of compliance with Regulation (EU) 2024/2847._
