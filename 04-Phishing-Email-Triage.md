# Phishing Email Triage — Header and Link Indicators

> **Lab:** Work Trainer — local SOC Analyst Trainer (simulated email)  
> **Status:** Lab requirements completed in October 2026  
> **MITRE ATT&CK:** [T1566 — Phishing](https://attack.mitre.org/techniques/T1566/)  
> **Scope:** Analysis of a simulated message; no real malicious attachment or live domain was investigated.

## Scenario

A user-reported message claimed that an account would soon be locked and urged the recipient to confirm their account via a link. The investigation focused on email-header inconsistencies, social engineering, and safe indicator handling.

## Evidence from the simulated email

| Field / element | Observed value | Significance |
|---|---|---|
| From | `IT-Support <support@paypa1-secure.com>` | Brand impersonation and `paypa1` lookalike spelling. |
| Reply-To | `harvest@mailbox.example` | Different reply destination; suspicious in context. |
| Return-Path | `bounce@mailer.example` | Different bounce handling address; not intrinsically malicious by itself. |
| Received-SPF | `fail` | Authentication concern; should be interpreted with sending infrastructure and other signals. |
| Subject | `Your account will be locked - act now` | Pressure / urgency. |
| Link | `http://paypa1-login.example/verify` | Lookalike domain and unencrypted HTTP URL. |
| Attachment name | `Invoice.pdf.exe` | Double extension ending in a Windows executable type. |

All `.example` domains are reserved for examples. They are **not production indicators to block**.

## Investigation outcome

The lab classified the message as a **True Positive — phishing attempt**. The analyst checked the example domain using a DNS lookup, added the domain to the simulated `~/blocklist.txt`, and documented SPF, Reply-To, and typosquatting indicators in a ticket.

This lab outcome shows a phishing message with multiple mutually reinforcing indicators. **It does not show attachment execution, credential theft, endpoint compromise, or actual delivery of a malicious payload.**

## Reusable triage workflow

1. Preserve the email and inspect header fields without clicking links.
2. Compare displayed sender, actual address, reply destination and authentication results.
3. Examine URL hostnames carefully for lookalike characters, including `1` versus `l`.
4. Treat `.pdf.exe` as an executable-looking filename, not as proof that malware executed.
5. Check safe enrichment sources and decide whether organizational email/web blocking is warranted.
6. Document confirmed observations separately from endpoint-impact hypotheses.

### Analyst caution

A separate training discussion explored **hypothetical** Windows process trees and PowerShell activity. Those examples were **not evidence collected from this email lab** and are intentionally excluded from its findings.

## Lessons learned

Several weaker phishing clues can support a strong classification together. Domain age, SPF failures, mismatched headers, and urgent language are context; none alone proves compromise.

## Reference

[MITRE ATT&CK T1566 — Phishing](https://attack.mitre.org/techniques/T1566/)
