# Windows Threat Detection 2 — Event Correlation and Evidence Limits

> **Platform:** TryHackMe — SOC Level 1 (historical training notes, June 2026)  
> **Topic:** Windows logon events and Sysmon telemetry  
> **Status:** Previously published lab summary, revised for evidence accuracy  
> **Evidence limitation:** The repository contains no raw event exports, screenshots, or process timelines from the original exercise. Specific attack conclusions from the earlier version cannot be independently verified from this write-up alone.

## Scenario and investigation goal

The original exercise concerned identifying suspicious activity after access to a Windows host. The notes discuss failed and successful logons as well as process creation, file creation, and registry modification. They do **not** reproduce the events needed to prove that these actions belonged to one attacker sequence.

## Relevant Windows telemetry

| Source | Event ID | What the event records | What it **does not** prove on its own |
|---|---|---|---|
| Windows Security | `4625` | A failed logon attempt. | An attacker successfully authenticated. |
| Windows Security | `4624` | A successful logon. | The login is malicious or linked to earlier failures. |
| Sysmon | `1` | Process creation with configured metadata. | That the process is malicious. |
| Sysmon | `11` | File creation. | That the file is a malicious payload. |
| Sysmon | `13` | Registry value modification. | That persistence was established. |

Sysmon events depend on the host's installed configuration and event collection.

## Detection methodology

### Failed logons followed by a successful logon

A cluster of Windows `4625` events followed by a `4624` **can suggest** credential guessing or brute-force success. It is **not sufficient to claim confirmed brute-force compromise** without further correlation.

Investigate:
- Target account and host.
- Event time window.
- Source address / workstation, where available and reliable.
- Logon type (for example, network versus remote-interactive sessions).
- Expected administration, testing, and user behavior.
- Subsequent account, process, and network activity.

### Post-authentication activity

Correlate Sysmon event 1 process ancestry and command lines, event 11 file paths and content/hash indicators, and event 13 registry paths with known persistence mechanisms. Interpret each event in its operational context.

A registry value change, by itself, could be a normal application or administrative operation.

## Findings and confidence

**Supported by this document:** The exercise used Windows authentication and Sysmon event types relevant to brute-force detection and post-authentication triage.

**Not independently verifiable from the repository:** The earlier notes' claims that brute-force succeeded, a malicious process executed, a payload was dropped, and registry persistence was established. Raw supporting evidence was not preserved here; these assertions are therefore **not presented as confirmed findings**.

## Lessons learned

1. Correlate multiple event attributes, not only event IDs.
2. Keep suspicious activity distinct from confirmed attacker activity.
3. Preserve sanitized event excerpts and an evidence timeline for future write-ups.
4. Treat Sysmon as visibility into behavior, not an automatic maliciousness verdict.

## References

- [Microsoft — 4624: An account was successfully logged on](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [Microsoft — 4625: An account failed to log on](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [Microsoft — Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

---

**Original author:** Abdalwahab Abdalrazak  
**Original exercise date:** June 2026
