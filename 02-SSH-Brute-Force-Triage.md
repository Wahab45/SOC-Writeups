# SSH Brute-Force Triage — Correlate Failures Before Claiming Compromise

> **Lab:** Work Trainer — local SOC Analyst Trainer (simulated data)  
> **Status:** Lab requirements completed in October 2026  
> **MITRE ATT&CK:** [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)  
> **Evidence policy:** This is a reconstructed educational case based on retained lab observations, not a production incident or a protected platform answer key.

## Investigation objective

Assess repeated SSH authentication failures, identify the suspicious source, and determine whether an unauthorized login was demonstrated.

## Observed evidence

| Source | Recorded observation | Analytical meaning |
|---|---|---|
| Simulated SSH authentication data | Five failed attempts from `203.0.113.7`: four against `root` and one against `admin`. | Repeated attempts against privileged usernames. |
| Authentication data | A successful analyst login was present from **another** source IP. | That success cannot be attributed to the suspect IP. |
| Lab checklist | Source enrichment, success-check, ticket documentation and source blocking were completed. | The lab accepted the investigative and response steps; it does not establish production control effectiveness. |

`203.0.113.7` is a documentation-range address used in the lab.

## Analysis and response

The pattern supports a **True Positive for attempted SSH brute-force activity** in this simulated scenario. It does **not** demonstrate that a guessed password worked or that a host was compromised.

A sensible analysis correlates failed and successful events using **source address, username, destination, and time window**. A successful authentication from a different IP must not be counted as proof of this source's success.

A simulated firewall block was applied to the suspicious source. In a real environment, blocking should follow the incident-response playbook and change-control requirements, with a post-action check.

### Reusable detection logic

1. Count SSH failures by `src_ip`, `user` and time window.
2. Identify attacks targeting multiple sensitive accounts.
3. Search separately for subsequent successful logins from the same source.
4. Enrich the alert with asset criticality and known authorized testing activity.
5. Escalate when a confirmed success or other compromise evidence appears.

## What remains unverified

- Whether `203.0.113.7` obtained access.
- Whether any credentials were exposed.
- Whether the failures were part of authorized testing.

## Lessons learned

Distinguish **attempted authentication**, **successful authentication**, and **confirmed compromise**. Treat correlation as an evidence problem, not simply as counting log lines.

## Reference

[MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
