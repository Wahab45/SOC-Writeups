# VPN Impossible Travel — T1078 Valid Accounts

> **Lab:** Work Trainer — local SOC Analyst Trainer (simulated VPN log and enrichment)  
> **Status:** All six lab requirements completed on 27 October 2026  
> **Severity in simulator:** High | **Difficulty:** Intermediate  
> **MITRE ATT&CK:** [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)  
> **Scope:** Simulated access anomaly, not a confirmed real-world account takeover.

## Investigation objective

Examine two successful VPN logins associated with one account and assess subsequent access to a sensitive file.

## Observed VPN log

```text
08:00:02 jlee LOGIN ok src=84.12.33.9 geo=DE
08:12:44 jlee LOGIN ok src=185.220.101.4 geo=RU
08:13:10 jlee ACCESS file-server /finance/payroll.xlsx
```

The times are from the training log; date and timezone were not supplied. IP addresses are part of simulated lab telemetry.

| Observation | Significance | Limitation |
|---|---|---|
| Two successful logins | Same account, different source IPs / geolocations, 12 minutes 42 seconds apart. | Geolocation does not establish a person's physical location. |
| Second IP enrichment | Simulated `whois 185.220.101.4` returned `Tor exit node (known)`. | A Tor exit IP does not establish the operator's identity or actual location. |
| File access | `/finance/payroll.xlsx` was accessed 26 seconds after the second login. | The record alone does not prove a download, exfiltration, or which active session caused the access. |

## Assessment

**Lab classification:** True Positive — Impossible Travel / suspicious account activity.

**Analyst interpretation:** The combination of two successful logins, a Tor-associated exit address, and a subsequent sensitive-file access justified elevated concern. This **did not conclusively establish** credential theft, account compromise, or data exfiltration.

Unknown context includes user role, approved travel, VPN configuration, MFA results, and the detailed file access operation. These should be verified through authorized identity, VPN and file-server telemetry.

## Containment performed in the simulator

The investigation included a simulated account lock and VPN-session termination, and the corresponding lab checks were completed.

A key engineering distinction:

- `usermod -L jlee` locks a **local Linux password**. It does not automatically disable an Active Directory / Entra ID account, revoke tokens, or invalidate every possible authentication method.
- `vpn-kill jlee` was a **simulator-specific** command representing VPN session termination, **not a portable Linux or vendor VPN command**.

In a real enterprise, containment must target the **actual VPN identity provider and session manager**, follow authorization procedures, and be verified.

## Post-containment verification checklist

- Confirm the account's disabled/blocked state in the correct identity provider.
- Review active VPN sessions and explicit disconnect/revocation events.
- Look for successful authentication events **after** the containment time.
- Examine file-server activity involving the sensitive resource.
- Record precise timestamps, systems checked, results and remaining visibility gaps.

These are **recommended checks**; the training session did **not** provide evidence that all of them were performed successfully.

## Lessons learned

1. A positive alert classification is not identical to proof of account compromise.
2. An anonymizing exit node can make geolocation-based travel signals misleading.
3. Password locking and session revocation are distinct controls.
4. Successful incident response requires verification, not just issuing commands.

## Reference

[MITRE ATT&CK T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
