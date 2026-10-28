# Firewall Port-Scan Triage — What a DROP Event Actually Proves

> **Lab:** Work Trainer — local SOC Analyst Trainer (simulated firewall logs)  
> **Status:** Lab requirements completed in October 2026  
> **MITRE ATT&CK:** [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/)  
> **Scope:** Educational reconstruction; no live network was scanned.

## Investigation objective

Identify the source of a short burst of blocked connections and separate observed firewall events from claims about open ports or authenticated access.

## Evidence

| Source IP | Observation | Time window |
|---|---|---|
| `198.51.100.77` | Six `DROP` events targeting destination ports `21, 22, 23, 80, 443, 3389`. | Roughly two seconds. |
| `203.0.113.9` | One separate `DROP` event targeting `443`. | Outside the six-event pattern. |

All addresses are documentation-only examples from the simulator.

## Investigation and decision

The repeated, rapid probes across different service ports are **consistent with reconnaissance / port scanning**. The lab classified the main sequence as **True Positive — reconnaissance** and the source was blocked in the simulator.

Important interpretation boundaries:

- `DROP` means the firewall dropped the observed traffic; it **does not, by itself, prove that a destination port is closed**.
- A connection attempt is **not** an SSH/FTP/RDP login attempt.
- The log shows no completed connection, authentication, successful exploitation, or host compromise.
- The one-off event from `203.0.113.9` should not be rolled into the other source's six attempts.

### Reusable analysis method

Group firewall events by source IP, inspect the count and distinct destination ports, and compare event timestamps. For a text log, the investigation may use `grep`, `awk`, `sort` and `uniq -c`; the exact field extraction depends on the log format.

Tune alerts using baseline traffic, authorized scanner inventories, target criticality, and evidence of permitted or denied connections.

## What remains unknown

Whether the scanning source was authorized, whether services were actually exposed, and whether any later stage of an attack occurred.

## Lessons learned

State exactly what the telemetry supports. A blocked scan can still be a real detection without becoming a confirmed intrusion.

## Reference

[MITRE ATT&CK T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
