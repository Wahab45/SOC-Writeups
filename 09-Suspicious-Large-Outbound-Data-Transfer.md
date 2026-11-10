# ALERT-1009 — Suspicious Large Outbound Data Transfer

> **Source:** Work Trainer / SOC Analyst Trainer (simulated exercise)  
> **Scenario severity:** Critical  
> **Simulator classification:** True Positive (exercise requirement; not independent proof of unauthorized data exfiltration)  
> **Scenario ATT&CK label:** T1048 (Exfiltration Over Alternative Protocol). The log excerpt does not establish a protocol or enough detail to confirm this technique.  
> **Evidence scope:** Educational simulation, not a real customer incident.

## Scenario and objective

A Data Loss Prevention (DLP) alert flagged unusually high outbound traffic during nighttime hours. The investigation aimed to identify the source account and destination, quantify the observed transfer, evaluate legitimate alternatives, and apply the simulated containment actions.

The DLP scenario describes the events as outbound; the individual log rows do not explicitly contain a traffic direction, date, timezone, or protocol. This distinction matters when interpreting the evidence.

## Evidence collected

The analyst inspected the simulation log:

```bash
cat /var/log/proxy.log
```

The following excerpt comes from the training log:

```text
02:50:10 jsmith  10.0.0.31  93.184.216.34 BYTES=120000
03:12:01 dbadmin 10.0.0.9   203.0.113.50 BYTES=8800000000
03:14:20 dbadmin 10.0.0.9   203.0.113.50 BYTES=4100000000
09:15:00 jsmith  10.0.0.31  93.184.216.34 BYTES=90000
```

These addresses are part of the training data. In particular, `203.0.113.50` is within a documentation-reserved IP range, **not a real-world indicator to block or hunt for**.

| Account | Source IP | Destination IP | Transfer shown | Timing |
|---|---|---|---:|---|
| `dbadmin` | `10.0.0.9` | `203.0.113.50` | 8,800,000,000 bytes | 03:12:01 |
| `dbadmin` | `10.0.0.9` | `203.0.113.50` | 4,100,000,000 bytes | 03:14:20 |
| `jsmith` | `10.0.0.31` | `93.184.216.34` | 120,000 + 90,000 bytes | 02:50 and 09:15 |

### Volume calculation

```text
dbadmin = 8,800,000,000 + 4,100,000,000 = 12,900,000,000 bytes = 12.9 GB
jsmith  =       120,000 +        90,000 =        210,000 bytes = 0.21 MB
```

The two large entries occur 2 minutes and 19 seconds apart. The volume is striking relative to the other **observed** account in this short excerpt.

**Important limitation:** Two `jsmith` events do **not** constitute a verified baseline for `dbadmin`. Establishing an actual baseline would require comparable historical traffic for this account, application, destination, and business workflow.

## Investigation and decision

**Initial observation:** `dbadmin` was associated with a very large transfer to one destination during nighttime hours.

**Suspicion:** Potential exfiltration warrants investigation and precautionary containment.

**Alternative explanations to test:** An approved backup or replication task, scheduled export, business-critical batch operation, or authorized large file transfer.

**What the log alone does not prove:**

- Whether data transfer was unauthorized.
- Whether the transferred content contained confidential or personal data.
- Whether the account was compromised, or the account owner initiated the operation.
- Whether the specified network destination was suspicious beyond the unexplained volume.
- Whether the log records actual successful bytes delivered versus another proxy accounting metric.

The training exercise's **True Positive** classification is reported as a simulator outcome, not as an independently confirmed security breach.

## Containment performed in the simulator

The learner reported the following completed simulator checklist states:

1. **Proxy log sorted/analyzed** — checked.
2. **Destination blocked** — checked, after a training action using:

   ```bash
   sudo ufw deny out to 203.0.113.50
   ```

3. **Account locked** — checked, after:

   ```bash
   sudo usermod -L dbadmin
   ```

**Operational nuance:** `usermod -L` locks a Linux user's password entry. By itself it does not reliably revoke active sessions or SSH key-based authentication. In production, account containment needs identity-provider, session, and credential-specific validation.

A German incident ticket was drafted and the learner stated it was entered in the simulator. It included the account, source and destination, approx. 13 GB, completed containment, and a recommendation to escalate to the Incident Response team. The final six-item checklist screenshot/status was not provided, so this write-up does **not** claim all remaining ticket criteria were independently checked or escalation was actually performed.

## Recommended production investigation (not performed)

- Check change records, backup schedules, approved export jobs, destination ownership, and any proxy/DLP exception policy.
- Build a **like-for-like historical baseline** for `dbadmin` or the relevant service and data flow.
- Correlate proxy logs with firewall/netflow, DNS, DLP, endpoint activity, application/database audit logs, and authentication telemetry.
- Determine data classification and actual transferred content, where authorized and technically feasible.
- Confirm any egress block at the correct enforcement point, validate account and session containment, and assess business impact.
- Escalate promptly to the Incident Response owner for verification of scope, authorization, and impact. If personal data may be affected, involve the privacy team for the applicable notification assessment; a GDPR notification deadline is **conditional**, not automatic for every large transfer.

## Lessons learned

- **Transfer size and time** are stronger triage evidence than whether a username sounds ordinary or administrative.
- A log excerpt with two accounts is **not** a trustworthy historical baseline.
- **Bytes are not bits:** decimal GB conversion divides bytes by 1,000,000,000; multiply by 8 only to convert bytes to bits.
- Successful simulator commands are not equivalent to production-wide containment verification.
- Keep the simulation's True Positive verdict separate from proof of malicious intent or actual data theft.

## References

- [MITRE ATT&CK T1048 — Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [IANA IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
- [Linux usermod manual](https://man7.org/linux/man-pages/man8/usermod.8.html)
