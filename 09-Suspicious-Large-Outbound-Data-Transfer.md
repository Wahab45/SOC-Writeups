# ALERT-1009 — Suspicious Large Outbound Data Transfer (T1048)

> **Lab:** Work Trainer / SOC Analyst Trainer — simulated environment  
> **Severity in simulator:** Critical | **Level:** Expert  
> **MITRE ATT&CK:** [T1048 — Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/) (scenario label; the protocol is not established by the excerpt)  
> **Status:** Proxy-log analysis, destination blocking and account password locking confirmed by the simulator checklist. The analyst reported submitting a ticket, but a final all-items checklist was not provided.  
> **Scope:** Educational case study, not evidence of a real production data breach.

## Investigation objective

Investigate a Data Loss Prevention (DLP) alert concerning unusually large outbound data transfers during nighttime hours. Identify the account, internal source and destination, quantify the transfer, apply the simulated containment steps and document the evidence limitations.

## Observed evidence

### Proxy-log findings

The analyst used:

```bash
cat /var/log/proxy.log
```

The simulator returned:

```text
02:50:10 jsmith 10.0.0.31 93.184.216.34 BYTES=120000
03:12:01 dbadmin 10.0.0.9 203.0.113.50 BYTES=8800000000
03:14:20 dbadmin 10.0.0.9 203.0.113.50 BYTES=4100000000
09:15:00 jsmith 10.0.0.31 93.184.216.34 BYTES=90000
```

The records provide times but no date, timezone, network protocol or explicit direction field. The DLP **scenario**, rather than the individual rows, describes the traffic as outbound. The destination `203.0.113.50` is a documentation-range address used for the simulation, **not a production indicator to block**.

| Account | Source IP | Destination IP | Recorded volume | Time |
|---|---|---|---|---|
| `dbadmin` | `10.0.0.9` | `203.0.113.50` | 8,800,000,000 bytes | 03:12:01 |
| `dbadmin` | `10.0.0.9` | `203.0.113.50` | 4,100,000,000 bytes | 03:14:20 |
| `jsmith` | `10.0.0.31` | `93.184.216.34` | 120,000 + 90,000 bytes | 02:50:10 and 09:15:00 |

### Data-volume assessment

```text
dbadmin: 8,800,000,000 + 4,100,000,000 = 12,900,000,000 bytes = 12.9 GB
jsmith:        120,000 +        90,000 =        210,000 bytes = 0.21 MB
```

The two large `dbadmin` events were recorded **2 minutes and 19 seconds apart**. The volume is markedly higher than the other records in this excerpt.

**Important limitation:** The two `jsmith` records are **not a verified historical baseline** for `dbadmin`. Normal behavior would need to be checked against comparable prior transfers, approved destinations, backup schedules and the account's business role.

### Assessment

**Simulator classification target:** True Positive — Data Exfiltration.

**Analyst interpretation:** The time, unusually large transfer volume and concentration on a single account and destination justified urgent investigation and the containment steps required by the lab. The evidence supports **suspected exfiltration**, not a confirmed unauthorized transfer or breach.

The supplied records do **not** establish that:

- The transfer was unauthorized rather than a scheduled backup, replication job or approved export.
- The data contained personal, confidential or sensitive information.
- The account was compromised, or who initiated the operation.
- The recorded `BYTES` values prove exactly what content reached the destination.
- The specific ATT&CK technique **T1048** applies: the transport or application protocol was not provided.

## Response and containment

The analyst reported completing the following simulator checklist items:

| Step | Analyst command / action | Confirmed simulator result and limitation |
|---|---|---|
| Inspect proxy activity | `cat /var/log/proxy.log` | **Proxy log sorted/analyzed** marked complete. |
| Block destination | `sudo ufw deny out to 203.0.113.50` | **Destination blocked** marked complete. |
| Lock account password | `sudo usermod -L dbadmin` | **Account locked** marked complete. |

The firewall command represents an outbound rule on the machine where it is applied; it does **not** prove that every enterprise egress path was blocked. Similarly, `usermod -L` locks a local Linux password, but does **not necessarily** terminate existing sessions or prevent SSH key-based access.

### Incident ticket and escalation

A German-language incident ticket was drafted with:

- User `dbadmin`; source `10.0.0.9`; destination `203.0.113.50`.
- Approximate total of **12.9 GB** transferred between 03:12 and 03:14.
- Completed destination blocking and account password lock in the simulator.
- The simulator's True Positive classification and a recommendation to escalate to the Incident Response team.
- The explicit caveat that unauthorized exfiltration had not been conclusively established.

The analyst reported submitting the ticket. **No final checklist output was provided**, and escalation was written as a required next step rather than a verified completed action.

## Recommended next steps in a production environment

The following are recommendations, **not actions shown as completed in the lab**:

1. Check authorized backup, database export and replication jobs, maintenance windows and destination ownership before concluding malicious intent.
2. Establish a proper volume baseline for the same account or service, target, business workflow and time period.
3. Correlate proxy/DLP findings with firewall or NetFlow, DNS, authentication, database and endpoint telemetry.
4. Determine the scope and classification of any affected data, subject to authorization and evidence-handling requirements.
5. Confirm that containment is effective in the actual egress controls and identity system, including sessions and alternate authentication methods.
6. Escalate to the Incident Response team. If personal data may be implicated, involve the privacy team to determine whether regulatory breach-notification obligations apply; they are not automatic for every large transfer.

## Lessons learned

- A username containing `admin` does **not** make activity trustworthy; evaluate what the logs actually show.
- The strongest clues in this excerpt are **transfer volume, timing, source, and destination**, not the appearance of the username.
- Distinguish a few comparison records from a real historical baseline.
- **Bytes and bits differ:** 12.9 GB is 103.2 Gb; decimal GB is calculated by dividing bytes by 1,000,000,000.
- A simulator's True Positive classification is not independent proof of a production data breach.
- Distinguish **completed simulator steps**, **actual system-control effects** and **proposed escalation**.

## References

- [MITRE ATT&CK T1048 — Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [IANA — IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
- [Linux usermod(8) manual](https://man7.org/linux/man-pages/man8/usermod.8.html)
