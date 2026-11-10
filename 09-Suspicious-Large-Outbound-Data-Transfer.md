# ALERT-1009 — Suspicious Large Outbound Data Transfer

> **Lab:** Work Trainer — simulated SOC Analyst Trainer  
> **Severity in simulator:** Critical | **Level:** Expert  
> **MITRE ATT&CK:** [T1048 — Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/) (scenario label; protocol not confirmed in the log)  
> **Status:** Log analysis, destination block and account password lock completed in the simulator; analyst reported writing a ticket. A final all-items checklist was not supplied.  
> **Scope:** Educational investigation, **not** a real incident.

## Investigation objective

A Data Loss Prevention (DLP) alert identified unusually large outbound traffic during nighttime hours. The investigation aimed to identify the source account and destination, estimate the transferred volume, distinguish a suspicious transfer from proven unauthorized exfiltration, and contain the activity within the training environment.

## Evidence collected

The analyst read the simulated proxy log using:

```bash
cat /var/log/proxy.log
```

Relevant excerpt:

```text
02:50:10 jsmith 10.0.0.31 93.184.216.34 BYTES=120000
03:12:01 dbadmin 10.0.0.9 203.0.113.50 BYTES=8800000000
03:14:20 dbadmin 10.0.0.9 203.0.113.50 BYTES=4100000000
09:15:00 jsmith 10.0.0.31 93.184.216.34 BYTES=90000
```

| Field | Observation | Interpretation |
|---|---|---|
| Account | `dbadmin` | User associated with the two large transfer records. |
| Source | `10.0.0.9` | Internal address shown in both records. |
| Destination | `203.0.113.50` | Same destination for both large transfers. |
| Timing | `03:12:01` and `03:14:20` | Two unusually large records, 2 minutes 19 seconds apart. |
| Comparison events | `jsmith` transferred 120,000 and 90,000 bytes | Much smaller records, but not an established baseline for `dbadmin`. |

The records contain times but no date, timezone or protocol. The **DLP scenario** describes the activity as outbound; the individual log lines do not specify direction. `203.0.113.50` belongs to a documentation-only address range in this **simulated** scenario, not a production indicator.

## Transfer volume analysis

The analyst compared the recorded byte counts and calculated the total:

```text
dbadmin: 8,800,000,000 + 4,100,000,000 = 12,900,000,000 bytes = 12.9 GB
jsmith:        120,000 +        90,000 =        210,000 bytes = 0.21 MB
```

**Behavior indicated by the records:**

1. `dbadmin` was associated with approximately **12.9 GB** in two entries during the night.
2. Both entries used the same internal source and external destination.
3. The volume greatly exceeded the `jsmith` entries shown in this small excerpt.

**Important baseline nuance:** Two events from another user are **not a reliable historical baseline** for `dbadmin`. A real assessment would compare this transfer with the account's normal behavior, approved destinations, business processes and scheduled jobs.

The record supports an unusually large transfer. **It does not independently prove that the transfer was unauthorized or that sensitive data was stolen.**

## Findings and confidence

**Observed:**

- The simulated proxy log recorded two large `dbadmin` transfers totaling **12.9 GB**.
- Both records had source `10.0.0.9` and destination `203.0.113.50`.
- The events occurred at `03:12:01` and `03:14:20`.

**Assessment:** The combination of transfer size, timing and concentration on one account and destination warrants investigation and containment. The training incident was classified as **True Positive — Data Exfiltration** for the simulator checklist. That classification is not independent confirmation of a real unauthorized data transfer.

**Not established by the provided evidence:**

- Whether the transfer was an approved backup, replication job or scheduled export.
- Whether confidential or personal information was involved.
- Whether `dbadmin` was compromised or its active sessions were controlled by an attacker.
- Whether the `BYTES` field represents successfully delivered content.
- Whether MITRE ATT&CK **T1048** specifically applies; the protocol was not recorded.

## Response performed in the simulator

The analyst reported applying these commands:

```bash
sudo ufw deny out to 203.0.113.50
sudo usermod -L dbadmin
```

The analyst subsequently confirmed the simulator checklist items **Destination blocked** and **Account locked**. **Proxy log sorted/analyzed** was also marked complete.

The firewall command affects the outbound policy of the host where it is applied; it does not by itself prove organization-wide egress control. The `usermod -L` command locks the local Linux account password but does not necessarily terminate active sessions or block SSH key authentication.

The analyst also reported submitting a German incident ticket naming `dbadmin`, the destination IP, the 12.9 GB volume and the completed simulator containment actions. The ticket recommended escalation to the Incident Response team. A final screenshot or checklist confirming every ticket criterion was **not** supplied; escalation was not independently verified as completed.

## Recommended production follow-up (not performed in the lab)

- Check approved backup, replication and export schedules, change records and ownership of the destination.
- Build a suitable baseline using historical traffic for the affected account, service and workflow.
- Correlate DLP and proxy findings with firewall or NetFlow, DNS, endpoint, authentication and database audit telemetry.
- Determine the types of data involved and whether transfer was authorized, using approved evidence-handling procedures.
- Confirm network containment at the actual enforcement point and validate account, session and credential restrictions.
- Escalate to Incident Response and, where a personal data breach is suspected, involve the privacy team to assess any applicable notification obligations.

## Lessons learned

- A username containing `admin` is not proof of legitimate activity.
- Large data volume and unusual timing are triage signals, **not proof of malicious exfiltration**.
- A few comparison records do not replace an established behavioral baseline.
- `12.9 GB` is a decimal byte volume; multiplying by eight converts **bytes to bits**, not to gigabytes.
- Distinguish completed simulator checklist items from independently verified production containment.

## References

- [MITRE ATT&CK T1048 — Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [IANA — IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
- [Linux usermod(8) manual](https://man7.org/linux/man-pages/man8/usermod.8.html)
