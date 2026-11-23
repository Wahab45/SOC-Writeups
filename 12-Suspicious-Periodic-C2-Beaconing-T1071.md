# ALERT-1012 — Suspicious Periodic Network Connections (Possible C2 Beaconing)

> **Lab:** Work Trainer — simulated SOC Analyst Trainer  
> **Severity in simulator:** Not confirmed by the provided conversation | **Level:** Not confirmed  
> **MITRE ATT&CK:** [T1071 — Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) (scenario mapping; application protocol not established by the log excerpt)  
> **Status:** Connection log reviewed; analyst selected a True Positive classification and discussed destination blocking. A German incident ticket was drafted, but the final simulator checklist was not supplied.  
> **Scope:** Educational investigation, **not** a real incident.

## Investigation objective

A simulated network-connection capture showed unusually uniform traffic. The investigation aimed to identify the source, destination and timing pattern, assess whether the behavior was consistent with command-and-control (C2) beaconing, and choose an appropriate containment action in the training environment.

## Evidence collected

The analyst examined the supplied connection capture using:

```bash
cat ~/cap/conn.txt
```

Relevant excerpt:

```text
10:00:00 10.0.0.12 -> 198.51.100.9:443 bytes=312
10:01:00 10.0.0.12 -> 198.51.100.9:443 bytes=312
10:02:00 10.0.0.12 -> 198.51.100.9:443 bytes=312
10:03:00 10.0.0.12 -> 198.51.100.9:443 bytes=312
10:00:20 10.0.0.40 -> 93.184.216.34:443 bytes=48210
```

| Field | Observation | Interpretation |
|---|---|---|
| Suspected source | `10.0.0.12` | Origin of four repeated recorded connections. |
| Destination | `198.51.100.9:443` | Same destination address and port in all four records. |
| Timing | `10:00:00`, `10:01:00`, `10:02:00`, `10:03:00` | Exact **60-second intervals** between consecutive records. |
| Recorded size | `bytes=312` for each connection | Same byte count in the four records. |
| Other traffic | `10.0.0.40` to `93.184.216.34:443`, `bytes=48210` | A single separate event, not evidence of the same pattern. |

The times were provided without a date or timezone. The excerpt does not establish what the `bytes` metric counts, the application payload or whether any TLS or HTTP exchange succeeded. The destination `198.51.100.9` is a documentation-range IP used in training, **not a production threat indicator**.

## Timing and beaconing analysis

The analyst compared the four records for `10.0.0.12`:

```text
10:00:00 -> 10:01:00 = 60 seconds
10:01:00 -> 10:02:00 = 60 seconds
10:02:00 -> 10:03:00 = 60 seconds
Each record: bytes=312
```

**Behavior indicated by the records:**

1. The same source contacted the same destination and port **four times**.
2. The observed intervals were exactly **60 seconds**.
3. Each record had the same **312-byte** value.

The regular timing and repeated size are compatible with **automated periodic communication**, including possible C2 beaconing.

**Important limitation:** A short four-event sequence is not enough to identify a malicious program. Legitimate monitoring agents, health checks or scheduled applications can also generate predictable connections. Port `443` alone does not establish a particular application protocol or that the traffic was encrypted.

The unrelated single event from `10.0.0.40` should not be treated as part of the periodic pattern merely because it also targeted port 443.

## Findings and confidence

**Observed:**

- Four records from `10.0.0.12` to `198.51.100.9:443`.
- Exact 60-second spacing between the four records.
- Identical recorded size of 312 bytes per connection.

**Assessment:** The evidence establishes a **suspiciously regular communication pattern** consistent with possible C2 beaconing. The learner chose **True Positive** for the SOC training case and proposed blocking the destination. That simulator classification is not independent proof of malware or a real C2 server.

**Not established by the provided evidence:**

- That a malicious process generated the connections.
- That `198.51.100.9` actually operated as a C2 server.
- That commands or sensitive data were transferred.
- Which process, executable, user or scheduled service initiated the traffic.
- Whether a production network-wide block was enforced.
- Whether the simulator accepted the ticket and closed all checklist items.

## Response performed in the simulator

The analyst compared **host isolation** with **destination blocking** and selected the latter to address the observed destination. The training command discussed was:

```bash
ufw deny out to 198.51.100.9
```

The command was provided as the intended step in the SOC Trainer; the learner subsequently stated that **only the ticket remained**, indicating they considered containment done. However, **no command output or completed blocking checklist was supplied** in this conversation, so the exact simulator enforcement result is not independently verified here.

A host-isolation command such as `isolate 10.0.0.12` would have a different, broader effect; `isolate` is a simulator-specific command, not a general Linux command. An `ufw deny out` rule applies to the host/firewall where it is configured and does **not** automatically block traffic across an entire organization.

A German-language incident ticket was drafted with source `10.0.0.12`, destination `198.51.100.9:443`, 60-second intervals, 312 bytes per event, the learner's True Positive classification and the intended block. **The learner has not yet supplied a final ticket submission or all-items checklist**, so the case is not represented as fully closed.

## Recommended production follow-up (not performed in the lab)

- Check endpoint process, executable, user, scheduled-task and service telemetry for connections from `10.0.0.12`.
- Extend the analysis over a longer time window and compare destination, timing, jitter, volume and known software behavior.
- Enrich the real destination address and review authorized monitoring, update and management services.
- Correlate EDR, DNS, proxy, firewall and network-flow logs to assess the process and any delivered content where permitted.
- If containment is justified, apply an approved egress block or EDR isolation at the appropriate control point, then **verify** the result.
- Preserve relevant artifacts, document investigation limits and escalate if endpoint compromise or additional C2 indicators are confirmed.

## Lessons learned

- **Periodicity plus consistent size** is a useful anomaly signal, but cannot by itself prove C2.
- Four events at 60-second intervals are stronger pattern evidence than one isolated larger transfer.
- A destination port number alone does not establish the application protocol.
- **Block a destination** and **isolate a host** are distinct containment strategies with different operational impact.
- Separate the learner's decision, the simulator's acceptance state and independently verified technical effects.

## References

- [MITRE ATT&CK T1071 — Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [IANA IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
- [Ubuntu UFW documentation](https://documentation.ubuntu.com/server/how-to/security/firewalls/)
