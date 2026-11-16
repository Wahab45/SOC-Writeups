# ALERT-1011 — Suspicious DNS TXT Queries and Possible DNS Tunneling

> **Lab:** Work Trainer — simulated SOC Analyst Trainer  
> **Severity in simulator:** Not independently confirmed from the supplied checklist | **Level:** Not verified  
> **MITRE ATT&CK:** [T1071.004 — Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)  
> **Status:** Source investigation and simulated DNS-domain blocking confirmed. A German ticket was drafted, but the learner has not supplied a final checklist confirming the ticket and True Positive classification.  
> **Scope:** Educational investigation, **not** a real incident.

## Investigation objective

A simulated network-capture export raised concern about conspicuously long DNS queries. The investigation aimed to find the originating host and queried domain, evaluate whether the query structure was consistent with DNS tunneling, and block the suspicious destination in the training simulator.

## Evidence collected

The analyst inspected the simulated DNS export using:

```bash
cat ~/cap/dns.txt
```

The provided log contained:

```text
10.0.0.12 A q=www.example.org
10.0.0.12 TXT q=aGVsbG8gd29ybGQ1.x7f3k2.evil-tunnel.example
10.0.0.12 TXT q=c2VjcmV0cGFzc3dk.x7f3k2.evil-tunnel.example
10.0.0.12 TXT q=ZGF0YWRhdGFkYXRh.x7f3k2.evil-tunnel.example
10.0.0.33 A q=mail.example.org
```

| Field | Observation | Interpretation |
|---|---|---|
| Suspicious source | `10.0.0.12` | Host associated with all three unusual TXT queries. |
| Query type | `TXT` | Legitimate DNS record type, sometimes misused to carry encoded data. |
| Destination domain | `evil-tunnel.example` | Common suffix across the three suspicious queries. |
| Query labels | Changing Base64-like first labels and repeated `x7f3k2` label | Pattern potentially consistent with data being embedded in DNS query names. |
| Other source | `10.0.0.33` queried `mail.example.org` (A record) | Separate query; no demonstrated connection to the suspicious pattern. |

The `.example` domains are reserved for documentation and appear here only in training data. The supplied text provides neither timestamps nor DNS responses or network-transfer totals.

## DNS query pattern analysis

The analyst examined the DNS record types and domain labels, then safely decoded one label using:

```bash
echo 'aGVsbG8gd29ybGQ1' | base64 -d
```

The displayed output was:

```text
hello world5
```

**Behavior indicated by the observed queries:**

1. Three TXT queries originate from `10.0.0.12` and target subdomains under `evil-tunnel.example`.
2. Their first labels differ and resemble encoded data, unlike a typical human-readable hostname.
3. One inspected label decodes as readable text, consistent with data being **encoded inside a query name**.

**Important limitation:** Decoding one label establishes the encoding in this sample, not unauthorized data transfer. DNS tunneling is a plausible hypothesis, but without DNS response content, authorized-use context, capture timestamps, traffic volume and endpoint telemetry, the available lines alone do **not** establish successful exfiltration or remote command-and-control.

The Base64 decoding was performed as an optional analytical step; the simulator's listed checklist items did **not** require it.

## Findings and confidence

**Observed:**

- `10.0.0.12` issued three TXT queries containing data-like labels to the same domain.
- A selected query label decoded to `hello world5`.
- The learner identified the source and queried-domain pattern.

**Assessment:** The pattern is **suspicious and compatible with possible DNS tunneling**. The simulator requires a **True Positive** ticket classification for its exercise, but that planned classification is separate from a verified claim that data actually left the organization.

**Not established by the provided evidence:**

- Whether the queried labels contain sensitive information.
- Whether any data was successfully received by an attacker-controlled DNS server.
- Whether the domain or host was compromised, or why the queries were generated.
- Whether the traffic represents exfiltration rather than a benign test or approved DNS-based mechanism.
- Whether the simulator's final two ticket-related checklist conditions were completed.

## Response performed in the simulator

The analyst executed the training-specific command:

```text
dnsblock evil-tunnel.example
```

The subsequent simulator checklist showed **Source investigated** and **Domain blocked** checked.

`dnsblock` is **specific to the SOC training simulator**, not a standard Linux command. The conversation does not contain verification of a production DNS resolver policy or external blocking effectiveness.

A German incident-ticket draft was provided naming host `10.0.0.12`, the `evil-tunnel.example` domain, the suspicious TXT-query pattern, the simulator's intended True Positive label and the domain-blocking action. **The analyst did not yet report submitting or checking the ticket**, so no ticket-completion or full-case-closure claim is made.

## Recommended production follow-up (not performed in the lab)

- Identify the process and user responsible for the queries on `10.0.0.12`; inspect endpoint and resolver telemetry.
- Correlate DNS questions, response codes, TXT responses, query rate, label lengths and time distribution.
- Evaluate whether the data-like labels encode actual sensitive material; preserve evidence and avoid unnecessary execution of decoded content.
- Verify the domain's ownership, approved testing status and whether DNS-based application protocols are expected.
- Check DNS egress controls and block or sinkhole indicators under the organization's authorized incident-response procedures.
- Hunt across DNS logs for other hosts using the same domain or similar query structure and escalate based on verified impact.

## Lessons learned

- A DNS TXT record is not malicious by itself; the **query pattern and surrounding context** matter.
- Long encoded-looking subdomain labels can indicate tunneling, but are **not proof of data exfiltration**.
- Base64 is **encoding**, not encryption; decoding a string safely does not run its contents.
- Isolate simulator checklist outcomes from real network-security control effectiveness.
- Distinguish the source IP, the queried DNS name and the specific evidence needed to support a True Positive decision.

## References

- [MITRE ATT&CK T1071.004 — Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)
- [RFC 1035 — Domain Names: Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035)
- [IANA — Example Domains](https://www.iana.org/help/example-domains)
