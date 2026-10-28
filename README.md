# SOC Write-ups

Evidence-based SOC investigation notes from simulated training labs and previous study exercises, including TryHackMe SOC Level 1.

**Purpose:** Build an honest, progressively stronger SOC analyst portfolio through real learning. A completed lab is not necessarily a confirmed real-world security incident.

## Investigation index

| # | Write-up | Topic | Context |
|---|---|---|---|
| 01 | [Windows Threat Detection 2](01-Windows-Threat-Detection-2.md) | Windows logon events, Sysmon, post-authentication triage | Historical training notes; evidence limitations explicitly documented |
| 02 | [SSH Brute-Force Triage](02-SSH-Brute-Force-Triage.md) | Linux authentication logs, false attribution, attempted brute force | Work Trainer simulated SOC lab |
| 03 | [Firewall Port-Scan Triage](03-Firewall-Port-Scan-Triage.md) | DROP events, source aggregation, reconnaissance | Work Trainer simulated SOC lab |
| 04 | [Phishing Email Triage](04-Phishing-Email-Triage.md) | SPF, Reply-To, typosquatting, suspicious attachment | Work Trainer simulated SOC lab |
| 05 | [VPN Impossible Travel](05-VPN-Impossible-Travel-T1078.md) | VPN authentication, Tor exit node, access anomaly, containment | Work Trainer simulated SOC lab |

## Publication standards

- Separate **observed evidence**, **inferences**, **hypotheses**, and **unverified claims**.
- Explain whether a finding comes from a local simulator, an external training platform, or a real environment.
- Sanitize logs and addresses; never post real customer data, credentials, access tokens, API keys, personal records or protected challenge flags.
- Do not equate a True Positive alert with a confirmed intrusion or data exfiltration.
- Record limitations and verification steps; do not invent missing observations.
- Prioritize quality over posting frequency.

## Contributing another investigation

Use [WRITEUP_TEMPLATE.md](WRITEUP_TEMPLATE.md). Only add a case when it provides a distinct, useful insight and its claims can be supported by retained evidence.

**Repository:** [Wahab45/SOC-Writeups](https://github.com/Wahab45/SOC-Writeups)
