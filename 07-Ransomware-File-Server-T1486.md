# ALERT-1007 — Ransomware Suspicion on a File Server (T1486)

> **Lab:** Work Trainer / SOC Analyst Trainer — simulated environment  
> **Severity in simulator:** Critical | **Level:** Intermediate  
> **MITRE ATT&CK:** [T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)  
> **Status:** Investigation and containment discussed; the final ticket checklist was **not independently confirmed complete** in the recorded session.  
> **Scope:** Educational case study, not evidence of a real production incident.

## Investigation objective

Investigate reports that files on the shared directory `/srv/share` had acquired the extension `.locked`. Use endpoint detection and response (EDR) telemetry to identify a likely source host, contain the suspected activity and document remaining uncertainty.

## Observed evidence

### File-system findings

The analyst used:

```bash
find /srv/share -type f -name '*.locked'
```

The simulator returned:

```text
/srv/share/a.docx.locked
/srv/share/b.xlsx.locked
/srv/share/c.pdf.locked
```

**Verified in the displayed output:** Three filenames ending in `.locked` were found in the searched tree.

**Important limitation:** The extension alone does **not** cryptographically prove that the file contents were encrypted. Three listed paths also do not establish the full number of affected files elsewhere in the environment.

### EDR timeline

The analyst read `/var/log/edr.log` using `cat` and received:

```text
09:40:11 WS-14 10.0.0.14 proc=enc.exe parent=outlook.exe action=file_rename count=1200
09:40:15 WS-14 10.0.0.14 net=SMB write /srv/share
```

| Time | Asset | Observation | Interpretation |
|---|---|---|---|
| 09:40:11 | `WS-14` / `10.0.0.14` | `enc.exe` launched with `outlook.exe` recorded as the parent; EDR recorded `file_rename count=1200`. | High-volume rename activity is suspicious in context, but the exact file scope and the meaning of the event's count require validation. |
| 09:40:15 | `WS-14` / `10.0.0.14` | SMB write to `/srv/share`. | A network write by the same asset occurred four seconds after the rename event. |

The log excerpt does not contain an event date or timezone.

### Assessment

The combination of `.locked` filenames, unusually high rename activity, a process named `enc.exe`, and SMB writes toward the affected share is **strongly consistent with ransomware activity**. It justifies urgent containment of `WS-14`.

It does **not** establish, from the supplied excerpt alone, that:

- The file contents were encrypted and unrecoverable.
- All 1,200 renames represent 1,200 confirmed encrypted files.
- An email attachment was the entry point merely because `outlook.exe` was the parent process.
- Data was exfiltrated or additional hosts were compromised.

**Simulator classification target:** True Positive — Ransomware. The real-world assessment would remain evidence-led and require additional confirmation of impact.

## Response and containment

During the lab the analyst selected `WS-14` (`10.0.0.14`) for isolation based on the EDR findings and reported that the isolation action was performed using:

```text
isolate WS-14
```

`isolate` is a **training-simulator command**, not a standard Linux command.

**Evidence status:** The user reported completing the isolation step. A separate post-isolation verification output or completed isolation checklist was not included in the conversation; isolation effectiveness therefore remains **unverified in this report**.

### Linux network-control distinction

A firewall rule on the file server such as `sudo ufw deny from 10.0.0.14` can block traffic from that source **to that server**, if applicable and properly ordered. It is **not equivalent to isolating the entire endpoint**. A Linux host's network interface can be administratively disabled, but doing so remotely may sever management access. For an endpoint like `WS-14`, containment through the actual deployed EDR or endpoint-management system is generally more appropriate.

## Ticket and backup recovery notes

The analyst discussed and attempted to document:

- Classification: **True Positive — Ransomware** (simulator requirement).
- Suspected host: `WS-14` (`10.0.0.14`).
- Suspicious process: `enc.exe`; parent: `outlook.exe`.
- EDR rename and SMB events.
- A requirement to verify backup integrity and recoverability **before** restoration.

A backup-related sentence was submitted to a shell command once with an incorrect path (`~./ticket.txt`), which generated a file-not-found error. A corrected command was then suggested. At a later point, the simulator still showed two ticket checks as incomplete: classification and host/process naming. A complete ticket command was provided to the learner, but **no subsequent checklist confirmation was shown**. Accordingly, this write-up does not claim that the final incident ticket was accepted or that backups were tested.

### Next steps for a real incident (not performed in the lab)

1. Verify endpoint isolation and stop unauthorized access to the share using approved incident-response procedures.
2. Preserve relevant forensic evidence (endpoint telemetry, process details, share logs, and ransom indicators) before cleanup.
3. Determine whether content was actually encrypted, assess the extent of impact, and look for lateral movement.
4. Determine the execution chain and entry point rather than assuming Outlook was the source.
5. Assess backup integrity, isolation from the attacker, and recoverability with a controlled restore test.
6. Rebuild or recover only after containment and eradication have been validated; document follow-up monitoring.

## Detection and troubleshooting lessons

- `find` is suitable for finding filenames by extension; `grep` searches file content.
- A rename burst paired with SMB writes is a useful signal, but it requires correlation with process, host, user and file-level events.
- Use the source host, not a VPN-session command, when planning endpoint isolation.
- Distinguish **reported action**, **completed simulator step**, and **verified technical effect**.
- Never record a backup as clean or successfully restored without supporting evidence.

## References

- [MITRE ATT&CK T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [CISA — StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)
