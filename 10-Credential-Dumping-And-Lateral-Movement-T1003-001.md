# ALERT-1010 — Suspected Credential Dumping on a Domain Controller

> **Lab:** Work Trainer — simulated SOC Analyst Trainer  
> **Severity in simulator:** Critical | **Level:** Expert  
> **MITRE ATT&CK:** [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)  
> **Status:** Event-log review, simulated source isolation and account password lock were confirmed by the checklist. An incident ticket was drafted, but final ticket/checklist completion was not supplied.  
> **Scope:** Educational investigation, **not** a real incident.

## Investigation objective

A security alert reported unusual activity on a domain controller at night. The investigation aimed to reconstruct the order of Windows security events, identify evidence of attempted credential dumping, assess a possible connection to a later administrator login on a file server, and contain the suspected source within the training simulator.

## Evidence collected

The analyst read the simulated event log using:

```bash
cat /var/log/win-events.log
```

Relevant excerpt:

```text
02:11:05 EventID=4625 user=svc-backup src=10.0.0.55 FAILED
02:11:40 EventID=4624 type=3 user=svc-backup src=10.0.0.55 host=SRV-DC1
02:12:03 EventID=4672 user=svc-backup privileges=SeDebugPrivilege host=SRV-DC1
02:13:20 EventID=4688 host=SRV-DC1 proc=procdump.exe args=-ma lsass.exe
02:20:00 EventID=4624 type=3 user=Administrator src=10.0.0.40 host=SRV-FS1
```

| Event | Observation | Interpretation |
|---|---|---|
| `4625` | Failed login for `svc-backup` from `10.0.0.55` at 02:11:05. | One failed authentication; not sufficient on its own to demonstrate an attack. |
| `4624` | `svc-backup` network logon (type 3) from `10.0.0.55` to `SRV-DC1` at 02:11:40. | Successful network logon 35 seconds after the failed attempt. |
| `4672` | `SeDebugPrivilege` assigned to `svc-backup` on `SRV-DC1` at 02:12:03. | A special privilege associated with a logon; this does not alone prove malicious use. |
| `4688` | `procdump.exe` launched with `-ma lsass.exe` on `SRV-DC1` at 02:13:20. | A process was created that appears intended to request a full dump of LSASS memory. |
| `4624` | `Administrator` network logon from `10.0.0.40` to `SRV-FS1` at 02:20:00. | Later activity on another host, but not proven connected to the earlier source or process. |

The records include times but no date or timezone. The provided `4688` entry also lacks the executing username, `SubjectLogonId`, command-line context beyond the shown arguments, and a dump creation result.

## Event correlation and process analysis

The analyst reconstructed this sequence:

1. One failed `svc-backup` authentication was followed by a successful network logon from the **same source IP** to the domain controller.
2. The account was then associated with a special-privilege event on `SRV-DC1`.
3. Roughly one minute later, `SRV-DC1` logged the creation of `procdump.exe` with arguments targeting `lsass.exe`.
4. A later `Administrator` logon was recorded on `SRV-FS1`, but its source was **`10.0.0.40`**, not `10.0.0.55`.

**Why the process matters:**

- `procdump.exe` is a legitimate Sysinternals diagnostic tool that can create process-memory dumps.
- `-ma` requests a full memory dump; the target in the record is `lsass.exe`, the Windows Local Security Authority process.
- LSASS memory may contain sensitive authentication material, making an attempted dump on a domain controller a serious credential-access signal.

**Important correlation nuance:** Matching `SRV-DC1` and closely spaced timestamps does **not** prove `svc-backup` launched `procdump.exe`. The `4688` entry shown does not identify the user or logon session responsible. A real investigation would correlate `SubjectUserName`, `SubjectLogonId`, process identifiers and endpoint telemetry.

Similarly, the later `Administrator` network logon on `SRV-FS1` is **not proof of lateral movement** without additional evidence linking the sessions, source systems, credentials and actions.

## Findings and confidence

**Observed:**

- A failed-then-successful network logon sequence for `svc-backup` from `10.0.0.55`.
- A special-privilege event for `svc-backup` on the domain controller.
- A `procdump.exe -ma lsass.exe` process-creation record on the domain controller.
- A later successful `Administrator` network logon to a separate file server from `10.0.0.40`.

**Assessment:** The process activity targeting LSASS on a domain controller is sufficiently concerning to treat as **True Positive — suspicious credential-dumping activity** in the simulator and to escalate promptly. It is not by itself definitive evidence of completed credential theft. The case's lateral-movement component remains an **investigative hypothesis**.

**Not established by the provided evidence:**

- That a valid LSASS dump file was successfully created or its contents obtained.
- That `svc-backup` launched `procdump.exe`.
- That `svc-backup` or `Administrator` credentials were stolen.
- That the `Administrator` login on `SRV-FS1` was initiated by the suspected actor.
- That the Active Directory domain was fully compromised.

## Response performed in the simulator

The analyst chose to isolate the suspicious source and lock the associated account password:

```text
isolate 10.0.0.55
```

```bash
sudo usermod -L svc-backup
```

The simulator checklist supplied by the analyst showed **Event log read**, **Account svc-backup locked** and **Source 10.0.0.55 isolated** as completed.

The `isolate` action is **simulator-specific**, not a standard Linux command. `usermod -L` locks the password of a **local Linux account**; it does not automatically disable a corresponding Active Directory service account, revoke Kerberos tickets, terminate existing sessions or invalidate alternate authentication methods.

A German incident ticket was then provided, including the `4624`–`4672`–`4688` timeline, suspected LSASS dumping, True Positive classification, containment actions and an escalation recommendation. It also requested that the AD/IR team **assess a controlled `krbtgt` reset if domain compromise is confirmed or strongly suspected**. This is a conditional recommendation, **not** evidence that any reset took place or should be performed automatically.

**Verification limit:** The analyst did not supply a subsequent simulator output showing the final ticket-related checklist items as completed. Actual IR escalation and a `krbtgt` reset were not observed.

## Recommended production follow-up (not performed in the lab)

- Validate the account's real identity, authorized service use and expected backup activity; coordinate containment to avoid disrupting legitimate backups.
- Examine the complete `4688` event and EDR process tree, including the executing user, logon session, parent process, command line and any generated dump artifact.
- Inspect endpoint/EDR telemetry, file creation and access, and security tooling around LSASS to determine whether the dump attempt succeeded.
- Correlate the later `Administrator` login with source-host telemetry, logon IDs, account activity and file-server events before claiming lateral movement.
- Verify endpoint isolation and lock or disable compromised accounts **in the actual AD/identity infrastructure**; assess and revoke active sessions or credentials as appropriate.
- Escalate urgently to the incident-response and Active Directory teams. If domain compromise is established or strongly suspected, develop a coordinated recovery plan, including an appropriately sequenced **two-stage `krbtgt` password reset** when justified; do not reset it reflexively based solely on these five events.
- Preserve available logs and artifacts, record timestamps and control outcomes, and assess other high-privilege accounts and domain controllers.

## Lessons learned

- An Event ID is a **starting point for interpretation**, not a verdict by itself.
- The same host and a close timestamp support a correlation hypothesis, **not proof** that the same account launched a process.
- `procdump.exe` targeting LSASS can indicate credential-dumping intent, but a process-creation event does **not** verify a completed dump.
- A later administrator network logon from a different source IP is **not confirmed lateral movement**.
- Treat simulator checklist completion, actual endpoint containment and domain-wide recovery as separate evidence levels.

## References

- [MITRE ATT&CK T1003.001 — LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [Microsoft — Event 4624: An account was successfully logged on](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [Microsoft — Event 4672: Special privileges assigned to new logon](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672)
- [Microsoft — Event 4688: A new process has been created](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- [Microsoft — ProcDump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump)
