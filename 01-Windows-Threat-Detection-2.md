# Windows Threat Detection 2
**Platform:** TryHackMe — SOC Level 1  
**Topic:** Post-Exploitation Detection on Windows  
**Difficulty:** Beginner  

---

## Scenario Overview

A threat actor successfully breached a Windows host. 
The goal was to detect attacker activity after initial access 
using Windows Event Logs and Sysmon.

---

## Detection Methodology

### Phase 1 — Brute Force Detection
**Tool:** Windows Event Viewer  

| Event ID | Meaning |
|----------|---------|
| 4625 | Failed logon attempt |
| 4624 | Successful logon |

**Logic:** Multiple 4625 events from the same source  
followed by a 4624 = confirmed Brute Force success.

---

### Phase 2 — Post-Exploitation Detection
**Tool:** Sysmon

| Event ID | Meaning | Why It Matters |
|----------|---------|----------------|
| 1 | Process Creation | Detects malicious process execution |
| 11 | File Created | Tracks dropped payloads or scripts |
| 13 | Registry Value Set | Detects persistence mechanisms |

---

## Key Findings

- Brute force attack confirmed via Event ID 4625/4624 correlation
- Malicious process executed post-access (Sysmon ID 1)
- File dropped on system (Sysmon ID 11)
- Registry modified for persistence (Sysmon ID 13)

---

## Lessons Learned

- Correlating failed + successful logons is essential for Brute Force detection
- Sysmon provides deeper visibility than default Windows logs
- Registry modifications (ID 13) are a strong indicator of persistence attempts

---

**Author:** Abdalwahab Abdalrazak  
**Date:** June 2026  
**Profile:** github.com/Wahab45
