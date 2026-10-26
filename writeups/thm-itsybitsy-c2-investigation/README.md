# TryHackMe - ItsyBitsy Writeup

**Room:** ItsyBitsy (SOC Level 1 > SIEM Triage for SOC)
**Tools:** Elastic / Kibana (Discover, KQL)
**Topic:** investigating suspected C2 communication from connection logs

## Scenario

During normal SOC monitoring, Analyst **John** observed an IDS alert indicating potential C2 communication from a user, **Browne**, in the HR department. A suspicious file was accessed containing a malicious pattern `THM:{ ________ }`. A week-long set of HTTP connection logs was pulled and ingested into the `connection_logs` index in Kibana.

---

## 1. How many events were returned for the month of March 2022?

**Answer: `1482`**

Set the time range in Kibana Discover from **March 1, 2022 00:00:00** to **April 1, 2022 00:00:00** (adjust it to match your own dashboard), then select the `connection_logs` index. The range must cover exactly one month because the question only counts events from March 2022. The total appears at the top left (1482 hits).

Next, add the columns `source_ip`, `destination_ip`, `destination_port`, `host`, `method`, and `user_agent` from the "Available fields" panel. This makes each event readable at a glance without expanding it one by one.

![Event count for March 2022](images/01-event-count-maret.png)

---

## 2. What is the IP associated with the suspected user in the logs?

**Answer: `192.166.65.54`**

The scenario points to C2 communication from the machine of user Browne (HR), so that machine is presumed compromised. The goal is to find which `source_ip` behaves suspiciously. I started by checking the distribution of `source_ip` values (click the `source_ip` field in the sidebar) to see which internal hosts appear in the logs.

![source_ip distribution](images/02-sebaran-source-ip.png)

At first I assumed `192.166.65.52` was the suspect because it dominates the logs (about 99.6% of the 500 sample events Kibana displays). However, in the visible events it only contacts common domains such as `redirector.gvt1.com`, `storage.googleapis.com`, and `au.download.windowsupdate.com`, which is normal traffic. High traffic volume does not necessarily mean malicious activity. C2 traffic is often small and infrequent, so the IP with very few events (`192.166.65.54`) deserved a closer look.

I then filtered with KQL:

```
source_ip : 192.166.65.54
```

This returned only 2 events (HEAD and GET) to `pastebin.com` with the `user_agent` `bitsadmin`, so this is the IP suspected of C2 communication.

![Filter on source_ip 192.166.65.54](images/03-ip-mencurigakan-bitsadmin.png)

---

## 3. The user's machine used a legit Windows binary to download a file from the C2 server. What is the name of the binary?

**Answer: `bitsadmin`**

From the filter in the previous question, the `user_agent` for IP `192.166.65.54` is `bitsadmin`, a built-in Windows tool (a legitimate binary) that can be used to download files. Attackers often use it so the download looks legitimate and evades detection. Abusing built-in system tools like this is known as **Living Off The Land (LOLBin)** and maps to MITRE ATT&CK **T1197 (BITS Jobs)**.

BITS (Background Intelligent Transfer Service) is a Windows service that handles background data transfers. Transfers can resume after a connection drops, which makes it well suited for downloading large files or system updates. `bitsadmin.exe` is the command-line tool for managing BITS. Because BITS is a legitimate Windows component, its traffic is often treated as normal and can be abused to download payloads from a C2 server.

![bitsadmin user_agent](images/03-ip-mencurigakan-bitsadmin.png)

---

## 4. What is the name of the filesharing site?

**Answer: `pastebin.com`**

I wanted to know which hosts `192.166.65.54` contacted. In the filtered results from question 2, the `host` column shows only one destination: `pastebin.com`. Text-sharing sites like this are often abused to store C2 commands or payloads because the domain looks legitimate and is rarely blocked.

> **Pastebin** is a website where anyone can paste text and get a link to share it. It is commonly used by programmers to share code snippets or error logs. No account is required, and the text can be opened directly through the link.

---

## 5. What is the full URL of the C2 to which the infected host is connected?

**Answer: `pastebin.com/yTg0Ah6a`**

The full URL comes from combining `host` and `uri` from the same event. In the `source_ip` `192.166.65.54` filter (question 2), the host is `pastebin.com`, the connection went to port 80 (HTTP) on March 10, 2022 at 18:23:11, and the `uri` is **`/yTg0Ah6a`**.

![Pastebin URI](images/04-uri-pastebin.png)

---

## 6. What is the name of the file accessed?

**Answer: `secret.txt`**

Open the URL from question 5 (`pastebin.com/yTg0Ah6a`) and the file name is shown on the page.

![secret.txt paste content](images/05-secret-txt.png)

---

## 7. The file contains a secret code with the format THM{_____}.

**Answer: `THM{SECRET__CODE}`**

---

## Summary of Findings (IOCs)

| Item | Value |
|---|---|
| Infected host | `192.166.65.54` (user Browne, HR) |
| LOLBin | `bitsadmin` (user_agent), MITRE ATT&CK T1197 BITS Jobs |
| C2 site | `pastebin.com` (`104.23.99.190`, port 80/HTTP) |
| C2 URL | `pastebin.com/yTg0Ah6a` (March 10, 2022 18:23:11) |
| File | `secret.txt`, content: `THM{SECRET__CODE}` |

**Note:** in a real environment, never open a suspicious URL directly in a regular browser. Analyze it first in a sandbox or with services such as urlscan.io and VirusTotal, because the page may contain malware. In this lab it is safe because the URL is provided by TryHackMe.

**Recommended response actions:** isolate the machine `192.166.65.54`, block access to the URL at the proxy/firewall, then perform further endpoint checks (for example, review BITS jobs history) and reset user Browne's credentials.
