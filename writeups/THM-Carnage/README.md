# THM Carnage — Network Traffic Analysis

**Platform:** TryHackMe  
**Room:** Carnage  
**Category:** Network Analysis  
**Difficulty:** Medium  
**Tools Used:** Wireshark, VirusTotal  
**Status:** Completed ✅

---

## Scenario

Eric Fischer, an employee of a company, received an email with a malicious attachment. He clicked "Enable Content" on a Word document, triggering a malware infection. A network capture (`carnage.pcap`) was taken from his endpoint during the infection. The task is to analyze the traffic and reconstruct what happened.

**Victim Host:** `10.9.23.102` | `DESKTOP-IOJC6RB`

---

## Step 1 — Initial Triage (Getting the Big Picture)

Before diving into specific questions, I always start by getting an overview of the capture using three key features in Wireshark.

### Protocol Hierarchy

Navigate to: `Statistics > Protocol Hierarchy`

This shows which protocols generated the most traffic and helps identify what kind of activity occurred.

![Protocol Hierarchy — Part 1](images/carnage_img02_protocol_hierarchy.png)
![Protocol Hierarchy — Part 2](images/carnage_img03_protocol_hierarchy2.png)

**Key observations:**
- **TCP (98.5%)** dominates — most traffic is connection-based
- **TLS (20.3%, 77.3% bytes)** — heavily encrypted HTTPS traffic indicating C2 communication
- **SMTP (2.0%)** — email activity, which is unusual for a regular endpoint and may indicate malspam
- **HTTP (0.6%)** — unencrypted web traffic where we can read the content directly
- **SMB2 (0.5%)** — internal file sharing activity

### Conversations (Top Talkers)

Navigate to: `Statistics > Conversations > IPv4`

Sort by **Bytes** to see which IP addresses communicated the most with the victim.

![Conversations — IP Top Talkers](images/carnage_img04_conversations.png)

The victim `10.9.23.102` had the highest traffic volume with several external IPs. The top talkers become our primary investigation targets.

### Endpoints

Navigate to: `Statistics > Endpoints > IPv4`

![Endpoints](images/carnage_img05_endpoints.png)

The victim machine `10.9.23.102` clearly stands out as the top endpoint with 70,419 packets and 54MB of traffic — confirming it is the infected host.

### Expert Information

Navigate to: `Analyze > Expert Information`

This auto-flags anomalies Wireshark detected during capture.

![Expert Information — Page 1](images/carnage_img06_expert_info1.png)
![Expert Information — Page 2](images/carnage_img07_expert_info2.png)
![Expert Information — Page 3](images/carnage_img08_expert_info3.png)

**Notable flags:**
- `GET /incidunt-consequatur/documents.zip HTTP/1.1` — suspicious ZIP download immediately visible
- Multiple POST requests to an unusual path (`/zLIisQRWZI9/...`) — characteristic of C2 beaconing
- `Illegal characters found in header name` — malformed HTTP headers, often seen in malware traffic
- `Connection reset (RST)` — abrupt connection terminations

---

## Step 2 — HTTP Analysis (First Contact with Malicious IP)

Since the first few questions relate to HTTP, I filtered specifically for HTTP traffic.

Apply filter: `http.request`

To set timestamps to UTC: `View > Time Display Format > UTC Date and Time of Day`

![HTTP Request Filter](images/carnage_img09_http_request_filter.png)
![Time Display Format Setting](images/carnage_img10_time_display.png)

The very first HTTP connection to an external IP stands out:

```
Frame 1735 | 2021-09-24 16:44:38
Source      : 10.9.23.102
Destination : 85.187.128.24
Method      : GET
URI         : /incidunt-consequatur/documents.zip
Host        : attirenepal.com
```

Following the HTTP Stream confirms the download:

![HTTP Stream — ZIP Download (Headers)](images/carnage_img11_http_stream_zip.png)
![HTTP Stream — ZIP Contents (XLS file inside)](images/carnage_img12_http_stream_xls.png)

The response shows:
- `content-disposition: attachment; filename=documents.zip` — confirms file download
- `server: LiteSpeed` — identifies the malicious web server
- Inside the ZIP: `chart-1530076591.xls` — the malicious Excel file

### Answers

| Question | Answer |
|---|---|
| Date and time of first HTTP connection to malicious IP | `2021-09-24 16:44:38` |
| Name of the ZIP file downloaded | `documents.zip` |
| File inside the ZIP | `chart-1530076591.xls` |
| Web server of the malicious IP | `LiteSpeed` |

---

## Step 3 — Finding Malicious Domains (TLS/HTTPS Traffic)

The question asks for three domains from which malicious files were downloaded. Since these connections use HTTPS, the actual file content is encrypted. However, we can extract domain names from the **TLS Client Hello** packets, specifically the **Server Name Indication (SNI)** extension.

Apply filter: `tls.handshake.type == 1`

This shows all TLS Client Hello packets, which contain the target domain name in plaintext even in encrypted HTTPS connections.

![TLS Handshake — All Domains](images/carnage_img13_tls_handshake_domains.png)

Looking at the timeline around 16:45 (shortly after the initial infection), three suspicious domains stand out from the TLS handshake packets:

**Domain 1 — finejewels.com.au**

Filter: `ip.addr == 10.9.23.102 && tls.handshake.type == 1`

![SNI — finejewels.com.au](images/carnage_img15_sni_finejewels.png)

**Domain 2 — thietbiagt.com**

![SNI — thietbiagt.com](images/carnage_img16_sni_thietbiagt.png)

**Domain 3 — new.americold.com**

![SNI — new.americold.com](images/carnage_img17_sni_americold.png)

To confirm the IP addresses of these domains, use `Statistics > Resolved Addresses`:

![Resolved Addresses](images/carnage_img18_resolved_addresses.png)

### SSL Certificate Authority for finejewels.com.au

To find the certificate authority (CA), apply:

```
tls.handshake.type == 11 && ip.addr == 148.72.192.206
```
(148.72.192.206 is the resolved IP of finejewels.com.au)

![TLS Certificate — GoDaddy Issuer (Detail)](images/carnage_img19_tls_cert_godaddy.png)
![TLS Certificate — GoDaddy Confirmation](images/carnage_img20_godaddy_issuer.png)

The `issuer` field confirms: **Go Daddy Secure Certificate Authority - G2**

### Answers

| Question | Answer |
|---|---|
| Three malicious domains | `finejewels.com.au`, `thietbiagt.com`, `new.americold.com` |
| Certificate authority for first domain | `GoDaddy` |

---

## Step 4 — Cobalt Strike C2 Servers

To find the Cobalt Strike command-and-control (C2) servers, I used the Conversations view sorted by bytes — C2 servers typically maintain persistent, high-volume connections with the victim.

Navigate to: `Statistics > Conversations > IPv4`, sort by **Bytes B→A**

![Conversations — Cobalt Strike IPs](images/carnage_img21_conversations_cobalt.png)

Two IPs showed unusually high and sustained traffic patterns consistent with C2 beaconing:
- `185.106.96.158`
- `185.125.204.174`

I verified both on **VirusTotal**:

**185.125.204.174** — VirusTotal Community tab:

![VirusTotal — 185.125.204.174](images/carnage_img22_vt_185125204174.png)
![VirusTotal — Community Comments (Cobalt Strike confirmed)](images/carnage_img24_vt_community_cobalt2.png)

Community member `drb_ra` confirmed: *"Cobalt Strike Server Found — C2: HTTPS @ 185.125.204.174:4444"*

**185.106.96.158** — VirusTotal:

![VirusTotal — 185.106.96.158 (6/91 malicious)](images/carnage_img23_vt_18510696158.png)

6/91 vendors flagged this as malicious, with detections including Malware and Malicious classifications.

### Finding the Host Header for the First Cobalt Strike IP (185.106.96.158)

Apply filter: `ip.addr == 185.106.96.158 && http`

Then right-click → `Follow > TCP Stream`

![HTTP Traffic to 185.106.96.158](images/carnage_img25_cobalt1_http_filter.png)
![TCP Stream — Host Header revealed](images/carnage_img26_cobalt1_host_header.png)

The TCP Stream reveals: `Host: ocsp.verisign.com`

This is a common Cobalt Strike masquerading technique — the beacon impersonates legitimate OCSP (Online Certificate Status Protocol) traffic to blend in with normal enterprise network activity.

### Finding the Domain Names for Both C2 IPs

Navigate to VirusTotal → **Relations tab** for each IP:

**185.106.96.158 → survmeter.live**

![VirusTotal Relations — survmeter.live](images/carnage_img27_vt_relations_survmeter.png)

**185.125.204.174 → securitybusinpuff.com**

![VirusTotal Relations — securitybusinpuff.com](images/carnage_img28_vt_relations_securitybusinpuff.png)

### Answers

| Question | Answer |
|---|---|
| Two Cobalt Strike C2 IP addresses | `185.106.96.158`, `185.125.204.174` |
| Host header for first C2 IP | `ocsp.verisign.com` |
| Domain name of first C2 server | `survmeter.live` |
| Domain name of second C2 server | `securitybusinpuff.com` |

---

## Step 5 — Post-Infection Traffic (C2 Beaconing)

**Post-infection traffic** (also called C2 traffic or beaconing) refers to all network communication the malware makes after successfully infecting the host. This is how the attacker maintains persistent control over the compromised machine.

To find it, I filtered for HTTP POST requests — malware typically sends stolen data and receives commands via POST:

Apply filter: `http.request.method == POST`

Then `Follow > HTTP Stream`

![POST Requests to Malicious Domain](images/carnage_img30_post_filter.png)
![HTTP Stream — POST to maldivehost.net](images/carnage_img29_post_maldivehost.png)

The stream reveals:
- **Host:** `maldivehost.net`
- First 11 characters sent by victim: `zLIisQRWZI9`
- **Server:** `Apache/2.4.49 (cPanel) OpenSSL/1.1.1l mod_bwlimited/1.4`

To find the length of the first packet, click the "Time" column header in the packet list to sort ascending, then identify the first POST packet (Frame 3822, Length: **281**).

![Server Header Confirmation](images/carnage_img31_post_server_header.png)

The server header in the HTTP stream clearly shows: `Server: Apache/2.4.49 (cPanel) OpenSSL/1.1.11 mod_bwlimited/1.4`

### Answers

| Question | Answer |
|---|---|
| Domain name of post-infection traffic | `maldivehost.net` |
| First 11 characters sent to malicious domain | `zLIisQRWZI9` |
| Length of first packet sent to C2 | `281` |
| Server header of malicious domain | `Apache/2.4.49 (cPanel) OpenSSL/1.1.1l mod_bwlimited/1.4` |

---

## Step 6 — IP Check via API (Malware Reconnaissance)

After infecting the victim, the malware needed to discover the victim's public IP address. It used **api.ipify.org**, a legitimate IP-checking service, to accomplish this.

Apply filter: `dns.qry.name contains "ipify"`

![DNS Query for api.ipify.org](images/carnage_img32_dns_ipify.png)
![UDP Stream — ipify.org DNS resolution](images/carnage_img33_dns_ipify_stream.png)
![HTTPS Traffic to api.ipify.org](images/carnage_img34_ipify_traffic.png)

The first DNS query for `api.ipify.org` was:

**Frame 24147 | Timestamp: `2021-09-24 17:00:04`**

The response data returned was small (as expected — just a public IP address), confirming the malware successfully obtained the victim's public IP.

### Answer

| Question | Answer |
|---|---|
| Date and time of DNS query for IP-check domain | `2021-09-24 17:00:04` |

---

## Step 7 — Malspam Activity

The malware also turned the victim's machine into a spam relay — sending out malicious spam emails from the compromised endpoint.

Apply filter: `smtp contains "MAIL FROM"`

This directly shows all outbound emails sent from the victim:

![SMTP — MAIL FROM Filter](images/carnage_img35_smtp_mailfrom.png)
![SMTP — Full Traffic View](images/carnage_img36_smtp_full.png)

Five outbound MAIL FROM addresses were found, all originating from the victim (`10.9.23.102`):

1. `farshin@mailfa.com` ← **First observed**
2. `ho3ein.sharifi@mailfa.com`
3. `cristianodummer@cultura.com.br`
4. `info@tanriverdinakliyat.com`
5. `roser@aebarcelo.com`

The victim's machine was actively sending malspam to external mail servers at `185.4.29.135` and others.

### Answer

| Question | Answer |
|---|---|
| First MAIL FROM address observed | `farshin@mailfa.com` |

---

## Indicators of Compromise (IOC)

| Type | Value | Description |
|---|---|---|
| **IP** | `85.187.128.24` | Initial malware delivery server |
| **IP** | `185.106.96.158` | Cobalt Strike C2 Server #1 |
| **IP** | `185.125.204.174` | Cobalt Strike C2 Server #2 |
| **IP** | `208.91.128.6` | maldivehost.net — post-infection C2 |
| **IP** | `185.4.29.135` | Malspam relay server |
| **Domain** | `attirenepal.com` | Hosted initial ZIP dropper |
| **Domain** | `finejewels.com.au` | Malware download domain #1 |
| **Domain** | `thietbiagt.com` | Malware download domain #2 |
| **Domain** | `new.americold.com` | Malware download domain #3 |
| **Domain** | `survmeter.live` | Cobalt Strike C2 domain #1 |
| **Domain** | `securitybusinpuff.com` | Cobalt Strike C2 domain #2 |
| **Domain** | `maldivehost.net` | Post-infection C2 / beaconing |
| **File** | `documents.zip` | Initial dropper archive |
| **File** | `chart-1530076591.xls` | Malicious Excel file inside ZIP |
| **Email** | `farshin@mailfa.com` | First malspam sender (compromised) |
| **Victim** | `10.9.23.102` / `DESKTOP-IOJC6RB` | Eric Fischer's endpoint |

---

## Attack Timeline

```
16:44:38  Malicious ZIP (documents.zip) downloaded from attirenepal.com
          └── Contains: chart-1530076591.xls

16:45:11  TLS connections to 3 malware download domains:
          ├── finejewels.com.au (148.72.192.206)
          ├── thietbiagt.com (210.245.90.247)
          └── new.americold.com (148.72.53.144)

16:55:08  Cobalt Strike C2 beaconing begins:
          ├── 185.106.96.158 (survmeter.live)
          │   └── Host header masquerades as: ocsp.verisign.com
          └── 185.125.204.174 (securitybusinpuff.com)

16:56:43  POST C2 traffic to maldivehost.net (208.91.128.6)
          └── First 11 chars: zLIisQRWZI9

17:00:04  DNS query to api.ipify.org
          └── Malware checks victim's public IP address

17:00+    SMTP malspam activity begins
          └── First sender: farshin@mailfa.com → 185.4.29.135
```

---

## Skills Practiced

| Skill | Applied |
|---|---|
| Protocol Hierarchy analysis | Step 1 |
| Conversations & Endpoints analysis | Step 1 |
| Expert Information triage | Step 1 |
| HTTP stream following | Step 2 |
| TLS/SNI extraction for HTTPS domains | Step 3 |
| SSL certificate analysis | Step 3 |
| IP reputation checking (VirusTotal) | Step 4 |
| Cobalt Strike identification | Step 4 |
| C2 beaconing pattern recognition | Step 5 |
| DNS query analysis | Step 6 |
| SMTP / malspam detection | Step 7 |
| IOC extraction and documentation | All steps |

---

## Lessons Learned

1. **Always start with Protocol Hierarchy and Conversations.** These two views immediately narrow the investigation scope and reveal anomalies before diving into individual packets.

2. **TLS doesn't hide everything.** Even with HTTPS encryption, the **SNI (Server Name Indication)** in TLS Client Hello packets exposes the target domain in plaintext — a critical technique for identifying malicious domains in encrypted traffic.

3. **Cobalt Strike masquerades as legitimate traffic.** The C2 beacon used `Host: ocsp.verisign.com` to disguise its traffic as certificate status checks. Defenders must correlate host headers with actual destination IPs to detect this.

4. **Expert Information is an underrated first step.** Wireshark auto-flagged the suspicious GET request for `documents.zip` in the Expert Information panel — this was a direct shortcut to the first malicious activity.

5. **VirusTotal Community tab is essential for C2 confirmation.** Detection scores alone are not enough — community comments often contain specific threat intelligence like C2 server details, malware family names, and IOCs that are not captured by automated scanners.

6. **Malware uses legitimate services for reconnaissance.** The use of `api.ipify.org` to check the victim's public IP is a common technique that blends in with normal traffic and evades basic detection rules.

---

*Writeup produced as part of cybersecurity portfolio — TryHackMe Carnage Room — Said Almunawar*
