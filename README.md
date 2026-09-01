# Network Traffic Analysis & Incident Triage (Wireshark)

## 1. Executive Summary
This project demonstrates packet-level network forensics and incident triage using **Wireshark** to analyze a compromised host network capture (`.pcap`). The investigation walks through the adversary's attack lifecycle—from initial reconnaissance and malware staging over plaintext protocols to credential harvesting and active Command and Control (C2) communications—mapped directly to the **MITRE ATT&CK** framework.

---

## 2. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Wireshark Display Filter | Evidence / Artifact |
| :--- | :--- | :--- | :--- | :--- |
| **Reconnaissance** | `T1595.001` | Active Scanning: Port Scan | `tcp.flags.syn == 1 && tcp.flags.ack == 0` | High-frequency SYN packets targeting consecutive TCP ports. |
| **Initial Access / Execution** | `T1204.002` | Malicious File Download | `http.request.uri matches "\.(exe\|dll\|bin)$"` | Executable binary retrieved over unencrypted HTTP (Port 80). |
| **Credential Access** | `T1040` | Network Sniffing: Plaintext Credentials | `http.request.method == "POST"` | Unencrypted authentication tokens and user credentials in transit. |
| **Command and Control** | `T1071.001` | Web Protocols (C2 Beaconing) | `http.request // tcp.port == 8080` | Repetitive interval beaconing callbacks to external adversary infrastructure. |

---

## 3. Investigation & Packet Forensics

### 3.1. Network Reconnaissance & Port Sweep
```text
Filter: tcp.flags.syn == 1 && tcp.flags.ack == 0
```

**Findings:** Identified suspicious outbound sweep activity originating from internal host **10.6.7.104**. The infected host generated multiple unacknowledged TCP SYN packets targeting external destination endpoints on non-standard ports: **51.83.138.148:443** (repeated TCP SYN Retransmissions across frames 794–815), **117.252.68.65:449** (Frame 817), and **185.61.149.38:447** (Frame 855), confirming automated network discovery and egress port validation.

---

## 3.2 Malicious Payload Staging & File Carving
```text
Filter: http.request.method == "GET"
Navigation: File -> Export Objects -> HTTP
```

**Findings:** Detected an unencrypted HTTP GET request targeting **46.249.59.89** retrieving a raw Windows executable named bnc.exe (Packet 608, Size: 320 kB, MIME: application/octet-stream). Extracted corresponding HTTP objects indicating secondary staging and repetitive multipart/form-data interactions directed at **186.159.1.217:8082**, indicating potential host profiling and data staging post-execution.

---

## 3.3. HTTP Stream Analysis & IoC Extraction
```text
Filter: ip.addr == 46.249.59.89
Navigation: Right-click Packet -> Follow -> HTTP Stream
```

**Findings:** The victim host explicitly requested /zxcn/bnc.exe over plaintext HTTP. The User-Agent string (Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko) identifies the compromised endpoint as a legacy Windows 7 64-bit client using Internet Explorer 11. The raw HTTP 200 OK response body reveals the MZ magic bytes (4D 5A) and the DOS stub message This program must be run under Win32, confirming a Portable Executable (PE) binary delivery from an Apache/2.4.6 (CentOS) server.

---

## 3.4. Command and Control (C2) Stream Analysis
```text
Filter: http.request.method == "POST"
Navigation: Right-click Packet 4187 -> Follow -> HTTP Stream (Stream Index 37)
```

**Findings:** Captured persistent HTTP POST beaconing directed to external C2 server **186.159.1.217:8082** across two compromised internal endpoints: **10.6.7.104** (ZARAGOZA-WIN-PC) and **10.6.7.7** (PHANTASMEDIA-DC). Following the stream revealed active data exfiltration structured as multipart/form-data with a suspicious User-Agent (User-Agent: test), exfiltrating process list parameters (proclist) and system reconnaissance data (sysinfo) scanning specifically for Domain and Point-of-Sale/Retail host environments (POS, REG, CASH, LANE, STORE, RETAIL, MICROS, ALOHA).
