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
| **Command and Control** | `T1071.001` | Web Protocols (C2 Beaconing) | `http.request (||) tcp.port == 8080` | Repetitive interval beaconing callbacks to external adversary infrastructure. |

---

## 3. Investigation & Packet Forensics

### 3.1. Network Reconnaissance & Port Sweep
```text
Filter: tcp.flags.syn == 1 && tcp.flags.ack == 0
