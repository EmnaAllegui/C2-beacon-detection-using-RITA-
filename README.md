# C2-beacon-detection-using-RITA-

---
# Objective

The objective of this project is to analyze a suspicious network traffic capture (PCAP) using Zeek and RITA in order to detect Command and Control (C2) beaconing activity.

---
# Environment
- Ubuntu 24.04 operating system

---

# Tools Used

- Zeek
- RITA (Real Intelligence Threat Analytics)
- Suricata
- CyberChef
---

## Task
An internal device demonstrates:

- Consistent high beacon activity
- Use of a common service to hide communication
- Repeated connections at fixed intervals

1. Analyze the PCAP using RITA  
2. Identify the beacon pattern  
3. Determine whether the service is being abused as a C2 channel  
4. Provide a short conclusion describing the attack type  

---

# Introduction

This report presents a practical scenario demonstrating the use of RITA (Real Intelligence Threat Analytics) to analyze a provided PCAP to detect beacons pattern and identify malicious activities.

The analysis identified:

- High beacons
- Repetitive and consistent connections at fixed intervals
- HTTP based Command and Control C2 communications

Further investigation, including full TCP stream and decoding an encrypted payload using CyberChef indicates that the activity was malicious. These findings suggest that an internal host was likely compromised by malware fileless attack, establishing an HTTP based Command and Control C2 communication channel with an external server.

---

# 1. PCAP Analysis Using Rita

To analyze the PCAP using Rita, the following steps were performed:

## 1.1. Download the PCAP file

<img width="944" height="369" alt="image" src="https://github.com/user-attachments/assets/ac4fd83c-5df5-4d6c-8029-4a6f7b5587b0" />

## 1.2. Parse the PCAP file using Zeek

<img width="944" height="69" alt="image" src="https://github.com/user-attachments/assets/bbecfaaf-7bd5-4dac-83c1-f7d801839789" />

## 1.3. Import the generated logs into the Rita database

<img width="943" height="387" alt="image" src="https://github.com/user-attachments/assets/2d15fc64-9528-4408-a40e-b3f0d2a53443" />

## 1.4. Display the Rita analysis of the PCAP

<img width="943" height="141" alt="image" src="https://github.com/user-attachments/assets/3d62fd6a-be12-4d81-838b-b4f81991f94d" />

<img width="945" height="502" alt="image" src="https://github.com/user-attachments/assets/c60d1ebc-8c2d-4736-ba2e-f1e8ef27959b" />

---

# 2. Beacons Pattern Identification

## 2.1 Rita Analysis Results

Rita analysis identified critical beacon activity originating from the source `192.168.99.53` communicating with an external domain `mahamaya1ifesciences.com` using HTTP protocol.

This communication is considered malicious based on the following indicators:

### Connection Count

A total of 2882 connections were made within a short time in 34 minutes and 15 seconds. This activity is commonly associated with automated Command and Control (C2) beaconing because a high number of connections within a short time is not consistent with normal user behavior.

### Prevalence

The prevalence is 100%, indicating communication with the domain `mahamaya1ifesciences.com`, which is highly suspicious.

### User Agent

The source host used an outdated browser, and this technique is commonly employed by malware to evade detection.

### Threat Intelligence Validation

Analysis of the domain with VirusTotal reveals that 8/53 security vendors flagged it as malicious, classifying it as associated with malware activity.

<img width="945" height="455" alt="image" src="https://github.com/user-attachments/assets/db45e17f-9a33-436c-9df9-f5bb69687660" />

---

## 2.2 Conn.log Investigation

The analysis of `conn.log` reveals high connections from `192.168.99.53` to the following destinations:

### `67.207.93.135` — External Server

External server contacted to request the malicious `mahamaya1ifesciences.com` domain.

### `224.0.0.251` — Multicast DNS

Multicast DNS is used to send DNS queries to a group of hosts on a network.

### `208.67.222.220` — DNS Resolver

The DNS resolver used to resolve legitimate Windows domains.

<img width="944" height="456" alt="image" src="https://github.com/user-attachments/assets/5615b367-8ae7-4e19-8701-8d30fd3ad71b" />

> The repeated connection between `192.168.99.53` and `67.207.93.135`, combined with the requested malicious domain, indicates a beaconing communication pattern consistent with Command-and-Control activity.

---

## 2.3 Investigation of http.log

Multiple abnormal and repeated HTTP requests from `192.168.99.53` to `67.207.93.135` requested the domain `mahamaya1ifesciences.com`. This behavior is a strong indicator of an HTTP-based C2 beacon.

Other legitimate HTTP requests observed in the Windows environment include:

- `dl.delivery.mp.microsoft.com`
- `tile-service.weather.microsoft.com`
- `ctldl.windowsupdate.com`
- `adl.windows.com`
- `ocsp.digicert.com`

<img width="943" height="170" alt="image" src="https://github.com/user-attachments/assets/5323ca77-b654-449f-b152-81f44a3c354f" />


The communication between the internal host and the external server has the following beaconing characteristics:

- Multiple and repeated communication from the same source to the same destination (`192.168.99.53 → 67.207.93.135`)
- Fixed data exchanged (`send: 383`, `received: 226237`)
- Short and consistent intervals (`0.536566s → 0.538287`)

> All of these characteristics are strong indicators of automated C2 beaconing.

<img width="944" height="536" alt="image" src="https://github.com/user-attachments/assets/b1572d4b-6597-4903-8714-3cfb168d1d29" />

<img width="945" height="502" alt="image" src="https://github.com/user-attachments/assets/f546d3e5-7c41-45ce-a5e7-9e6ff2fe350d" />

---

## 2.4 Determine Whether the Service Is Being Abused as a C2 Channel

The investigation of `http.log` disclosed that 2882 connections were established between the internal host `192.168.99.53` and the external server `67.207.93.135`.

The full TCP stream indicated:

- An obfuscated PowerShell payload executed in memory using `Base64String` through the HTTP service.
- An abnormal behavior in which the internal host requested a `ppptg.jpg` image file while the server responded with plain text content instead of image data.

> All these activities are strong indicators that the HTTP service was being abused as a C2 channel.

<img width="945" height="647" alt="image" src="https://github.com/user-attachments/assets/70b6415f-4ec2-4980-baea-abe85dfbaa8e" />

<img width="945" height="640" alt="image" src="https://github.com/user-attachments/assets/4ad49444-acae-4cd1-b03f-e059b1499515" />

<img width="945" height="643" alt="image" src="https://github.com/user-attachments/assets/87ce24c1-22c7-4310-881b-5f1d42cc7fdb" />

---

## 2.5 Suricata Analysis

While the payload contains encoded data, invoke-expression, and memory execution behavior, Suricata alerts mainly identified invalid TCPv4 checksum anomalies and no critical alerts were triggered.

<img width="945" height="562" alt="image" src="https://github.com/user-attachments/assets/e32275de-157a-4f44-a4b2-c2ede388b9e5" />

---

## 2.6 Payload Decoding Using CyberChef

CyberChef was used to decode the payload and save the result into a file.

<img width="983" height="596" alt="image" src="https://github.com/user-attachments/assets/6e4e48f9-fecd-424d-b104-3437067ef442" />

The decoded PowerShell script downloaded from the external server is malicious. It downloads hidden code, decrypts it, and executes it directly in memory without creating any file on disk.

<img width="945" height="634" alt="image" src="https://github.com/user-attachments/assets/a38d7072-203d-49f0-a847-776bf370eb7e" />

<img width="945" height="687" alt="image" src="https://github.com/user-attachments/assets/6014e9cf-2336-4f1a-9d12-151c96922287" />


This activity is not normal for legitimate programs or users and is strong evidence of a fileless malware attack.

---

# Conclusion

Based on the analysis, the host `192.168.99.53` was likely compromised by malware, which established an HTTP-based Command and Control communication with `67.207.93.135` using the malicious domain `mahamaya1ifesciences.com`.

During the attack, the following operations were performed:

- An internal host requested a `metro91/admin/1/ppptp.jpg` resource.
- The external server responded with an encrypted payload in text format.
- The payload performed the following operations:
  1. Creation of a memory stream object that provides a stream of data stored in memory, allowing the attacker to read and write from and to the stream.

  2. Conversion of Base64 encoded content to binary data.

  3. Decompression of the content using `IO.Compression.GZIPStream`.

  4. Reading the decompressed content using `IO.StreamReader`.

  5. Execution of the final payload using `Invoke-Expression (IEX)`.
  

---

# Mitigations

## Immediate Actions

- Isolate the host `192.168.99.53` from the network to prevent malware propagation.
- Disable the compromised account associated with `192.168.99.53`.
- Reset credentials associated with the infected system.
- Block all incoming and outgoing traffic to and from `67.207.93.135` using firewall rules.
- Perform a full digital forensic investigation.

## Strategic Recommendations

- Implement Two-Factor Authentication (2FA) to reduce unauthorized access risks.
- Deploy Endpoint Detection and Response (EDR) solutions to monitor malware behavior and C2 communication activity.
- Implement continuous network monitoring and anomaly detection.
- Regularly update systems and security tools to reduce exploitation risks.
