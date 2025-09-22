# Task 1 — Scanning Local IP and Ports

**Author:** KUSH THAKER (kthaker442@gmail.com)

---

## Overview
This repository documents a network discovery and port-scanning task performed on a local network. The objective was to discover live hosts, identify open ports and services, and capture wireless traffic for analysis. The work was performed from a Kali Linux host with a statically assigned IP.

---

## Environment & Host Details
- Host OS: Kali Linux (static IP: `192.168.31.50`)
- Network: `192.168.31.0/24` (subnet mask `255.255.255.0`)
- Tools used: `ifconfig`/`ip a`, `nmap`, `aircrack-ng` suite (`airmon-ng`, `airodump-ng`), and `Wireshark`.

---

## Files in this repository
- `task1.html` — Saved Nmap scan output (full scan report).
- `task1-01.cap` — Wireless capture file created by `airodump-ng` (if included).
- `images/` — Folder containing screenshots referenced in this README (if included): `ifconfig`, `nmaptask1`, `nmapscanend`, and other relevant screenshots.

---

## Steps performed

### 1) Confirm host IP and network range
Commands used for verification (screenshots in `images/`):

```bash
# show network interfaces and IP
ifconfig  # or: ip a
```

From the interface output the host IP was `192.168.31.50` and the network derived as `192.168.31.0/24`.

---

### 2) Nmap scan (discover hosts, services, OS fingerprinting)
Command used:

```bash
nmap -sS -sV -T4 -O -F 192.168.31.0/24
```

- `-sS` : TCP SYN (stealth) scan
- `-sV` : Service/version detection
- `-T4` : Aggressive timing
- `-O` : OS detection
- `-F` : Fast scan (top ports)

The Nmap results were saved as `task1.html` and screenshots are attached in `images/`.

---

## Discovered Hosts & Services (summary)

| IP Address | Device Name / Notes | Open Ports | Services |
|---|---:|:---:|---|
| `192.168.31.1` | Jio Air Fiber Router (gateway) | 53, 80, 443, 8080, 8443 | DNS, HTTP, HTTPS, HTTP proxy, HTTPS alt |
| `192.168.31.30` | UNKNOWN DEVICE | none | none |
| `192.168.31.106` | Android device (RAT suspected) | 49152 | tcpwrapped / reverse channel |
| `192.168.31.143` | Android device (RAT suspected) | 8888 | tcpwrapped / reverse channel |
| `192.168.31.139` | Set-Top-Box / Jio device | none | none |
| `192.168.31.170` | UNKNOWN DEVICE | none | none |
| `192.168.31.50` | Kali Linux host | none | none |

> Notes: Ports like `49152`, `8888` were observed as `tcpwrapped` and indicate high/ephemeral sockets often used by remote access tools (RATs). Treat these as high risk until proven benign.

---

## Port/service analysis (quick notes)
- **53 (DNS)** — Name resolution; misconfiguration can enable DNS spoofing.
- **80 (HTTP)** — Unencrypted device web management; credential leakage risk.
- **443 (HTTPS)** — Encrypted management; secure if correctly configured.
- **8080 (HTTP proxy / alternate web)** — Local web services; same risks as 80.
- **8443 (HTTPS alt)** — Alternate HTTPS; same cautions as 443.
- **49152, 8888 (tcpwrapped)** — Likely reverse/ephemeral ports used by RATs; high-risk.

---

## Wireless capture & Wireshark (optional)
Instead of interacting directly with the router's management interface, wireless capture was performed using the aircrack-ng suite. Commands and rationale:

```bash
# kill interfering processes and enable monitor mode on wlan0
airmon-ng check kill && airmon-ng start wlan0
# scan for access points and clients
airodump-ng wlan0mon
# capture packets from a specific BSSID on channel 1 and write to file
airodump-ng --bssid BE:0A:F3:77:E4:BD -c 1 -w task1 wlan0mon
```

- `--bssid` targets the AP MAC address.
- `-c` selects the channel in use by the AP.
- `-w` writes captured packets to a `.cap` file (e.g., `task1-01.cap`).

Open the resulting `.cap` file in Wireshark for analysis. WPA2-protected traffic will remain encrypted unless the handshake and PSK are available to Wireshark.

---

## Safety, Ethics, and Legal
- All scanning and packet capture must be performed only on networks and devices for which you have explicit authorization. Unauthorized scanning, exploitation, or monitoring of networks is illegal and unethical.
- The presence of suspected RAT channels should be escalated through appropriate channels (incident response/cybercrime unit) rather than probed further without authority.

---

## Conclusion
- Confirmed Kali host and derived `192.168.31.0/24` network.
- Nmap discovered seven live hosts; router (`192.168.31.1`) exposed management ports and two Android devices (`192.168.31.106`, `192.168.31.143`) exhibited suspicious high ports consistent with RAT activity.
- Wireless captures were collected for traffic analysis; packets remain encrypted under WPA2 unless decrypted with the network PSK or captured handshakes and keys.

---

## Contact
KUSH THAKER — kthaker442@gmail.com

---
