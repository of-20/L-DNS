# L-DNS: Lightweight DNS Tunneling & Anomaly Detection System

**L-DNS** is a lightweight, pure-Python Command-Line Tool (CLI) designed to detect DNS Tunneling and Data Exfiltration attacks using heuristic analysis, information entropy, and structural query inspection.

---

## Key Features

* **Zero External Dependencies**: Built entirely with standard Python 3 modules (`socket`, `struct`, `argparse`, `math`, `re`).
* **Multi-Vector Threat Analysis**:
  * **Shannon Entropy Scoring**: Detects encoded/encrypted subdomains with high randomness.
  * **Encoding Signatures**: Identifies Base64 and Hexadecimal encoded data payloads.
  * **Structural Anomaly Detection**: Evaluates FQDN/subdomain lengths and consonant-to-vowel ratios.
  * **Record Type Inspection**: Flags high-risk DNS records (`TXT`, `NULL`, `CNAME`, `MX`, `AAAA`).
  * **Rate Limiting Engine**: Tracks volumetric query speeds per client IP.
* **Dual Inspection Modes**:
  * **Static File Analysis**: Batch processing of domain lists or log files with JSON report exports.
  * **Live Packet Sniffing**: Real-time UDP socket listening on DNS Port 53.

---

## Installation & Setup

1. **Clone the repository**:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/L-DNS.git](https://github.com/YOUR_USERNAME/L-DNS.git)
   cd L-DNS