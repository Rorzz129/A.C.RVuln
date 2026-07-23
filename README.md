# VulnScope

<p align="center">
  <img src="https://img.shields.io/github/stars/Rorzz129/A.C.RVuln?style=for-the-badge">
  <img src="https://img.shields.io/github/forks/Rorzz129/A.C.RVuln?style=for-the-badge">
  <img src="https://img.shields.io/github/issues/Rorzz129/A.C.RVuln?style=for-the-badge">
  <img src="https://img.shields.io/github/license/Rorzz129/A.C.RVuln?style=for-the-badge">
  <img src="https://img.shields.io/github/last-commit/Rorzz129/A.C.RVuln?style=for-the-badge">
</p>

<p align="center">
Network Reconnaissance • Technology Fingerprinting • Web Security Analysis • CVE Correlation
</p>

---

## Overview

VulnScope est un scanner de reconnaissance et d'analyse de vulnérabilités développé en Python.

Il automatise les premières étapes d'un audit de sécurité en combinant plusieurs techniques afin d'identifier les services exposés, les technologies utilisées, les mauvaises configurations de sécurité ainsi que les vulnérabilités publiques connues.

---

# Features

## Target Analysis

- IP / Domain support
- Automatic DNS resolution
- Hostname detection

## DNS Enumeration

- A
- AAAA
- MX
- NS
- TXT
- CNAME

## HTTP Analysis

- HTTP / HTTPS detection
- Redirect handling
- Header analysis
- Server identification
- Response analysis

## Port & Service Discovery

- Nmap integration
- Open port discovery
- Service detection
- Product identification
- Version detection

## Technology Fingerprinting

Detection from multiple sources:

- Nmap
- HTTP Headers
- HTML
- Cookies
- CSS Resources
- JavaScript Resources
- JavaScript Analysis

Supported technologies include:

- Apache
- Nginx
- IIS
- PHP
- OpenSSH
- Node.js
- Cloudflare
- Vue.js
- Nuxt
- React
- Angular
- Next.js
- Bootstrap
- jQuery
- Axios
- Webpack

## JavaScript Analysis

- JavaScript resource discovery
- Framework detection
- Library detection
- Version extraction
- Source Map detection
- Evidence collection

## Web Security Checks

### Security Headers

- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

### Cookies

- HttpOnly
- Secure
- SameSite

### CORS

- Wildcard detection
- Credential checks

### HTTP Methods

- Enabled HTTP methods

### Sensitive Files

- robots.txt
- sitemap.xml
- Common sensitive paths

Each finding contains:

- Identifier
- Severity
- Confidence
- Evidence
- Recommendation

## CVE Correlation

- Automatic CPE lookup
- NVD integration
- CVSS score
- Severity
- Description
- Confirmed CVEs only

---

# Installation

Clone the repository:

```bash
git clone https://github.com/Rorzz129/A.C.RVuln.git
cd VulnScope
```

Create a virtual environment:

```bash
python -m venv .venv
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Install **Nmap** and ensure it is available in your PATH.

---

# Usage

```bash
python main.py
```

Example targets:

```
google.com
```

```
8.8.8.8
```

---

# Scan Workflow

```
Target
   │
   ▼
DNS Enumeration
   │
   ▼
HTTP Analysis
   │
   ▼
Port Discovery
   │
   ▼
Technology Fingerprinting
   │
   ▼
Web Security Analysis
   │
   ▼
CVE Correlation
   │
   ▼
Summary
```

---

# Example Output

- Target Information
- DNS Records
- HTTP Analysis
- Open Ports
- Service Detection
- Technology Fingerprinting
- Web Security Findings
- Confirmed CVEs
- Scan Summary

---

# Technologies Used

- Python
- Requests
- BeautifulSoup4
- Nmap
- Colorama

---

# Roadmap

- Improved JavaScript fingerprinting
- Additional technology signatures
- Export to JSON
- Export to HTML
- Export to PDF
- Screenshot capture
- SSL/TLS analysis
- Additional web security checks

---

# Disclaimer

VulnScope must only be used on systems you own or for which you have explicit authorization to perform security assessments.

The author assumes no responsibility for misuse.

---

# License

MIT License
