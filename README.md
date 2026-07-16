<div align="center">
  <img src="vd-logo.png" width="130" alt="VD Logo"/>

  <h1>VD — Red Team Toolkit</h1>

  <p><em>Modular offensive security toolkit for authorized server testing, OSINT reconnaissance, and red team operations.</em></p>

  <p>
    <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white"/>
    <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=for-the-badge"/>
    <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
    <img src="https://img.shields.io/badge/Use-Authorized%20Only-red?style=for-the-badge"/>
    <img src="https://img.shields.io/badge/Maintained-Yes-brightgreen?style=for-the-badge"/>
  </p>
</div>

---

> **⚠️ Legal Disclaimer**
> This toolkit is intended **exclusively** for use on systems you own or have **explicit written authorization** to test.
> Unauthorized use against systems you do not own is illegal under the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent legislation worldwide.
> The author accepts **no liability** for misuse. Always get written permission before testing any target.

---

## 📖 Overview

**VD** is a self-contained red team and OSINT toolkit built for security researchers, penetration testers, and CTF players operating in authorized environments. It consolidates the most common recon, enumeration, and stress-testing workflows into a clean, modular Python collection — no bloated GUI, no unnecessary cloud dependencies, no framework overhead.

The toolkit is designed around a simple philosophy: **fast setup, real output, zero noise**. Every module runs standalone or through the unified `run.sh` launcher, making it easy to chain tools together during an engagement without switching between a dozen different applications.

Whether you're conducting an authorized load test on your own infrastructure, building a threat intelligence profile for an asset you manage, or running an internal red team drill against your organization's defenses, VD gives you a focused set of tools that stay out of your way.

---

## 🧠 What VD Can Do

### Reconnaissance & OSINT
VD's recon layer is built for **passive and semi-passive intelligence gathering**. The OSINT aggregator (`osint2.py`) pulls from multiple public data sources simultaneously, correlating results into a single output instead of making you run five tools and merge the results yourself. The phone modules (`phone2.py`, `phone_deep.py`) go beyond basic carrier lookup — they map number metadata, regional registration data, and cross-reference against available public records. The git leak scanner (`git_leak_scanner.py`) parses commit histories, configuration files, and `.env` artifacts for exposed API keys, database credentials, and private tokens that developers commonly leave behind.

### Network Enumeration
Port scanning (`port_scan.py`) supports configurable thread counts, timeout tuning, and basic banner grabbing — enough to produce a solid service map of a target host without reaching for nmap for simple tasks. `ping_check.py` handles host discovery across ranges. IP intelligence (`ip_intel.py`) and geographic recon (`geo.py`) layer in ASN data, WHOIS records, and rough physical location context to help you understand who operates an IP and where.

### Infrastructure Stress Testing
The traffic simulation modules (`ddos_sim.py`, `ddos_simple.py`, `ddos_triple.py`) are for **testing your own servers under load** — validating rate limiting, connection limits, WAF behavior, and how your infrastructure degrades under pressure. The triple-thread variant sends concurrent multi-vector traffic to stress different parts of the stack simultaneously. These are not attack tools; they are load testing tools for infrastructure you control.

### Credential & Access Auditing
`password_guesser.py` is a credential brute-force module for authorized audits — useful for testing whether default credentials or weak passwords remain on services you manage. Use it as part of an internal audit, not against external systems.

### Phishing Simulation
`phishing.py` is a phishing simulation framework intended for **internal security awareness training**. It lets security teams run controlled phishing campaigns against their own organization to identify employees who need additional training, measure click rates, and report on organizational risk — exactly what managed security services charge thousands of dollars to do externally.

---

## 🛠 Modules

| Module | Category | Description |
|---|---|---|
| `port_scan.py` | Network | TCP/UDP port scanner with configurable threads and banner grabbing |
| `ip_intel.py` | OSINT | IP geolocation, ASN lookup, and WHOIS data |
| `geo.py` | OSINT | Geographic recon and coordinate mapping |
| `osint2.py` | OSINT | Multi-source intelligence aggregator |
| `git_leak_scanner.py` | OSINT | Scan repositories for exposed secrets, keys, and credentials |
| `phone2.py` | OSINT | Phone number intelligence — carrier, country, line type |
| `phone_deep.py` | OSINT | Deep phone recon using multiple public intelligence sources |
| `ping_check.py` | Network | Host availability sweep and latency measurement |
| `password_guesser.py` | Audit | Credential brute-force for authorized security audits |
| `phishing.py` | Red Team | Phishing simulation for internal awareness training |
| `ddos_sim.py` | Stress Test | Controlled single-thread traffic simulation |
| `ddos_simple.py` | Stress Test | Simplified flood test for own server load validation |
| `ddos_triple.py` | Stress Test | Multi-vector concurrent stress test — triple thread |
| `chatbot.py` | Automation | Automated interaction and bot detection testing |
| `run.sh` | Launcher | Interactive menu-driven entry point for the full toolkit |

---

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/nilavog4-f/vd.git
cd vd

# Install all dependencies
pip install -r requirements.txt

# Launch the interactive toolkit menu
bash run.sh
```

---

## 🔧 Running Modules Directly

```bash
# Port scan a target
python port_scan.py --target 192.168.1.1 --ports 1-65535

# IP intelligence lookup
python ip_intel.py --ip 1.1.1.1

# OSINT on a domain
python osint2.py --target example.com

# Scan a git repository for leaked secrets
python git_leak_scanner.py --repo https://github.com/example/repo

# Phone number lookup
python phone2.py --number +1234567890

# Host availability check
python ping_check.py --range 192.168.1.0/24
```

---

## ⚙️ Configuration

Edit `osint_config.json` to set default targets, API keys, and module parameters before running:

```json
{
  "target_ip": "",
  "target_domain": "",
  "threads": 10,
  "timeout": 5,
  "output_dir": "./results"
}
```

---

## 📋 Requirements

- Python 3.8 or higher
- All Python dependencies are listed in `requirements.txt`
- Linux recommended; most modules work on Windows with minor adjustments

---

## 🎯 Use Cases

- **Personal server hardening** — test your own infrastructure before an attacker does
- **CTF and lab environments** — practice offensive techniques in controlled, legal settings
- **Security awareness training** — run authorized phishing drills inside your organization
- **Internal red team operations** — fast recon tooling for authorized engagements
- **Home lab stress testing** — understand how your servers behave under real load

---

## 📁 Project Structure

```
vd/
├── osint_config.json      # Shared configuration file
├── requirements.txt       # Python dependencies
├── run.sh                 # Interactive launcher
├── port_scan.py
├── ip_intel.py
├── geo.py
├── osint2.py
├── git_leak_scanner.py
├── phone2.py
├── phone_deep.py
├── ping_check.py
├── password_guesser.py
├── phishing.py
├── ddos_sim.py
├── ddos_simple.py
├── ddos_triple.py
└── chatbot.py
```

---

## 🤝 Contributing

This is a personal toolkit maintained for private use. Pull requests are welcome for bug fixes, module improvements, or new standalone tools that fit the scope. Open an issue before submitting anything major so we can discuss it first.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for full details.

---

<div align="center">
  <sub>Built for authorized security research · Red team responsibly · Know your scope</sub>
</div>****
