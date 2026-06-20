# 🧠 RetrieverLabs Infrastructure Explorer

A lightweight OSINT-style infrastructure correlation tool for analyzing domains, IPs, and URLs to identify shared infrastructure signals.

Built for threat hunting, triage, and rapid enrichment workflows — with no external API dependencies required.

---

## 🚀 What it does

Paste in indicators such as:
- Domains
- IP addresses
- URLs

The tool will:
- Normalize inputs safely (URL/IP/domain detection)
- Enrich with passive signals (WHOIS, cert, favicon hash)
- Score infrastructure risk signals
- Correlate shared infrastructure across multiple IOCs
- Generate pivot points for further investigation

---

## 🧠 Key Features

- IOC normalization engine (URL-safe parsing)
- Domain + IP resolution
- Certificate inspection (issuer extraction)
- WHOIS enrichment (where available)
- Favicon hashing for infrastructure grouping
- Correlation clustering (IP / cert / favicon)
- Batch processing mode with progress tracking
- Safe pivot generation (no auto-click tracking)

---

## 🔐 Design Philosophy

This tool is built with:
- No data storage
- No external API dependencies
- Analyst-first workflow design
- Safe rendering (no accidental clickable threat domains in tables)

---

## 🖥️ How to run locally

```bash
pip install -r requirements.txt
streamlit run app.py
