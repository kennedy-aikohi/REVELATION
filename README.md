# REVELATION

**REVELATION** is an analyst-driven DFIR and threat-hunting tool designed to provide **transparent, evidence-backed detection** for incident response and forensic investigations.

Unlike traditional antivirus or EDR solutions, REVELATION does not run continuously, perform remediation, or rely on opaque vendor signatures.  
It is built to help analysts **understand why something was flagged**, not just that it was.

---

## 🔍 What REVELATION Does

REVELATION analyzes local artifacts and logs to surface **high-confidence suspicious activity** using multiple independent signals:

- YARA-based disk scanning
- Suspicious API import analysis
- Windows EVTX execution evidence
- Evidence-backed scoring and severity classification
- Analyst-controlled workflows with full visibility

Each finding includes:
- File path
- Severity score
- Matched YARA rule(s)
- Supporting evidence (APIs, strings, offsets, events)

---

## 🧠 Detection Philosophy

REVELATION is built around **reasoning, not alerts**.

Core principles:
- Evidence-first detection
- Correlation over single-signal hits
- Analyst trust over automation
- No black-box scoring
- No continuous monitoring
- No vendor dependency

Ideal for:
- Incident response
- Threat hunting
- Malware research
- DFIR training and learning

---

## 🖥️ Screenshots

### Overview

![REVELATION Overview](assets/Revelation.png)

*(Additional screenshots can be added to `assets/` and referenced here.)*

---

## ⚙️ Current Features (v1.0)

- YARA-based disk scanning  
- Windows EVTX parsing  
- Suspicious API import classification  
- Evidence-backed scoring (0–100)  
- Severity classification (Low / Medium / High)  
- JSON and CSV report export  
- GUI-based analyst workflow  
- No background services or persistence

---

## 🛠️ Building From Source

### Requirements

- Rust (stable)  
- Windows (for EVTX parsing and GUI)

### Build

Run the following command:

`cargo build --release`

---

### Build Output

After running the build command locally, the compiled binary will be located at:

`target/release/revelation-gui.exe`

---

## Required DLLs for YARA Rules

REVELATION uses YARA for disk scanning and supports updating rules from YARA and Sigma repositories.  
To enable this functionality on Windows, the following OpenSSL DLLs must be present in the same directory as the compiled binary:

- `libcrypto-3-x64.dll`
- `libssl-3-x64.dll`

Place these DLLs in:

`target/release/`
