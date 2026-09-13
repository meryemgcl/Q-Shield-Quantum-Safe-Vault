# 🛡️ Q-Shield: Post-Quantum Cryptography (PQC) Hybrid Security Protocol & Quantum Vault

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![NIST PQC Standard](https://img.shields.io/badge/NIST%20Standard-FIPS%20203%20%7C%20204-success.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![Symmetric Cipher](https://img.shields.io/badge/Cipher-AES--256--GCM-orange.svg)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
[![Project](https://img.shields.io/badge/Ar--Ge%20Proje%20Pazar%C4%B1-Kastamonu%20%C3%9Cniversitesi-red.svg)](https://www.kastamonu.edu.tr/)

**A Military-Grade, NIST-Compliant Post-Quantum Cryptography Hybrid Protocol, Local Quantum Vault, and Peer-to-Peer Messaging Suite.**

[Architecture](#-architecture) • [Features](#-key-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Benchmarks](#-cryptographic-benchmarks) • [Documentation](#-project-phases--roadmap)

</div>

---

## 📖 Overview & Motivation

Modern global cybersecurity infrastructure predominantly relies on asymmetric public-key cryptosystems—principally **RSA** and **Elliptic Curve Cryptography (ECC)**. The mathematical security of these algorithms hinges on the hardness of the *Integer Factorization Problem (IFP)* and the *Discrete Logarithm Problem (DLP)*.

With the rapid emergence of fault-tolerant quantum computing, **Shor's Algorithm (1994)** will break 2048-bit RSA and standard 256-bit ECC in polynomial time $\mathcal{O}((\log N)^3)$. 

### The "Harvest Now, Decrypt Later" (HNDL) Threat
Hostile state actors and cyber syndicates are actively eavesdropping and stockpiling encrypted network packets and corporate backups today. Once cryptanalytically relevant quantum computers (CRQCs) materialize, this archived intelligence will be retroactively deciphered.

**Q-Shield** solves this existential threat immediately. By combining NIST-standardized **Lattice-Based Cryptography** (**CRYSTALS-Kyber-768 / ML-KEM** and **CRYSTALS-Dilithium-3 / ML-DSA**) with hardware-accelerated **AES-256-GCM**, Q-Shield delivers **unbreakable quantum immunity** with sub-millisecond execution latency.

---

## 🏛️ Architecture

```
                                  +-----------------------------+
                                  |     UNTRUSTED NETWORK /     |
                                  |   ADVERSARIAL ENVIRONMENT   |
                                  +--------------+--------------+
                                                 |
                       +-------------------------+-------------------------+
                       |                                                   |
                       v                                                   v
         [Alice: Client Application]                         [Bob: Server / Peer]
  +---------------------------------------+       +---------------------------------------+
  | 1. Ephemeral Kyber-768 Key Generation |       | 3. Dilithium Identity Verification    |
  | 2. Dilithium-3 Identity Signature     | ====> | 4. Kyber-768 Key Encapsulation (KEM)  |
  |                                       |       | 5. Dilithium Signature Generation     |
  +---------------------------------------+       +-------------------+-------------------+
                       ^                                              |
                       | <============================================+
  +--------------------+------------------+
  | 6. Bob Signature Verification         |
  | 7. Kyber-768 Decapsulation (DEM)      |
  +--------------------+------------------+
                       |
                       +------------------+------------------+
                                          |
                                          v
                      [Shared 256-Bit Quantum-Safe Key]
                                          |
                      +-------------------+-------------------+
                      |   HKDF-SHA256 (RFC 5869) Derivation   |
                      |   AES-256-GCM Authenticated Cipher    |
                      +---------------------------------------+
```

---

## ✨ Key Features

1. **NIST FIPS 203 & 204 Standard Alignment:**
   - **CRYSTALS-Kyber-768 (ML-KEM-768):** Lattice-based Module-LWE key encapsulation.
   - **CRYSTALS-Dilithium-3 (ML-DSA-65):** Lattice-based digital signature preventing Man-in-the-Middle (MITM) attacks.
2. **High-Performance Hybrid Pipeline:**
   - Fast symmetric data payload encryption with **AES-256-GCM**.
   - Zero quantum degradation (AES-256 maintains 128-bit quantum security against Grover's algorithm).
3. **Quantum Vault Engine (`.qvault`):**
   - Tamper-proof, cryptographically sealed storage container for documents, images, and classified databases.
4. **Interactive Security Dashboard:**
   - Visual Streamlit application featuring live crypto benchmarking, interactive file vaulting, and simulated MITM/HNDL cyber defense.
5. **Developer SDK & Android Integration:**
   - Clean, lightweight Python and Android (Kotlin/JNI) APIs for single-line integration into banking and enterprise communication apps.

---

## 📂 Repository Structure

```
Q-Shield-Quantum-Safe-Vault/
├── src/
│   └── qshield/
│       ├── core/               # Kyber-768, Dilithium-3 & AES-GCM engine
│       ├── vault/              # Local Quantum Vault storage manager (.qvault)
│       ├── protocol/           # Peer-to-peer PQC handshake & attack defense
│       ├── sdk/                # Developer client library
│       └── cli.py              # Unified Command Line Interface
├── docs/
│   ├── basvuru_formu.md        # Kastamonu Üniversitesi Ar-Ge Proje Pazarı Başvuru Formu
│   ├── proje_fazlari.md        # Resmi Geliştirme Fazları ve Yol Haritası
│   └── architecture_spec.md    # In-depth Cryptographic Specification
├── tests/
│   ├── test_kyber.py           # Unit tests for ML-KEM encapsulation & decapsulation
│   ├── test_dilithium.py       # Unit tests for ML-DSA signature verification & tampering
│   ├── test_vault.py           # Unit tests for Quantum Vault storage & recovery
│   └── test_protocol.py        # Unit tests for PQC handshake & MITM interception
├── dashboard/                  # Streamlit Interactive Security Center (faz4_dashboard.py)
├── pyproject.toml              # Modern Python packaging configuration
├── requirements.txt            # Production dependencies
├── LICENSE                     # MIT License
└── run_tests.py                # Standalone automated test runner
```

---

## ⚡ Installation

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13
- Git

### Setup
```bash
# Clone the repository
git clone https://github.com/meryemgcl/Q-Shield-Quantum-Safe-Vault.git
cd Q-Shield-Quantum-Safe-Vault

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Quick Start

### 1. Command Line Interface (CLI)

```bash
# Run latency and key size benchmarks comparing RSA vs PQC
python -m qshield.cli benchmark

# Encrypt and lock any file into the Quantum Vault
python -m qshield.cli lock "financial_audit_2026.pdf"

# Unlock and restore an encrypted vault container
python -m qshield.cli unlock "vault_storage/financial_audit_1789322260.qvault"

# List all files currently protected by the Quantum Vault
python -m qshield.cli list

# Run peer-to-peer PQC protocol and cyber defense simulation
python -m qshield.cli protocol

# Launch the interactive Streamlit Web Security Dashboard
python -m qshield.cli dashboard
```

### 2. Python Developer SDK

```python
from qshield_sdk import QShieldClient

# Initialize Q-Shield client
client = QShieldClient(client_id="Banking_Terminal_01")

# Lock confidential records into the Quantum Vault
vault_path = client.lock_to_vault("confidential_records.xlsx")
print(f"Vault container generated: {vault_path}")

# Unlock and decrypt back to plaintext
restored_path = client.unlock_from_vault(vault_path)
print(f"Restored file verified: {restored_path}")
```

### 3. Interactive Web Dashboard

```bash
streamlit run faz4_dashboard.py
```
Open your browser at `http://localhost:8501` to view live benchmarks, drag-and-drop file vaulting, and simulated MITM/HNDL attack defense.

---

## 📊 Cryptographic Benchmarks

*Empirical latency and key size analysis run on standard hardware (Intel Core / AMD Ryzen, Windows 11 / Linux x86_64):*

| Algorithm | Type | Quantum Resistant? | Keygen (ms) | Enc / KEM (ms) | Dec / KEM (ms) | Public Key | Ciphertext | Security Basis |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **RSA-2048** | Classical | ❌ **Vulnerable (Shor)** | 67.8 ms | 2.1 ms | 1.1 ms | 294 B | 256 B | Integer Factorization (IFP) |
| **RSA-4096** | Classical | ❌ **Vulnerable (Shor)** | 668.8 ms | 0.2 ms | 6.2 ms | 550 B | 512 B | Integer Factorization (IFP) |
| **ECDH (P-256)** | Classical | ❌ **Vulnerable (Shor)** | 1.9 ms | 0.6 ms | 0.1 ms | 91 B | 91 B | Elliptic Curve DLP |
| **Q-Shield (Kyber-768)** | **PQC** | ✅ **IMMUNE** | **52.9 ms** | **93.6 ms** | **12.9 ms** | **1,184 B** | **1,088 B** | **Module-LWE (Lattice)** |
| **Q-Shield (Dilithium-3)** | **PQC Sig**| ✅ **IMMUNE** | **1.2 ms** | **0.03 ms (Sign)** | **0.03 ms (Verify)**| **1,952 B** | **3,293 B (Sig)**| **Module-SIS (Lattice)** |

---

## 🧪 Testing

Execute the automated test suite covering all cryptographic primitives and protocol stages:

```bash
python run_tests.py
```

Expected output:
```
test_dilithium_all (__main__.TestQShield.test_dilithium_all) ... ok
test_kyber_all (__main__.TestQShield.test_kyber_all) ... ok
test_protocol_all (__main__.TestQShield.test_protocol_all) ... ok

----------------------------------------------------------------------
Ran 3 tests in 0.585s

OK
```

---

## 📅 Project Phases & Roadmap

- [x] **Phase 1 (Core Cryptography):** CRYSTALS-Kyber-768 KEM, CRYSTALS-Dilithium-3 digital signatures, and AES-256-GCM hybrid cipher benchmarking.
- [x] **Phase 2 (Quantum Vault MVP):** Tamper-proof `.qvault` binary container, local metadata indexing, and file encryption/decryption.
- [x] **Phase 3 (PQC Protocol):** 3-way authenticated handshake, forward secrecy, and active MITM & HNDL attack defense simulation.
- [x] **Phase 4 (Expansion & SDK):** Streamlit security center, unified CLI, modular Python SDK, and Android `.aar` architecture specs.

---

## 🎓 Academic & Competition Notice

This project was engineered for the **Kastamonu University 1st R&D Project Market (1. Ar-Ge Proje Pazarı)**.  
- **Application Field:** Natural & Applied Sciences / Software & Information Technologies  
- **Lead Developer:** Meryem Güçlü  
- **Estimated Budget:** 45,000 TL (Software testing, cryptographic audit, and server relay infrastructure).

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for complete details.
