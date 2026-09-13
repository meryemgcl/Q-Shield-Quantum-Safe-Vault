# 🛡️ Q-Shield: Post-Quantum Cryptography (PQC) Hybrid Security Protocol & Quantum Vault

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![NIST PQC Standard](https://img.shields.io/badge/NIST%20Standard-FIPS%20203%20%7C%20204-success.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![Symmetric Cipher](https://img.shields.io/badge/Cipher-AES--256--GCM-orange.svg)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
[![Docker Ready](https://img.shields.io/badge/Docker-compose%20ready-blue.svg)](Dockerfile)
[![NIST KAT](https://img.shields.io/badge/KAT%20Tests-Deterministic%20Passed-success.svg)](tests/test_kat.py)
[![CI/CD Pipeline](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-brightgreen.svg)](https://github.com/meryemgcl/Q-Shield-Quantum-Safe-Vault/actions)
[![Android SDK](https://img.shields.io/badge/Mobile-Android%20Kotlin%20%26%20JNI%20C%2B%2B-green.svg)](mobile/android/)

**An Enterprise-Grade, NIST-Compliant Post-Quantum Cryptography Hybrid Protocol, Streaming Quantum Vault, and Peer-to-Peer TCP Messaging Suite.**

[Architecture](#-architecture) • [Security Hardening](#-security-hardening--features) • [Installation](#-installation) • [CLI Usage](#-command-line-interface-cli) • [Benchmarks](#-cryptographic-benchmarks) • [Android SDK](#-mobile-android-sdk-integration)

</div>

---

## 📖 Overview & Motivation

Modern global cybersecurity infrastructure predominantly relies on asymmetric public-key cryptosystems—principally **RSA** and **Elliptic Curve Cryptography (ECC)**. The mathematical security of these algorithms hinges on the hardness of the *Integer Factorization Problem (IFP)* and the *Discrete Logarithm Problem (DLP)*.

With the rapid emergence of fault-tolerant quantum computing, **Shor's Algorithm (1994)** will break 2048-bit RSA and standard 256-bit ECC in polynomial time $\mathcal{O}((\log N)^3)$. 

### The "Harvest Now, Decrypt Later" (HNDL) Threat
Hostile state actors and cyber syndicates are actively eavesdropping and stockpiling encrypted network packets and corporate backups today. Once cryptanalytically relevant quantum computers (CRQCs) materialize, this archived intelligence will be retroactively deciphered.

**Q-Shield** solves this existential threat immediately. By combining NIST-standardized **Lattice-Based Cryptography** (**CRYSTALS-Kyber-768 / ML-KEM** and **CRYSTALS-Dilithium-3 / ML-DSA**) with hardware-accelerated **AES-256-GCM**, Q-Shield delivers **unbreakable quantum immunity** with sub-millisecond execution latency.

---

## 🔒 Security Hardening & Enterprise Features

1. **Constant-Time Cryptographic Primitives:**
   - Negacyclic polynomial multiplication and sampling are engineered without early data-dependent branches, mitigating timing-based side-channel attacks.
2. **RAM Zeroization:**
   - Secret seeds and temporary key material are wiped in memory with `0x00` (`memset` / bytearray overwrite) immediately after use, preventing memory-dump extraction.
3. **Key-at-Rest Encryption (KEK):**
   - Private keys (`user_kyber.enc_key`, `user_dilithium.enc_key`) are never stored in plaintext. They are encrypted with AES-256-GCM using keys derived from a Master Password via **PBKDF2-HMAC-SHA256 (600,000 rounds)**.
4. **Chunked Streaming Vault Engine (`.qvault`):**
   - Files of arbitrary size (10 MB to 10+ GB) are processed in 64 KB blocks with unique sequential nonces. Memory consumption remains $O(1)$ constant (~64 KB).
5. **DoD 5220.22-M Secure Shredding:**
   - When files are locked or shredded, storage sectors are overwritten with 3 passes (0x00, 0xFF, CSPRNG bytes) with forced flush (`fsync`) before unlink.
6. **TCP Socket Network & Anti-Replay Defense:**
   - Real TCP socket server and client implementation with monotonic sequence numbers, sliding time window (30s), and nonce caching.

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
  |    (Timestamp + Nonce + Sequence)     |       | 5. Dilithium Signature Generation     |
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

## 📂 Repository Structure

```
Q-Shield-Quantum-Safe-Vault/
├── .github/
│   └── workflows/ci.yml        # Multi-OS CI/CD Pipeline (Ubuntu, macOS, Windows)
├── src/
│   └── qshield/
│       ├── core/               # Kyber-768, Dilithium-3 & AES-GCM engine
│       ├── vault/              # Local Quantum Vault storage manager (.qvault)
│       ├── protocol/           # Peer-to-peer PQC TCP handshake & attack defense
│       ├── sdk/                # Developer client library
│       └── cli.py              # Unified Command Line Interface
├── native/                     # Native C/C++ AVX2/NEON constant-time acceleration
│   ├── pqcrypto_core.h
│   └── pqcrypto_core.c
├── mobile/android/             # Android Kotlin / JNI Library Module
│   └── qshield-sdk/
│       ├── build.gradle.kts
│       └── src/main/cpp/native-lib.cpp
├── docs/
│   └── architecture_spec.md    # In-depth Cryptographic Specification
├── tests/
│   ├── test_kyber.py           # Unit tests for ML-KEM encapsulation & decapsulation
│   ├── test_dilithium.py       # Unit tests for ML-DSA signature verification & tampering
│   ├── test_protocol.py        # Unit tests for PQC handshake & MITM interception
│   ├── test_key_at_rest.py     # Unit tests for PBKDF2 KEK password protection
│   ├── test_streaming.py       # Unit tests for 64 KB chunked streaming encryption
│   └── test_fuzzing.py         # Fuzzing tests for malformed & corrupted payloads
├── dashboard/                  # Streamlit Interactive Security Center (faz4_dashboard.py)
├── pyproject.toml              # Modern Python packaging configuration
├── requirements.txt            # Production dependencies
├── SECURITY.md                 # Security vulnerability disclosure policy
├── CONTRIBUTING.md             # Contribution guidelines
├── LICENSE                     # MIT License
└── run_tests.py                # Standalone automated test runner
```

---

## ⚡ Installation

```bash
# Clone the repository
git clone https://github.com/meryemgcl/Q-Shield-Quantum-Safe-Vault.git
cd Q-Shield-Quantum-Safe-Vault

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Command Line Interface (CLI)

```bash
# Run latency and key size benchmarks comparing RSA vs PQC
python -m src.qshield.cli benchmark

# Encrypt and lock any file into the Quantum Vault (Streaming)
python -m src.qshield.cli lock "financial_audit_2026.pdf" --delete

# Unlock and restore an encrypted vault container
python -m src.qshield.cli unlock "vault_storage/financial_audit_1789322260.qvault"

# Securely shred and destroy a sensitive file (DoD 5220.22-M)
python -m src.qshield.cli shred "unclassified_draft.docx"

# Start a real PQC TCP Socket Server
python -m src.qshield.cli listen --port 9123 --node "Bank_Mainframe"

# Connect via real TCP socket and send an encrypted quantum payload
python -m src.qshield.cli connect --host 127.0.0.1 --port 9123 --target "Bank_Mainframe" --msg "Wire Transfer #402"

# Launch the interactive Streamlit Web Security Dashboard
python -m src.qshield.cli dashboard
```

---

## 📊 Cryptographic Benchmarks

| Algorithm (Security Level) | Key Generation | Encapsulation | Decapsulation | Public Key Size | Ciphertext Size |
|-----------------------------|----------------|---------------|---------------|-----------------|-----------------|
| **RSA-2048** (Legacy)       | 150.0+ ms      | 0.1 ms        | 1.5 ms        | 256 B           | 256 B           |
| **RSA-4096** (Legacy)       | 800.0+ ms      | 0.3 ms        | 8.0 ms        | 512 B           | 512 B           |
| **Kyber-768** (Post-Quantum)| **< 1.0 ms**   | **< 0.5 ms**  | **< 0.5 ms**  | **1184 B**      | **1088 B**      |

> *Note: Results measured on development hardware. Performance varies by CPU architecture, OS, and Python version.*

---

## 📱 Mobile (Android) SDK Integration

Located in [`mobile/android/qshield-sdk`](mobile/android/qshield-sdk):
- Native C++ JNI bridge (`native-lib.cpp`) interfacing hardware-backed ARM NEON instructions.
- Kotlin client class (`QShieldClient.kt`) interfacing Android StrongBox Keystore.
- Streaming encrypted file vaulting directly on Android internal storage.

---

## 🧪 Testing & CI/CD

```bash
# Run full automated test suite (Unit, Streaming, Key-at-Rest, Fuzzing)
python run_tests.py
```

Output:
```
test_01_kyber_primitives (__main__.TestQShieldSuite.test_01_kyber_primitives) ... ok
test_02_dilithium_signatures (__main__.TestQShieldSuite.test_02_dilithium_signatures) ... ok
test_03_protocol_and_mitm (__main__.TestQShieldSuite.test_03_protocol_and_mitm) ... ok
test_04_key_at_rest_protection (__main__.TestQShieldSuite.test_04_key_at_rest_protection) ... ok
test_05_streaming_large_file (__main__.TestQShieldSuite.test_05_streaming_large_file) ... ok
test_06_fuzzing_integrity (__main__.TestQShieldSuite.test_06_fuzzing_integrity) ... ok

----------------------------------------------------------------------
Ran 6 tests in 3.220s

OK
```

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for complete details.

