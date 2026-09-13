# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-13
### Added
- **Q-Shield PQC Core Engine**: Pure-Python implementations of CRYSTALS-Kyber-768 (ML-KEM) and CRYSTALS-Dilithium-3 (ML-DSA) algorithms.
- **Quantum Vault**: 64 KB chunked streaming AES-GCM engine for secure, O(1) RAM file encryption.
- **Key-at-Rest Protection**: Private keys are encrypted on disk using PBKDF2-HMAC-SHA256 (600,000 iterations).
- **Secure Shredding**: DoD 5220.22-M compliant 3-pass file deletion for original plaintext files.
- **PQC TCP Protocol**: Real TCP socket implementation with robust anti-replay defense (sliding window + monotonic sequence + nonce cache).
- **HybridCipher**: AES-256-GCM enveloped by Kyber-768 encapsulation and Dilithium-3 signatures, now with RFC 5869 compliant per-call randomized HKDF salts.
- **Dashboard**: Streamlit-based graphical user interface for PQC benchmarks, Vault management, and Protocol visualization.
- **CLI**: Comprehensive command-line interface for all cryptographic operations.
- **Android SDK**: Kotlin Multiplatform mobile SDK template with native C++ JNI bridge for constant-time cryptographic primitives.
- **CI/CD Pipeline**: GitHub Actions workflows for matrix testing across multiple OS and Python versions.

### Security
- Hardened poly_mul_negacyclic_constant_time logic to mitigate early-exit timing side channels.
- Added secure_zeroize for safe in-place wiping of sensitive keys from Python memory.
- Enforced required master_password initialization in QuantumVault (removed unsafe hardcoded default).
- Translated all system exceptions and logs to English to aid in unified SIEM and DevOps monitoring.
