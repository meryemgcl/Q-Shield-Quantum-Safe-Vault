"""
Q-Shield Command Line Interface (CLI)
Usage:
    python -m src.qshield.cli benchmark
    python -m src.qshield.cli lock <filepath>
    python -m src.qshield.cli unlock <vaultpath>
    python -m src.qshield.cli list
    python -m src.qshield.cli dashboard
"""

import sys
import argparse
import subprocess
from pathlib import Path

# Windows console encoding safety
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from faz1_crypto_core import run_benchmarks
from faz2_quantum_vault import QuantumVault
from faz3_pqc_protocol import run_protocol_demo

def main():
    parser = argparse.ArgumentParser(
        prog="qshield",
        description="Q-Shield: Post-Quantum Cryptography Hybrid Security Suite"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Benchmark
    subparsers.add_parser("benchmark", help="Run cryptographic latency & key size benchmarks (RSA vs PQC)")

    # Vault Lock
    lock_p = subparsers.add_parser("lock", help="Encrypt and lock a file into the Quantum Vault")
    lock_p.add_argument("file", help="Path to file to encrypt")
    lock_p.add_argument("--delete", action="store_true", help="Securely delete original file after locking")

    # Vault Unlock
    unlock_p = subparsers.add_parser("unlock", help="Decrypt and unlock a .qvault file")
    unlock_p.add_argument("vault_file", help="Path to .qvault file")
    unlock_p.add_argument("--out", default="restored_files", help="Output directory for restored file")

    # Vault List
    subparsers.add_parser("list", help="List all encrypted files in the Quantum Vault")

    # Protocol Demo
    subparsers.add_parser("protocol", help="Run peer-to-peer PQC handshake & attack simulation")

    # Dashboard
    subparsers.add_parser("dashboard", help="Launch interactive Streamlit security center")

    args = parser.parse_args()

    if args.command == "benchmark":
        run_benchmarks()
    elif args.command == "lock":
        vault = QuantumVault()
        out = vault.lock_file(args.file, delete_original=args.delete)
        print(f"[OK] File successfully locked: {out}")
    elif args.command == "unlock":
        vault = QuantumVault()
        out = vault.unlock_file(args.vault_file, output_dir=args.out)
        print(f"[OK] File successfully unlocked: {out}")
    elif args.command == "list":
        vault = QuantumVault()
        items = vault.list_vault()
        if not items:
            print("Quantum Vault is currently empty.")
        else:
            print(f"{'Vault File':<35} | {'Size':<10} | {'Status':<25}")
            print("-" * 75)
            for it in items:
                print(f"{it['vault_file']:<35} | {it['size_bytes']:<8} B | {it['quantum_status']}")
    elif args.command == "protocol":
        run_protocol_demo()
    elif args.command == "dashboard":
        print("Launching Q-Shield Streamlit Dashboard...")
        subprocess.run([sys.executable, "-m", "streamlit", "run", "faz4_dashboard.py"])
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
