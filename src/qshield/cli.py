"""
Q-Shield Command Line Interface (CLI)
Usage:
    python -m src.qshield.cli benchmark
    python -m src.qshield.cli lock <filepath>
    python -m src.qshield.cli unlock <vaultpath>
    python -m src.qshield.cli shred <filepath>
    python -m src.qshield.cli listen --port 9123
    python -m src.qshield.cli connect --host 127.0.0.1 --port 9123 --msg "..."
    python -m src.qshield.cli list
    python -m src.qshield.cli dashboard
"""

import sys
import argparse
import subprocess
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from faz1_crypto_core import run_benchmarks
from faz2_quantum_vault import QuantumVault, secure_shred
from faz3_pqc_protocol import run_protocol_demo, PQCSocketServer, PQCSocketClient

def main():
    parser = argparse.ArgumentParser(
        prog="qshield",
        description="Q-Shield: Post-Quantum Cryptography Hybrid Security Suite"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Benchmark
    subparsers.add_parser("benchmark", help="Run cryptographic latency & key size benchmarks (RSA vs PQC)")

    # Vault Lock (Streaming)
    lock_p = subparsers.add_parser("lock", help="Encrypt and lock a file into the Quantum Vault (Streaming)")
    lock_p.add_argument("file", help="Path to file to encrypt")
    lock_p.add_argument("--delete", action="store_true", help="Securely shred original file (DoD 5220.22-M)")
    lock_p.add_argument("--password", default=None, help="Optional Master Password to protect private keys")

    # Vault Unlock
    unlock_p = subparsers.add_parser("unlock", help="Decrypt and unlock a .qvault file (Streaming)")
    unlock_p.add_argument("vault_file", help="Path to .qvault file")
    unlock_p.add_argument("--out", default="restored_files", help="Output directory for restored file")
    unlock_p.add_argument("--password", default=None, help="Master Password if key was password-protected")

    # Secure Shred
    shred_p = subparsers.add_parser("shred", help="Securely destroy a file according to DoD 5220.22-M")
    shred_p.add_argument("file", help="Path to file to shred")

    # Vault List
    subparsers.add_parser("list", help="List all encrypted files in the Quantum Vault")

    # Protocol Demo / Socket Listen
    subparsers.add_parser("protocol", help="Run local PQC handshake & attack simulation")

    listen_p = subparsers.add_parser("listen", help="Start real TCP socket server for PQC handshakes")
    listen_p.add_argument("--host", default="127.0.0.1", help="Host address to bind")
    listen_p.add_argument("--port", type=int, default=9123, help="Port to listen on")
    listen_p.add_argument("--node", default="Server_Node", help="Server node identifier")

    conn_p = subparsers.add_parser("connect", help="Connect to PQC TCP server and exchange encrypted message")
    conn_p.add_argument("--host", default="127.0.0.1", help="Server host address")
    conn_p.add_argument("--port", type=int, default=9123, help="Server port")
    conn_p.add_argument("--target", default="Server_Node", help="Target node identifier")
    conn_p.add_argument("--msg", default="Secure Quantum Payload", help="Message to encrypt and transmit")

    # Dashboard
    subparsers.add_parser("dashboard", help="Launch interactive Streamlit security center")

    args = parser.parse_args()

    if args.command == "benchmark":
        run_benchmarks()
    elif args.command == "lock":
        vault = QuantumVault(master_password=args.password) if args.password else QuantumVault()
        out = vault.lock_file_stream(args.file, delete_original=args.delete)
        print(f"[OK] File successfully locked: {out}")
    elif args.command == "unlock":
        vault = QuantumVault(master_password=args.password) if args.password else QuantumVault()
        out = vault.unlock_file_stream(args.vault_file, output_dir=args.out)
        print(f"[OK] File successfully unlocked: {out}")
    elif args.command == "shred":
        secure_shred(Path(args.file))
        print(f"[OK] File shredded and securely destroyed: {args.file}")
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
    elif args.command == "listen":
        srv = PQCSocketServer(host=args.host, port=args.port, node_id=args.node)
        srv.start()
    elif args.command == "connect":
        cli = PQCSocketClient(host=args.host, port=args.port)
        res = cli.connect_and_send(args.target, args.msg)
        print(f"[OK] Decrypted response from server: {res}")
    elif args.command == "dashboard":
        print("Launching Q-Shield Streamlit Dashboard...")
        subprocess.run([sys.executable, "-m", "streamlit", "run", "faz4_dashboard.py"])
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
