"""
Q-Shield Example 1: Basic Quantum Vault Usage
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from faz2_quantum_vault import QuantumVault

def main():
    vault = QuantumVault()

    # 1. Create a sample secret document
    doc_path = Path("confidential_memo.txt")
    doc_path.write_text("TOP SECRET: Strategic Quantum Roadmap 2026-2035", encoding="utf-8")
    print(f"Created document: {doc_path}")

    # 2. Lock to Quantum Vault
    vault_file = vault.lock_file(str(doc_path))
    print(f"Locked into Quantum Vault: {vault_file}")

    # 3. Unlock and verify
    restored = vault.unlock_file(vault_file)
    print(f"Restored document: {restored}")
    print(f"Content: {Path(restored).read_text(encoding='utf-8')}")

if __name__ == "__main__":
    main()
