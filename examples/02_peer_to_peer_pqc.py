"""
Q-Shield Example 2: Peer-to-Peer Post-Quantum Handshake
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from faz3_pqc_protocol import PQCNode

def main():
    print("Initializing Post-Quantum Nodes...")
    alice = PQCNode("Alice_Fintech")
    bob = PQCNode("Bob_Liquidity")

    # Step 1: Alice initiates handshake
    init_packet = alice.initiate_handshake(bob.node_id)

    # Step 2: Bob responds with encapsulated key
    resp_packet = bob.respond_handshake(init_packet)

    # Step 3: Alice decapsulates and establishes common secret
    alice.finalize_handshake(resp_packet)

    assert alice.active_sessions[bob.node_id] == bob.active_sessions[alice.node_id]
    print(f"Mutual Quantum Session Key Established: {alice.active_sessions[bob.node_id].hex()[:32]}...")

    # Step 4: Exchange authenticated AES-256-GCM messages
    msg = "SWIFT Transfer Execution #88129: $10,000,000 USD"
    sec_packet = alice.send_secure_message(bob.node_id, msg)
    decrypted = bob.receive_secure_message(sec_packet)
    print(f"Received and decrypted successfully: {decrypted}")

if __name__ == "__main__":
    main()
