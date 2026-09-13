import base64
from faz3_pqc_protocol import PQCNode
from crypto_core import Kyber768

def test_pqc_handshake_and_messaging():
    alice = PQCNode("Alice_Test")
    bob = PQCNode("Bob_Test")

    init_pkt = alice.initiate_handshake(bob.node_id)
    resp_pkt = bob.respond_handshake(init_pkt)
    alice.finalize_handshake(resp_pkt)

    assert alice.active_sessions[bob.node_id] == bob.active_sessions[alice.node_id]

    test_message = "Kuantum Test Mesajı"
    msg_packet = alice.send_secure_message(bob.node_id, test_message)
    decrypted = bob.receive_secure_message(msg_packet)
    assert decrypted == test_message

def test_pqc_mitm_detection():
    alice = PQCNode("Alice_Test")
    bob = PQCNode("Bob_Test")

    init_pkt = alice.initiate_handshake(bob.node_id)
    tampered_pkt = dict(init_pkt)
    fake_pk, _ = Kyber768.keygen()
    tampered_pkt["kyber_pk"] = base64.b64encode(fake_pk).decode("ascii")

    mitm_intercepted = False
    try:
        bob.respond_handshake(tampered_pkt)
    except PermissionError:
        mitm_intercepted = True
    assert mitm_intercepted, "MITM attack should be intercepted!"
