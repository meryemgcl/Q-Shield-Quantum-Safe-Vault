from crypto_core import Kyber768, KYBER_PK_SIZE, KYBER_SK_SIZE, KYBER_CIPHERTEXT_SIZE, KYBER_SS_SIZE

def test_kyber_keygen():
    pk, sk = Kyber768.keygen()
    assert len(pk) == KYBER_PK_SIZE, f"Expected PK size {KYBER_PK_SIZE}, got {len(pk)}"
    assert len(sk) == KYBER_SK_SIZE, f"Expected SK size {KYBER_SK_SIZE}, got {len(sk)}"

def test_kyber_encapsulation_decapsulation():
    pk, sk = Kyber768.keygen()
    ct, ss_sender = Kyber768.encapsulate(pk)
    assert len(ct) == KYBER_CIPHERTEXT_SIZE
    assert len(ss_sender) == KYBER_SS_SIZE

    ss_receiver = Kyber768.decapsulate(ct, sk)
    assert ss_sender == ss_receiver, "Shared secrets do not match!"

def test_kyber_different_keys_generate_different_secrets():
    pk1, sk1 = Kyber768.keygen()
    pk2, sk2 = Kyber768.keygen()
    ct, ss1 = Kyber768.encapsulate(pk1)
    ss_wrong = Kyber768.decapsulate(ct, sk2)
    assert ss1 != ss_wrong, "Decapsulation with wrong key should yield different secret!"
