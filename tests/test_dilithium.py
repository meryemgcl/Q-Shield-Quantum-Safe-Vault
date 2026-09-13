from crypto_core import Dilithium3, DILITHIUM_PK_SIZE, DILITHIUM_SK_SIZE, DILITHIUM_SIG_SIZE

def test_dilithium_keygen():
    pk, sk = Dilithium3.keygen()
    assert len(pk) == DILITHIUM_PK_SIZE
    assert len(sk) == DILITHIUM_SK_SIZE

def test_dilithium_sign_and_verify():
    pk, sk = Dilithium3.keygen()
    msg = b"Kuantum Sonrasi Guvenlik Dogrulamasi"
    sig = Dilithium3.sign(msg, sk)
    assert len(sig) == DILITHIUM_SIG_SIZE
    assert Dilithium3.verify(msg, sig, pk) is True

def test_dilithium_tampered_message_fails():
    pk, sk = Dilithium3.keygen()
    msg = b"Orijinal Belge"
    sig = Dilithium3.sign(msg, sk)
    tampered_msg = b"Tahrif Edilmis Belge"
    assert Dilithium3.verify(tampered_msg, sig, pk) is False

def test_dilithium_tampered_signature_fails():
    pk, sk = Dilithium3.keygen()
    msg = b"Orijinal Belge"
    sig = bytearray(Dilithium3.sign(msg, sk))
    sig[10] ^= 0xFF
    assert Dilithium3.verify(msg, bytes(sig), pk) is False
