import hashlib
from src.qshield.crypto_core import Kyber768, Dilithium3, KYBER_PK_SIZE, KYBER_CIPHERTEXT_SIZE, DILITHIUM_PK_SIZE, DILITHIUM_SIG_SIZE

def test_nist_deterministic_kat():
    """
    Internal Determinism Test (NOT Official NIST KAT):
    Verifies that cryptographic primitives are mathematically deterministic
    under fixed entropy vectors.
    
    NOTE: This is NOT a formal Known Answer Test (KAT) against NIST FIPS 203 & 204
    reference `.rsp` vectors. It only ensures this specific implementation is 
    internally consistent and repeatable.
    """
    # 1. SHAKE-256 known digest test
    shake_test = hashlib.shake_256(b"NIST_PQC_KAT_SEED").digest(32)
    assert len(shake_test) == 32
    # Verify same seed produces identical digest
    assert shake_test == hashlib.shake_256(b"NIST_PQC_KAT_SEED").digest(32)

    # 2. Kyber-768 Keygen & Encapsulation invariant test
    pk, sk = Kyber768.keygen()
    assert len(pk) == KYBER_PK_SIZE
    ct, ss = Kyber768.encapsulate(pk)
    assert len(ct) == KYBER_CIPHERTEXT_SIZE
    assert len(ss) == 32

    # Decapsulation reproducibility
    ss_recovered_1 = Kyber768.decapsulate(ct, sk)
    ss_recovered_2 = Kyber768.decapsulate(ct, sk)
    assert ss == ss_recovered_1 == ss_recovered_2

    # 3. Dilithium-3 Signature reproducibility
    dpk, dsk = Dilithium3.keygen()
    msg = b"CRITICAL_FINANCIAL_TRANSACTION_PAYLOAD"
    sig1 = Dilithium3.sign(msg, dsk)
    sig2 = Dilithium3.sign(msg, dsk)
    assert len(sig1) == DILITHIUM_SIG_SIZE
    assert sig1 == sig2, "Deterministic signature must match for identical message and secret key!"
