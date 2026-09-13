import os
from crypto_core import KeyAtRestManager

def test_key_at_rest_roundtrip():
    raw_key = os.urandom(2400) # Kyber-768 SK size
    password = "CorrectHorseBatteryStaple2026!"

    encrypted_record = KeyAtRestManager.encrypt_key_at_rest(raw_key, password)
    assert encrypted_record["format"] == "QSHIELD_KEK_V1"
    assert encrypted_record["iterations"] == 600_000

    decrypted_key = KeyAtRestManager.decrypt_key_at_rest(encrypted_record, password)
    assert decrypted_key == raw_key

def test_key_at_rest_wrong_password_fails():
    raw_key = os.urandom(32)
    password = "SecurePassword123"
    wrong_password = "WrongPassword456"

    encrypted_record = KeyAtRestManager.encrypt_key_at_rest(raw_key, password)

    failed = False
    try:
        KeyAtRestManager.decrypt_key_at_rest(encrypted_record, wrong_password)
    except ValueError:
        failed = True
    assert failed, "Decryption with wrong password must raise ValueError!"
