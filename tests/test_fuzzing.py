import os
from pathlib import Path
from faz2_quantum_vault import QuantumVault

def test_fuzzing_corrupted_vault_file(tmp_path):
    vault_dir = tmp_path / "vault_storage"
    keys_dir = tmp_path / "vault_keys"
    vault = QuantumVault(vault_dir=vault_dir, keys_dir=keys_dir)

    sample = tmp_path / "sample.txt"
    sample.write_text("Sensible Confidential Data", encoding="utf-8")
    vault_path = vault.lock_file_stream(str(sample))

    # Read valid vault bytes and corrupt random byte
    vault_bytes = bytearray(Path(vault_path).read_bytes())
    vault_bytes[50] ^= 0xAA # Flip bits in header/ciphertext

    corrupted_file = tmp_path / "corrupted.qvault"
    corrupted_file.write_bytes(vault_bytes)

    # Decryption must fail gracefully with ValueError or cryptographic exception, never unhandled crash
    failed = False
    try:
        vault.unlock_file_stream(str(corrupted_file), output_dir=str(tmp_path / "out"))
    except Exception:
        failed = True
    assert failed, "Corrupted vault file must be rejected by integrity check!"
