import pytest
from pathlib import Path
from src.qshield.quantum_vault import QuantumVault

def test_vault_roundtrip(tmp_path):
    vault_dir = tmp_path / "vault_storage"
    keys_dir = tmp_path / "vault_keys"
    restore_dir = tmp_path / "restored"

    vault = QuantumVault(master_password='test-password-123!', vault_dir=vault_dir, keys_dir=keys_dir)

    test_file = tmp_path / "secret.txt"
    secret_text = "Çok Gizli Kuantum Bilgisi 2026"
    test_file.write_text(secret_text, encoding="utf-8")

    # Lock
    vault_path = vault.lock_file(str(test_file))
    assert Path(vault_path).exists()
    assert vault_path.endswith(".qvault")

    # Unlock
    restored_path = vault.unlock_file(vault_path, output_dir=str(restore_dir))
    assert Path(restored_path).exists()
    assert Path(restored_path).read_text(encoding="utf-8") == secret_text
