import os
from pathlib import Path
from faz2_quantum_vault import QuantumVault

def test_streaming_large_file(tmp_path):
    vault_dir = tmp_path / "vault_storage"
    keys_dir = tmp_path / "vault_keys"
    restore_dir = tmp_path / "restored"

    vault = QuantumVault(vault_dir=vault_dir, keys_dir=keys_dir)

    # 256 KB file spanning 4 chunks of 64 KB
    large_file = tmp_path / "large_payload.bin"
    original_data = os.urandom(256 * 1024)
    large_file.write_bytes(original_data)

    vault_path = vault.lock_file_stream(str(large_file))
    assert Path(vault_path).exists()

    restored_path = vault.unlock_file_stream(vault_path, output_dir=str(restore_dir))
    assert Path(restored_path).exists()
    assert Path(restored_path).read_bytes() == original_data
