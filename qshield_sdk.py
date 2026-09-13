"""
Q-Shield Developer SDK & Client Library
Mobil, Masaüstü ve Sunucu Uygulamaları için Kuantum Sonrası Kriptografi (PQC) SDK'sı.

Kullanım:
    from qshield_sdk import QShieldClient

    client = QShieldClient()
    # 1. Dosya veya veri şifreleme (AES-256 + Kyber-768)
    encrypted_pkg = client.encrypt_data(b"Gizli Bankacilik Verisi", recipient_public_key)

    # 2. Şifreli paketi çözme
    original_data = client.decrypt_data(encrypted_pkg)
"""

import base64
from typing import Dict, Any, Optional
from crypto_core import Kyber768, Dilithium3, HybridCipher
from faz2_quantum_vault import QuantumVault
from faz3_pqc_protocol import PQCNode

class QShieldClient:
    """
    Üçüncü parti yazılımcıların uygulamalarına tek satırla
    Kuantum Güvenliği eklemesini sağlayan Q-Shield SDK İstemcisi.
    """

    def __init__(self, client_id: str = "Client_App"):
        self.client_id = client_id
        self.vault = QuantumVault()
        self.node = PQCNode(client_id)

    def get_public_key(self) -> str:
        """İstemcinin CRYSTALS-Kyber-768 açık anahtarını Base64 olarak döndürür."""
        return base64.b64encode(self.vault.kyber_pk).decode("ascii")

    def get_identity_signature_key(self) -> str:
        """İstemcinin CRYSTALS-Dilithium-3 açık kimlik anahtarını döndürür."""
        return base64.b64encode(self.vault.dilithium_pk).decode("ascii")

    def encrypt_data(self, data: bytes, recipient_kyber_pk_b64: str) -> Dict[str, Any]:
        """Kuantum hibrit şifreleme yapar."""
        recipient_pk = base64.b64decode(recipient_kyber_pk_b64)
        return HybridCipher.encrypt(data, recipient_pk, self.vault.dilithium_sk)

    def decrypt_data(self, envelope: Dict[str, Any], sender_dilithium_pk_b64: Optional[str] = None) -> bytes:
        """Kuantum hibrit şifreli paketi çözer."""
        sender_dpk = base64.b64decode(sender_dilithium_pk_b64) if sender_dilithium_pk_b64 else None
        return HybridCipher.decrypt(envelope, self.vault.kyber_sk, sender_dpk)

    def lock_to_vault(self, filepath: str) -> str:
        """Yerel dosyayı kuantum kasasına kilitler."""
        return self.vault.lock_file(filepath)

    def unlock_from_vault(self, vault_path: str) -> str:
        """Kasadan dosyayı çözer."""
        return self.vault.unlock_file(vault_path)
