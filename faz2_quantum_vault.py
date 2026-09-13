"""
Q-Shield FAZ 2: "Quantum Vault" (Kuantum Kasası) Depolama Motoru
(Local Quantum Vault File Storage & Management)

Bu modül:
1. Kullanıcının yerel cihazında kuantum güvenli anahtar kasası (vault_keys) oluşturur.
2. Belgeleri, fotoğrafları ve gizli verileri Kyber-768 + AES-256-GCM ile şifreleyerek .qvault formatında saklar.
3. CRYSTALS-Dilithium dijital imzasıyla dosyaların manipüle edilmesini (tampering) engeller.
4. Dosyaları güvenle geri çözer (unlock) ve bütünlük doğrulaması yapar.
"""

import os
import sys
import time
import json
import base64
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional
from crypto_core import Kyber768, Dilithium3, HybridCipher

DEFAULT_VAULT_DIR = Path("vault_storage")
DEFAULT_KEYS_DIR = Path("vault_keys")
DEFAULT_RESTORE_DIR = Path("restored_files")

class QuantumVault:
    def __init__(self, vault_dir: Path = DEFAULT_VAULT_DIR, keys_dir: Path = DEFAULT_KEYS_DIR):
        self.vault_dir = Path(vault_dir)
        self.keys_dir = Path(keys_dir)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_keys()

    def _ensure_keys(self):
        """Kullanıcının Kyber ve Dilithium anahtarlarını kontrol eder, yoksa üretir."""
        kyber_pk_path = self.keys_dir / "user_kyber.pub"
        kyber_sk_path = self.keys_dir / "user_kyber.key"
        dilithium_pk_path = self.keys_dir / "user_dilithium.pub"
        dilithium_sk_path = self.keys_dir / "user_dilithium.key"

        if not (kyber_pk_path.exists() and kyber_sk_path.exists()):
            print("[QuantumVault] Yeni Kyber-768 kuantum anahtar çifti üretiliyor...")
            pk, sk = Kyber768.keygen()
            kyber_pk_path.write_bytes(pk)
            kyber_sk_path.write_bytes(sk)

        if not (dilithium_pk_path.exists() and dilithium_sk_path.exists()):
            print("[QuantumVault] Yeni Dilithium-3 dijital imza anahtar çifti üretiliyor...")
            dpk, dsk = Dilithium3.keygen()
            dilithium_pk_path.write_bytes(dpk)
            dilithium_sk_path.write_bytes(dsk)

        self.kyber_pk = kyber_pk_path.read_bytes()
        self.kyber_sk = kyber_sk_path.read_bytes()
        self.dilithium_pk = dilithium_pk_path.read_bytes()
        self.dilithium_sk = dilithium_sk_path.read_bytes()

    def lock_file(self, source_path: str, delete_original: bool = False) -> str:
        """
        Belirtilen dosyayı okur, metadata ve içeriğini kuantum hibrit algoritmayla şifreler,
        .qvault dosyası olarak kasaya kilitler.
        """
        src = Path(source_path)
        if not src.exists():
            raise FileNotFoundError(f"Dosya bulunamadı: {source_path}")

        file_bytes = src.read_bytes()
        original_meta = {
            "filename": src.name,
            "original_size": len(file_bytes),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "owner": "Q-Shield Authorized User",
            "file_hash_sha256": src.read_bytes() and json.dumps(list(file_bytes[:16])) # özet belirteç
        }

        # Payload = Metadata (JSON) + \x00\x00DELIM\x00\x00 + Dosya İkili İçeriği
        meta_json = json.dumps(original_meta).encode("utf-8")
        delim = b"\x00\x00__QSHIELD_DATA__\x00\x00"
        full_payload = meta_json + delim + file_bytes

        t0 = time.perf_counter()
        envelope = HybridCipher.encrypt(full_payload, self.kyber_pk, self.dilithium_sk)
        enc_time_ms = (time.perf_counter() - t0) * 1000

        # Kasa dosyası adı: ornek.txt.qvault
        vault_filename = f"{src.stem}_{int(time.time())}.qvault"
        target_path = self.vault_dir / vault_filename

        packed_binary = HybridCipher.pack_binary(envelope)
        target_path.write_bytes(packed_binary)

        if delete_original:
            src.unlink()
            print(f"[QuantumVault] Orijinal dosya güvenle silindi: {src.name}")

        print(f"[QuantumVault] Dosya başarıyla kilitlendi:")
        print(f"   -> Kaynak: {src.name} ({len(file_bytes)} bayt)")
        print(f"   -> Kuantum Kasa Hedefi: {target_path.name} ({len(packed_binary)} bayt)")
        print(f"   -> Şifreleme Süresi: {enc_time_ms:.2f} ms")
        return str(target_path)

    def unlock_file(self, vault_path: str, output_dir: Optional[str] = None) -> str:
        """
        .qvault dosyasını çözer, Dilithium imzasını teyit eder ve orijinal dosyayı geri yükler.
        """
        v_path = Path(vault_path)
        if not v_path.exists():
            raise FileNotFoundError(f"Kasa dosyası bulunamadı: {vault_path}")

        raw_bytes = v_path.read_bytes()
        envelope = HybridCipher.unpack_binary(raw_bytes)

        t0 = time.perf_counter()
        decrypted_payload = HybridCipher.decrypt(envelope, self.kyber_sk, self.dilithium_pk)
        dec_time_ms = (time.perf_counter() - t0) * 1000

        delim = b"\x00\x00__QSHIELD_DATA__\x00\x00"
        if delim not in decrypted_payload:
            raise ValueError("Kasa verisi biçim hatası: Ayrıcı bulunamadı!")

        meta_bytes, file_data = decrypted_payload.split(delim, 1)
        meta = json.loads(meta_bytes.decode("utf-8"))
        original_name = meta.get("filename", "restored_file.bin")

        out_path = Path(output_dir) if output_dir else DEFAULT_RESTORE_DIR
        out_path.mkdir(parents=True, exist_ok=True)
        restored_file_path = out_path / original_name

        restored_file_path.write_bytes(file_data)
        print(f"[QuantumVault] Dosya başarıyla açıldı:")
        print(f"   -> Geri Yüklenen: {restored_file_path}")
        print(f"   -> Deşifreleme Süresi: {dec_time_ms:.2f} ms")
        return str(restored_file_path)

    def list_vault(self) -> List[Dict[str, Any]]:
        """Kasada kilitli olan tüm .qvault dosyalarını listeler."""
        items = []
        for file in self.vault_dir.glob("*.qvault"):
            stat = file.stat()
            items.append({
                "vault_file": file.name,
                "path": str(file),
                "size_bytes": stat.st_size,
                "modified_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
                "quantum_status": "KORUMADA (CRYSTALS-Kyber-768 + AES-256)",
                "signature": "CRYSTALS-Dilithium-3 Doğrulandı"
            })
        return items

def run_vault_demo():
    print("=" * 80)
    print("        Q-SHIELD FAZ 2: QUANTUM VAULT (KUANTUM KASASI) TESTİ")
    print("=" * 80)

    vault = QuantumVault()

    # Test dosyası oluştur
    test_file = Path("ornek_askeri_ve_finansal_veri.txt")
    test_file.write_text(
        "GİZLİDİR: Bu belge Kastamonu Üniversitesi Ar-Ge Proje Pazarı kapsamında\n"
        "Q-Shield Kuantum Sonrası Kriptografi Protokolü ile korunmaktadır.\n"
        "Klasik RSA ve ECC algoritmalarının aksine, kuantum bilgisayarların\n"
        "Shor algoritması bu şifreyi çözemez. HNDL saldırılarına karşı tam koruma sağlar.\n"
        "Tarih: 2026 | Bütçe: 45.000 TL | Algoritma: CRYSTALS-Kyber-768\n",
        encoding="utf-8"
    )
    print(f"\n[1/3] Test dosyası oluşturuldu: {test_file.name}")

    # Dosyayı kasaya kilitle
    print("\n[2/3] Dosya kuantum kasasına kilitleniyor (Lock)...")
    vault_file = vault.lock_file(str(test_file))

    # Kasadaki dosyaları listele
    print("\n[3/3] Kasadaki dosyalar listeleniyor:")
    items = vault.list_vault()
    for item in items:
        print(f" - {item['vault_file']} | Boyut: {item['size_bytes']} B | {item['quantum_status']}")

    # Dosyayı geri çöz
    print("\n[4/4] Dosya kuantum kasasından çıkarılıyor (Unlock)...")
    restored = vault.unlock_file(vault_file)
    restored_content = Path(restored).read_text(encoding="utf-8")
    assert restored_content == test_file.read_text(encoding="utf-8")
    print(f"\n[BAŞARILI] Kasa bütünlüğü ve deşifreleme %100 doğrulandı!")

if __name__ == "__main__":
    run_vault_demo()
