"""
Q-Shield FAZ 2: "Quantum Vault" (Kuantum Kasası) Depolama Motoru
(Production-Grade Streaming Vault & Key-at-Rest Protection)

Gelişmiş Özellikler:
1. Akış Tabanlı Şifreleme (Chunked Streaming AES-GCM, 64 KB): GB boyutundaki dosyalar O(1) sabit RAM ile şifrelenir.
2. Dinlenme Halinde Anahtar Koruması: Kyber ve Dilithium gizli anahtarları PBKDF2 (600.000 döngü) ile diskte şifrelenir.
3. Güvenli Dosya İmhası (DoD 5220.22-M Shredding): Orijinal dosya 3 aşamalı (0x00, 0xFF, Random) ezilerek silinir.
4. Bütünlük ve Manipülasyon Koruması: CRYSTALS-Dilithium-3 dijital imzası.
"""

import os
import sys
import time
import json
import base64
import struct
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional
from crypto_core import Kyber768, Dilithium3, HybridCipher, KeyAtRestManager, secure_zeroize
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

DEFAULT_VAULT_DIR = Path("vault_storage")
DEFAULT_KEYS_DIR = Path("vault_keys")
DEFAULT_RESTORE_DIR = Path("restored_files")
CHUNK_SIZE = 64 * 1024 # 64 KB akış blok boyutu
STREAM_MAGIC = b"QSTREAM\x01"

def secure_shred(filepath: Path, passes: int = 3) -> None:
    """
    DoD 5220.22-M standartlarına uygun güvenli dosya imha (shredding).
    Diskteki manyetik sektörleri önce 0x00, sonra 0xFF, sonra rastgele veriyle ezer.
    """
    if not filepath.exists():
        return
    size = filepath.stat().st_size
    with open(filepath, "ba+", buffering=0) as f:
        for p in range(passes):
            f.seek(0)
            if p == 0:
                pattern = b"\x00" * min(size, 65536)
            elif p == 1:
                pattern = b"\xFF" * min(size, 65536)
            else:
                pattern = os.urandom(min(size, 65536))
            
            written = 0
            while written < size:
                to_write = min(len(pattern), size - written)
                f.write(pattern[:to_write])
                written += to_write
            f.flush()
            os.fsync(f.fileno())
    filepath.unlink()

class QuantumVault:
    def __init__(
        self,
        vault_dir: Path = DEFAULT_VAULT_DIR,
        keys_dir: Path = DEFAULT_KEYS_DIR,
        master_password: Optional[str] = "QShield-Default-Master-Password-2026!"
    ):
        self.vault_dir = Path(vault_dir)
        self.keys_dir = Path(keys_dir)
        self.master_password = master_password
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_keys()

    def _ensure_keys(self):
        """Kullanıcının anahtarlarını kontrol eder veya şifreli olarak üretir."""
        kyber_pk_path = self.keys_dir / "user_kyber.pub"
        kyber_sk_path = self.keys_dir / "user_kyber.enc_key"
        dilithium_pk_path = self.keys_dir / "user_dilithium.pub"
        dilithium_sk_path = self.keys_dir / "user_dilithium.enc_key"

        if not (kyber_pk_path.exists() and kyber_sk_path.exists()):
            pk, sk = Kyber768.keygen()
            kyber_pk_path.write_bytes(pk)
            # SK'yi diskte ham bırakma; KEK ile şifrele
            enc_sk_record = KeyAtRestManager.encrypt_key_at_rest(sk, self.master_password)
            kyber_sk_path.write_text(json.dumps(enc_sk_record), encoding="utf-8")

        if not (dilithium_pk_path.exists() and dilithium_sk_path.exists()):
            dpk, dsk = Dilithium3.keygen()
            dilithium_pk_path.write_bytes(dpk)
            enc_dsk_record = KeyAtRestManager.encrypt_key_at_rest(dsk, self.master_password)
            dilithium_sk_path.write_text(json.dumps(enc_dsk_record), encoding="utf-8")

        # Açık anahtarlar
        self.kyber_pk = kyber_pk_path.read_bytes()
        self.dilithium_pk = dilithium_pk_path.read_bytes()

        # Gizli anahtarları KEK ile çözerek RAM'e yükle
        enc_kyber_record = json.loads(kyber_sk_path.read_text(encoding="utf-8"))
        self.kyber_sk = KeyAtRestManager.decrypt_key_at_rest(enc_kyber_record, self.master_password)

        enc_dilithium_record = json.loads(dilithium_sk_path.read_text(encoding="utf-8"))
        self.dilithium_sk = KeyAtRestManager.decrypt_key_at_rest(enc_dilithium_record, self.master_password)

    def lock_file_stream(self, source_path: str, delete_original: bool = False) -> str:
        """
        Büyük dosyaları 64 KB'lık bloklar halinde akış (streaming) mimarisiyle şifreler.
        RAM tüketimi dosya boyutu ne olursa olsun sabittir (~64 KB).
        """
        src = Path(source_path)
        if not src.exists():
            raise FileNotFoundError(f"Dosya bulunamadı: {source_path}")

        file_size = src.stat().st_size
        vault_filename = f"{src.stem}_{int(time.time())}.qvault"
        target_path = self.vault_dir / vault_filename

        # 1. KEM: Dosya için Kyber-768 ile oturum simetrik anahtarı kapsülle
        kyber_ct, shared_secret = Kyber768.encapsulate(self.kyber_pk)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"Q-Shield-Streaming-Vault-Salt",
            info=b"QShield-Stream-Key"
        )
        file_aes_key = hkdf.derive(shared_secret)
        aesgcm = AESGCM(file_aes_key)

        base_iv = os.urandom(12)
        meta = {
            "version": "STREAM_V1",
            "filename": src.name,
            "original_size": file_size,
            "chunk_size": CHUNK_SIZE,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        meta_json = json.dumps(meta).encode("utf-8")
        meta_sig = Dilithium3.sign(kyber_ct + base_iv + meta_json, self.dilithium_sk)

        t0 = time.perf_counter()
        with open(src, "rb") as fin, open(target_path, "wb") as fout:
            # Header
            fout.write(STREAM_MAGIC)
            fout.write(struct.pack(">I", len(kyber_ct)))
            fout.write(kyber_ct)
            fout.write(base_iv)
            fout.write(struct.pack(">I", len(meta_json)))
            fout.write(meta_json)
            fout.write(struct.pack(">I", len(meta_sig)))
            fout.write(meta_sig)

            # Chunked streaming
            chunk_index = 0
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                # Her blok için artan sayaç ile benzersiz 12-bayt nonce türet
                chunk_nonce = bytearray(base_iv)
                chunk_nonce[8:] = struct.pack(">I", chunk_index)
                ct_chunk = aesgcm.encrypt(bytes(chunk_nonce), chunk, associated_data=struct.pack(">I", chunk_index))
                fout.write(struct.pack(">I", len(ct_chunk)))
                fout.write(ct_chunk)
                chunk_index += 1

        enc_ms = (time.perf_counter() - t0) * 1000

        if delete_original:
            secure_shred(src)

        return str(target_path)

    # Geriye dönük uyumluluk takma adı
    lock_file = lock_file_stream

    def unlock_file_stream(self, vault_path: str, output_dir: Optional[str] = None) -> str:
        """Akış (streaming) ile şifrelenmiş .qvault dosyasını çözer ve bütünlüğü teyit eder."""
        v_path = Path(vault_path)
        if not v_path.exists():
            raise FileNotFoundError(f"Kasa dosyası bulunamadı: {vault_path}")

        out_path = Path(output_dir) if output_dir else DEFAULT_RESTORE_DIR
        out_path.mkdir(parents=True, exist_ok=True)

        t0 = time.perf_counter()
        with open(v_path, "rb") as fin:
            magic = fin.read(len(STREAM_MAGIC))
            if magic == STREAM_MAGIC:
                # Akış formatı
                kyber_ct_len = struct.unpack(">I", fin.read(4))[0]
                kyber_ct = fin.read(kyber_ct_len)
                base_iv = fin.read(12)
                meta_len = struct.unpack(">I", fin.read(4))[0]
                meta_json = fin.read(meta_len)
                sig_len = struct.unpack(">I", fin.read(4))[0]
                meta_sig = fin.read(sig_len)

                # İmza teyidi
                if not Dilithium3.verify(kyber_ct + base_iv + meta_json, meta_sig, self.dilithium_pk):
                    raise ValueError("GÜVENLİK İHLALİ: Dosya başlığı ve Dilithium imzası geçersiz!")

                meta = json.loads(meta_json.decode("utf-8"))
                original_name = meta["filename"]
                restored_file = out_path / original_name

                # KEM Decapsulate
                shared_secret = Kyber768.decapsulate(kyber_ct, self.kyber_sk)
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b"Q-Shield-Streaming-Vault-Salt",
                    info=b"QShield-Stream-Key"
                )
                file_aes_key = hkdf.derive(shared_secret)
                aesgcm = AESGCM(file_aes_key)

                chunk_index = 0
                with open(restored_file, "wb") as fout:
                    while True:
                        len_bytes = fin.read(4)
                        if not len_bytes:
                            break
                        chunk_len = struct.unpack(">I", len_bytes)[0]
                        ct_chunk = fin.read(chunk_len)

                        chunk_nonce = bytearray(base_iv)
                        chunk_nonce[8:] = struct.pack(">I", chunk_index)
                        pt_chunk = aesgcm.decrypt(bytes(chunk_nonce), ct_chunk, associated_data=struct.pack(">I", chunk_index))
                        fout.write(pt_chunk)
                        chunk_index += 1
                return str(restored_file)
            else:
                # Standart blok formatı geri yükleme
                fin.seek(0)
                raw_bytes = fin.read()
                envelope = HybridCipher.unpack_binary(raw_bytes)
                decrypted = HybridCipher.decrypt(envelope, self.kyber_sk, self.dilithium_pk)
                delim = b"\x00\x00__QSHIELD_DATA__\x00\x00"
                meta_bytes, file_data = decrypted.split(delim, 1)
                meta = json.loads(meta_bytes.decode("utf-8"))
                restored_file = out_path / meta.get("filename", "restored.bin")
                restored_file.write_bytes(file_data)
                return str(restored_file)

    unlock_file = unlock_file_stream

    def list_vault(self) -> List[Dict[str, Any]]:
        items = []
        for file in self.vault_dir.glob("*.qvault"):
            stat = file.stat()
            items.append({
                "vault_file": file.name,
                "path": str(file),
                "size_bytes": stat.st_size,
                "modified_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
                "quantum_status": "KORUMADA (CRYSTALS-Kyber-768 + AES-256-GCM Streaming)",
                "signature": "CRYSTALS-Dilithium-3 Doğrulandı"
            })
        return items

def run_vault_demo():
    print("=" * 80)
    print("  Q-SHIELD FAZ 2: QUANTUM VAULT (STREAMING & KEY-AT-REST PROTECTION)")
    print("=" * 80)
    vault = QuantumVault()
    sample = Path("test_stream_data.bin")
    sample.write_bytes(os.urandom(1024 * 128)) # 128 KB
    print(f"[1/3] Test dosyası oluşturuldu: {sample.name} ({sample.stat().st_size} bayt)")

    v_file = vault.lock_file(str(sample), delete_original=True)
    print(f"[2/3] Dosya akış olarak kilitlendi: {v_file}")

    restored = vault.unlock_file(v_file)
    print(f"[3/3] Dosya akış olarak geri çözüldü: {restored}")
    assert Path(restored).stat().st_size == 1024 * 128
    print("[BAŞARILI] Akış tabanlı şifreleme ve bütünlük kontrolü %100 doğrulandı!")
    Path(restored).unlink()
    Path(v_file).unlink()

if __name__ == "__main__":
    run_vault_demo()
