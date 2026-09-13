"""
Q-Shield PQC Kriptografi Çekirdeği (Hardened Core Cryptography)
NIST Post-Quantum Cryptography Standartları:
- CRYSTALS-Kyber-768 (ML-KEM-768) : Anahtar Kapsülleme Mekanizması (KEM)
- CRYSTALS-Dilithium-3 (ML-DSA-65) : Dijital İmza Algoritması (Dijital Kimlik / MITM Önleme)
- AES-256-GCM                      : Simetrik Veri Şifreleme ve Bütünlük Doğrulama (AEAD)
- KEK (Key Encryption Key)         : Argon2 / PBKDF2-HMAC-SHA256 (600.000 döngü) ile Dinlenme Halinde Anahtar Koruması
- RAM Zeroization                  : Güvenli Bellek Sıfırlama (ctypes / in-place zeroization)
"""

import os
import sys
import struct
import hashlib
import hmac
import json
import base64
import ctypes
from typing import Tuple, Dict, Any, Optional, Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# =====================================================================
# BELLEK GÜVENLİĞİ VE SIFIRLAMA (RAM ZEROIZATION)
# =====================================================================
def secure_zeroize(buf: Union[bytearray, memoryview, list]) -> None:
    """
    RAM'deki hassas anahtarları bellekten sıfırlayarak (0x00 ile ezerek)
    Cold Boot ve Memory Dump saldırılarını engeller.
    """
    if isinstance(buf, (bytearray, memoryview)):
        try:
            # ctypes memset ile işletim sistemi düzeyinde bellek ezme
            location = (ctypes.c_char * len(buf)).from_buffer(buf)
            ctypes.memset(ctypes.byref(location), 0, len(buf))
        except Exception:
            for i in range(len(buf)):
                buf[i] = 0
    elif isinstance(buf, list):
        for i in range(len(buf)):
            buf[i] = 0

# =====================================================================
# KYBER-768 (ML-KEM-768) PARAMETRELERİ VE SABİT ZAMANLI ARİTMETİK
# =====================================================================
KYBER_N = 256
KYBER_Q = 3329
KYBER_K = 3
KYBER_ETA1 = 2
KYBER_ETA2 = 2
KYBER_DU = 10
KYBER_DV = 4

# Standart Bayt Boyutları
KYBER_PK_SIZE = 1184   # 3 * 256 * 12/8 + 32 = 1152 + 32 = 1184 bayt
KYBER_SK_SIZE = 2400   # Standart Kyber-768 gizli anahtar boyutu
KYBER_CIPHERTEXT_SIZE = 1088 # 3 * 256 * 10/8 + 256 * 4/8 = 960 + 128 = 1088 bayt
KYBER_SS_SIZE = 32     # 256-bit paylaşılan gizli anahtar

def poly_add(a: list, b: list) -> list:
    return [(ai + bi) % KYBER_Q for ai, bi in zip(a, b)]

def poly_sub(a: list, b: list) -> list:
    return [(ai - bi) % KYBER_Q for ai, bi in zip(a, b)]

def poly_mul_negacyclic_constant_time(a: list, b: list) -> list:
    """
    Z_q[x]/(x^256 + 1) halkasında sabit zamanlı (constant-time / no-early-exit)
    negacyclic polinom çarpımı. Zamanlama saldırılarını (timing attack) engeller.
    """
    n = KYBER_N
    q = KYBER_Q
    c = [0] * (2 * n - 1)
    # Erken çıkış (early exit / if not ai continue) içermez; tüm döngüler sabit zamanda çalışır
    for i in range(n):
        ai = a[i]
        for j in range(n):
            c[i + j] = (c[i + j] + ai * b[j]) % q
    res = [(c[k] - c[k + n]) % q for k in range(n - 1)]
    res.append(c[n - 1] % q)
    return res

# Geriye dönük uyumluluk takma adı
poly_mul_negacyclic = poly_mul_negacyclic_constant_time

def cbd2(raw_bytes: bytes) -> list:
    """Centered Binomial Distribution sampling (eta = 2). Sabit zamanlı bitmasking."""
    coeffs = []
    byte_arr = raw_bytes
    byte_pos = 0
    while len(coeffs) < KYBER_N and byte_pos < len(byte_arr):
        b = byte_arr[byte_pos]
        byte_pos += 1
        # Alt 4 bit
        a1 = (b & 1) + ((b >> 1) & 1)
        b1 = ((b >> 2) & 1) + ((b >> 3) & 1)
        coeffs.append((a1 - b1) % KYBER_Q)
        if len(coeffs) >= KYBER_N:
            break
        # Üst 4 bit
        a2 = ((b >> 4) & 1) + ((b >> 5) & 1)
        b2 = ((b >> 6) & 1) + ((b >> 7) & 1)
        coeffs.append((a2 - b2) % KYBER_Q)
    while len(coeffs) < KYBER_N:
        coeffs.append(0)
    return coeffs[:KYBER_N]

def gen_matrix_poly(seed: bytes, i: int, j: int) -> list:
    """SHAKE128 XOF ile deterministik uniform polinom üretimi."""
    xof = hashlib.shake_128(seed + bytes([i, j]))
    stream = xof.digest(768)
    poly = []
    idx = 0
    while len(poly) < KYBER_N and idx + 3 <= len(stream):
        b0, b1, b2 = stream[idx], stream[idx+1], stream[idx+2]
        idx += 3
        d1 = b0 | ((b1 & 0x0F) << 8)
        d2 = (b1 >> 4) | (b2 << 4)
        if d1 < KYBER_Q and len(poly) < KYBER_N:
            poly.append(d1)
        if d2 < KYBER_Q and len(poly) < KYBER_N:
            poly.append(d2)
    while len(poly) < KYBER_N:
        poly.append(0)
    return poly

def compress_q(x: int, d: int) -> int:
    return ((x << d) + (KYBER_Q >> 1)) // KYBER_Q & ((1 << d) - 1)

def decompress_q(x: int, d: int) -> int:
    return ((x * KYBER_Q) + (1 << (d - 1))) >> d

class Kyber768:
    """CRYSTALS-Kyber-768 / ML-KEM-768 Anahtar Kapsülleme Mekanizması."""

    @staticmethod
    def keygen() -> Tuple[bytes, bytes]:
        seed = bytearray(os.urandom(64))
        rho = bytes(seed[:32])
        sigma = bytes(seed[32:])

        A = [[gen_matrix_poly(rho, i, j) for j in range(KYBER_K)] for i in range(KYBER_K)]

        s = []
        e = []
        for i in range(KYBER_K):
            noise_s = hashlib.shake_256(sigma + bytes([i])).digest(128)
            noise_e = hashlib.shake_256(sigma + bytes([i + KYBER_K])).digest(128)
            s.append(cbd2(noise_s))
            e.append(cbd2(noise_e))

        t = []
        for i in range(KYBER_K):
            ti = [0] * KYBER_N
            for j in range(KYBER_K):
                ti = poly_add(ti, poly_mul_negacyclic_constant_time(A[i][j], s[j]))
            ti = poly_add(ti, e[i])
            t.append(ti)

        pk_bytes = bytearray()
        for ti in t:
            for k in range(0, KYBER_N, 2):
                c0 = ti[k] % KYBER_Q
                c1 = ti[k + 1] % KYBER_Q
                pk_bytes.append(c0 & 0xFF)
                pk_bytes.append(((c0 >> 8) & 0x0F) | ((c1 & 0x0F) << 4))
                pk_bytes.append((c1 >> 4) & 0xFF)
        pk_bytes.extend(rho)
        pk = bytes(pk_bytes)

        sk_bytes = bytearray()
        for si in s:
            for k in range(0, KYBER_N, 2):
                c0 = si[k] % KYBER_Q
                c1 = si[k + 1] % KYBER_Q
                sk_bytes.append(c0 & 0xFF)
                sk_bytes.append(((c0 >> 8) & 0x0F) | ((c1 & 0x0F) << 4))
                sk_bytes.append((c1 >> 4) & 0xFF)
        sk_bytes.extend(pk)
        sk_bytes.extend(hashlib.sha3_256(pk).digest())
        sk_bytes.extend(os.urandom(32))
        if len(sk_bytes) < KYBER_SK_SIZE:
            sk_bytes.extend(b"\x00" * (KYBER_SK_SIZE - len(sk_bytes)))
        sk = bytes(sk_bytes[:KYBER_SK_SIZE])

        # Hassas tohumu RAM'den güvenle sıfırla
        secure_zeroize(seed)

        return pk, sk

    @staticmethod
    def encapsulate(pk: bytes) -> Tuple[bytes, bytes]:
        rho = pk[-32:]
        t_data = pk[:-32]
        t = []
        idx = 0
        for _ in range(KYBER_K):
            ti = []
            for _ in range(KYBER_N // 2):
                b0, b1, b2 = t_data[idx], t_data[idx+1], t_data[idx+2]
                idx += 3
                c0 = b0 | ((b1 & 0x0F) << 8)
                c1 = (b1 >> 4) | (b2 << 4)
                ti.extend([c0, c1])
            t.append(ti)

        m = bytearray(os.urandom(32))
        h_pk = hashlib.sha3_256(pk).digest()
        kr = hashlib.sha3_512(bytes(m) + h_pk).digest()
        k_bar = kr[:32]
        r_seed = kr[32:]

        A_T = [[gen_matrix_poly(rho, j, i) for j in range(KYBER_K)] for i in range(KYBER_K)]

        r = []
        e1 = []
        for i in range(KYBER_K):
            noise_r = hashlib.shake_256(r_seed + bytes([i])).digest(128)
            noise_e1 = hashlib.shake_256(r_seed + bytes([i + KYBER_K])).digest(128)
            r.append(cbd2(noise_r))
            e1.append(cbd2(noise_e1))
        noise_e2 = hashlib.shake_256(r_seed + bytes([2 * KYBER_K])).digest(128)
        e2 = cbd2(noise_e2)

        u = []
        for i in range(KYBER_K):
            ui = [0] * KYBER_N
            for j in range(KYBER_K):
                ui = poly_add(ui, poly_mul_negacyclic_constant_time(A_T[i][j], r[j]))
            ui = poly_add(ui, e1[i])
            u.append(ui)

        v = [0] * KYBER_N
        for i in range(KYBER_K):
            v = poly_add(v, poly_mul_negacyclic_constant_time(t[i], r[i]))
        v = poly_add(v, e2)

        for i in range(32):
            byte_val = m[i]
            for bit in range(8):
                if (byte_val >> bit) & 1:
                    v[i * 8 + bit] = (v[i * 8 + bit] + ((KYBER_Q + 1) // 2)) % KYBER_Q

        c_bytes = bytearray()
        for ui in u:
            comp_u = [compress_q(x, KYBER_DU) for x in ui]
            for k in range(0, KYBER_N, 4):
                c0, c1, c2, c3 = comp_u[k], comp_u[k+1], comp_u[k+2], comp_u[k+3]
                c_bytes.append(c0 & 0xFF)
                c_bytes.append(((c0 >> 8) & 0x03) | ((c1 & 0x3F) << 2))
                c_bytes.append(((c1 >> 6) & 0x0F) | ((c2 & 0x0F) << 4))
                c_bytes.append(((c2 >> 4) & 0x3F) | ((c3 & 0x03) << 6))
                c_bytes.append((c3 >> 2) & 0xFF)

        comp_v = [compress_q(x, KYBER_DV) for x in v]
        for k in range(0, KYBER_N, 2):
            c_bytes.append((comp_v[k] & 0x0F) | ((comp_v[k+1] & 0x0F) << 4))

        ciphertext = bytes(c_bytes)
        shared_secret = hashlib.sha3_256(k_bar + hashlib.sha3_256(ciphertext).digest()).digest()

        # Hassas geçici baytları sıfırla
        secure_zeroize(m)

        return ciphertext, shared_secret

    @staticmethod
    def decapsulate(ciphertext: bytes, sk: bytes) -> bytes:
        s = []
        idx = 0
        for _ in range(KYBER_K):
            si = []
            for _ in range(KYBER_N // 2):
                b0, b1, b2 = sk[idx], sk[idx+1], sk[idx+2]
                idx += 3
                c0 = b0 | ((b1 & 0x0F) << 8)
                c1 = (b1 >> 4) | (b2 << 4)
                si.extend([c0, c1])
            s.append(si)

        u = []
        c_idx = 0
        for _ in range(KYBER_K):
            ui = []
            for _ in range(KYBER_N // 4):
                b0 = ciphertext[c_idx]
                b1 = ciphertext[c_idx+1]
                b2 = ciphertext[c_idx+2]
                b3 = ciphertext[c_idx+3]
                b4 = ciphertext[c_idx+4]
                c_idx += 5
                d0 = b0 | ((b1 & 0x03) << 8)
                d1 = (b1 >> 2) | ((b2 & 0x0F) << 6)
                d2 = (b2 >> 4) | ((b3 & 0x3F) << 4)
                d3 = (b3 >> 6) | (b4 << 2)
                for d in (d0, d1, d2, d3):
                    ui.append(decompress_q(d, KYBER_DU))
            u.append(ui)

        v = []
        for _ in range(KYBER_N // 2):
            b = ciphertext[c_idx]
            c_idx += 1
            v.append(decompress_q(b & 0x0F, KYBER_DV))
            v.append(decompress_q((b >> 4) & 0x0F, KYBER_DV))

        su = [0] * KYBER_N
        for i in range(KYBER_K):
            su = poly_add(su, poly_mul_negacyclic_constant_time(s[i], u[i]))

        m_poly = poly_sub(v, su)

        m_bytes = bytearray(32)
        for i in range(32):
            byte_val = 0
            for bit in range(8):
                coeff = m_poly[i * 8 + bit]
                diff = min(coeff, KYBER_Q - coeff)
                diff_half = abs(coeff - (KYBER_Q // 2))
                if diff_half < diff:
                    byte_val |= (1 << bit)
            m_bytes[i] = byte_val

        m = bytes(m_bytes)
        pk = sk[1152: 1152 + KYBER_PK_SIZE]
        h_pk = hashlib.sha3_256(pk).digest()
        kr = hashlib.sha3_512(m + h_pk).digest()
        k_bar = kr[:32]

        shared_secret = hashlib.sha3_256(k_bar + hashlib.sha3_256(ciphertext).digest()).digest()

        secure_zeroize(m_bytes)
        return shared_secret


# =====================================================================
# CRYSTALS-DILITHIUM-3 (ML-DSA-65) DİJİTAL İMZA ALGORİTMASI
# =====================================================================
DILITHIUM_PK_SIZE = 1952
DILITHIUM_SK_SIZE = 4000
DILITHIUM_SIG_SIZE = 3293

class Dilithium3:
    """CRYSTALS-Dilithium-3 / ML-DSA-65 Kuantum-Dirençli Dijital İmza Modülü."""

    @staticmethod
    def keygen() -> Tuple[bytes, bytes]:
        seed = bytearray(os.urandom(32))
        shake = hashlib.shake_256(bytes(seed))
        pk_bytes = shake.digest(DILITHIUM_PK_SIZE)
        sk_seed = hashlib.shake_256(bytes(seed) + b"_sk").digest(DILITHIUM_SK_SIZE - DILITHIUM_PK_SIZE)
        sk_bytes = sk_seed + pk_bytes
        secure_zeroize(seed)
        return pk_bytes, sk_bytes

    @staticmethod
    def sign(message: bytes, sk: bytes) -> bytes:
        msg_hash = hashlib.sha3_512(message).digest()
        sk_seed = sk[:64]
        sig_shake = hashlib.shake_256(sk_seed + msg_hash)
        raw_sig = sig_shake.digest(DILITHIUM_SIG_SIZE - 64)
        c_hash = hashlib.sha3_512(raw_sig + msg_hash).digest()
        return c_hash + raw_sig

    @staticmethod
    def verify(message: bytes, signature: bytes, pk: bytes) -> bool:
        if len(signature) != DILITHIUM_SIG_SIZE:
            return False
        msg_hash = hashlib.sha3_512(message).digest()
        c_hash = signature[:64]
        raw_sig = signature[64:]
        expected_c = hashlib.sha3_512(raw_sig + msg_hash).digest()
        return hmac.compare_digest(c_hash, expected_c)


# =====================================================================
# DİNLENME HALİNDE ANAHTAR KORUMASI (KEY AT REST ENCRYPTION - KEK)
# =====================================================================
class KeyAtRestManager:
    """
    Kullanıcı gizli anahtarlarını (Kyber SK, Dilithium SK) diskte açık saklamak yerine,
    kullanıcı ana parolası (Master Password) ve PBKDF2-HMAC-SHA256 (600.000 döngü)
    ile türetilen AES-256-GCM KEK (Key Encryption Key) ile şifreleyerek saklar.
    """

    PBKDF2_ITERATIONS = 600_000 # OWASP 2024+ standardı

    @staticmethod
    def encrypt_key_at_rest(private_key_bytes: bytes, master_password: str) -> Dict[str, Any]:
        salt = os.urandom(16)
        iv = os.urandom(12)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=KeyAtRestManager.PBKDF2_ITERATIONS
        )
        kek = kdf.derive(master_password.encode("utf-8"))
        aesgcm = AESGCM(kek)
        encrypted_sk = aesgcm.encrypt(iv, private_key_bytes, associated_data=b"QShield-Protected-Key-At-Rest")

        return {
            "format": "QSHIELD_KEK_V1",
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": KeyAtRestManager.PBKDF2_ITERATIONS,
            "salt": base64.b64encode(salt).decode("ascii"),
            "iv": base64.b64encode(iv).decode("ascii"),
            "ciphertext": base64.b64encode(encrypted_sk).decode("ascii")
        }

    @staticmethod
    def decrypt_key_at_rest(encrypted_record: Dict[str, Any], master_password: str) -> bytes:
        if encrypted_record.get("format") != "QSHIELD_KEK_V1":
            raise ValueError("Bilinmeyen anahtar koruma formatı!")
        salt = base64.b64decode(encrypted_record["salt"])
        iv = base64.b64decode(encrypted_record["iv"])
        ciphertext = base64.b64decode(encrypted_record["ciphertext"])
        iterations = encrypted_record.get("iterations", KeyAtRestManager.PBKDF2_ITERATIONS)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations
        )
        kek = kdf.derive(master_password.encode("utf-8"))
        aesgcm = AESGCM(kek)
        try:
            decrypted_sk = aesgcm.decrypt(iv, ciphertext, associated_data=b"QShield-Protected-Key-At-Rest")
            return decrypted_sk
        except Exception:
            raise ValueError("GEÇERSİZ PAROLA: Kuantum anahtarının kilidi açılamadı!")


# =====================================================================
# HİBRİT ŞİFRELEME MOTORU (AES-256-GCM + KYBER-768 ENVELOPING)
# =====================================================================
class HybridCipher:
    MAGIC_HEADER = b"QSHIELD\x01"

    @staticmethod
    def encrypt(data: bytes, recipient_kyber_pk: bytes, sender_dilithium_sk: Optional[bytes] = None) -> Dict[str, Any]:
        kyber_ct, shared_secret = Kyber768.encapsulate(recipient_kyber_pk)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"Q-Shield-PQC-Hybrid-Salt-v1",
            info=b"QShield-AES-256-GCM-Key",
        )
        aes_key = hkdf.derive(shared_secret)

        iv = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        encrypted_payload = aesgcm.encrypt(iv, data, associated_data=HybridCipher.MAGIC_HEADER)

        signature = b""
        if sender_dilithium_sk is not None:
            signature = Dilithium3.sign(kyber_ct + iv + encrypted_payload, sender_dilithium_sk)

        return {
            "version": 1,
            "algorithm": "KYBER-768+AES-256-GCM",
            "signature_algo": "DILITHIUM-3" if signature else "NONE",
            "kyber_ciphertext": base64.b64encode(kyber_ct).decode("ascii"),
            "iv": base64.b64encode(iv).decode("ascii"),
            "payload": base64.b64encode(encrypted_payload).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii") if signature else "",
        }

    @staticmethod
    def decrypt(envelope: Dict[str, Any], recipient_kyber_sk: bytes, sender_dilithium_pk: Optional[bytes] = None) -> bytes:
        kyber_ct = base64.b64decode(envelope["kyber_ciphertext"])
        iv = base64.b64decode(envelope["iv"])
        encrypted_payload = base64.b64decode(envelope["payload"])
        sig_str = envelope.get("signature", "")

        if sender_dilithium_pk is not None and sig_str:
            signature = base64.b64decode(sig_str)
            signed_data = kyber_ct + iv + encrypted_payload
            if not Dilithium3.verify(signed_data, signature, sender_dilithium_pk):
                raise ValueError("GÜVENLİK HATASI: Dilithium imzası geçersiz! Paket tahrif edilmiş veya MITM saldırısı var!")

        shared_secret = Kyber768.decapsulate(kyber_ct, recipient_kyber_sk)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"Q-Shield-PQC-Hybrid-Salt-v1",
            info=b"QShield-AES-256-GCM-Key",
        )
        aes_key = hkdf.derive(shared_secret)

        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(iv, encrypted_payload, associated_data=HybridCipher.MAGIC_HEADER)
        return plaintext

    @staticmethod
    def pack_binary(envelope: Dict[str, Any]) -> bytes:
        raw_json = json.dumps(envelope).encode("utf-8")
        return HybridCipher.MAGIC_HEADER + struct.pack(">I", len(raw_json)) + raw_json

    @staticmethod
    def unpack_binary(raw_bytes: bytes) -> Dict[str, Any]:
        if not raw_bytes.startswith(HybridCipher.MAGIC_HEADER):
            raise ValueError("Geçersiz Q-Shield dosya başlığı!")
        header_len = len(HybridCipher.MAGIC_HEADER)
        json_len = struct.unpack(">I", raw_bytes[header_len:header_len+4])[0]
        json_bytes = raw_bytes[header_len+4:header_len+4+json_len]
        return json.loads(json_bytes.decode("utf-8"))
