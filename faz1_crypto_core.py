"""
Q-Shield FAZ 1: Şifreleme Çekirdeğinin İnşası ve Performans Karşılaştırma Testleri
(Core Cryptography & Benchmarking)

Bu modül:
1. CRYSTALS-Kyber-768, RSA-2048, RSA-4096 ve ECC (NIST P-256) algoritmalarını karşılaştırır.
2. Anahtar üretimi, şifreleme/kapsülleme ve deşifreleme gecikmelerini (latency) milisaniye bazında ölçer.
3. Anahtar ve şifreli veri boyutlarını (memory/bandwidth footprint) hesaplar.
4. Kuantum dayanıklılık durumunu (Shor algoritması tehdidi) raporlar.
5. Sonuçları benchmark_results.json dosyasına kaydeder.
"""

import os
import sys
import time
import json
from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from crypto_core import Kyber768, Dilithium3, HybridCipher

def benchmark_rsa_2048() -> Dict[str, Any]:
    # Keygen
    t0 = time.perf_counter()
    sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pk = sk.public_key()
    keygen_ms = (time.perf_counter() - t0) * 1000

    pk_bytes = pk.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sk_bytes = sk.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Encrypt (32 bayt simetrik anahtar)
    test_data = os.urandom(32)
    t0 = time.perf_counter()
    ciphertext = pk.encrypt(
        test_data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    enc_ms = (time.perf_counter() - t0) * 1000

    # Decrypt
    t0 = time.perf_counter()
    decrypted = sk.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    dec_ms = (time.perf_counter() - t0) * 1000
    assert decrypted == test_data

    return {
        "name": "RSA-2048 (Klasik)",
        "quantum_safe": False,
        "shor_vulnerable": True,
        "keygen_ms": round(keygen_ms, 2),
        "enc_ms": round(enc_ms, 2),
        "dec_ms": round(dec_ms, 2),
        "total_exchange_ms": round(enc_ms + dec_ms, 2),
        "pk_size_bytes": len(pk_bytes),
        "sk_size_bytes": len(sk_bytes),
        "ct_size_bytes": len(ciphertext),
        "security_bits": 112,
        "math_basis": "Tam Sayı Çarpanlara Ayırma (IFP)"
    }

def benchmark_rsa_4096() -> Dict[str, Any]:
    t0 = time.perf_counter()
    sk = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    pk = sk.public_key()
    keygen_ms = (time.perf_counter() - t0) * 1000

    pk_bytes = pk.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sk_bytes = sk.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    test_data = os.urandom(32)
    t0 = time.perf_counter()
    ciphertext = pk.encrypt(
        test_data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    enc_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    decrypted = sk.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    dec_ms = (time.perf_counter() - t0) * 1000
    assert decrypted == test_data

    return {
        "name": "RSA-4096 (Klasik Yüksek)",
        "quantum_safe": False,
        "shor_vulnerable": True,
        "keygen_ms": round(keygen_ms, 2),
        "enc_ms": round(enc_ms, 2),
        "dec_ms": round(dec_ms, 2),
        "total_exchange_ms": round(enc_ms + dec_ms, 2),
        "pk_size_bytes": len(pk_bytes),
        "sk_size_bytes": len(sk_bytes),
        "ct_size_bytes": len(ciphertext),
        "security_bits": 128,
        "math_basis": "Tam Sayı Çarpanlara Ayırma (IFP)"
    }

def benchmark_ecdh_p256() -> Dict[str, Any]:
    t0 = time.perf_counter()
    sk = ec.generate_private_key(ec.SECP256R1())
    pk = sk.public_key()
    keygen_ms = (time.perf_counter() - t0) * 1000

    pk_bytes = pk.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sk_bytes = sk.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Bob tarafı
    peer_sk = ec.generate_private_key(ec.SECP256R1())
    peer_pk = peer_sk.public_key()

    t0 = time.perf_counter()
    shared_key_1 = sk.exchange(ec.ECDH(), peer_pk)
    enc_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    shared_key_2 = peer_sk.exchange(ec.ECDH(), pk)
    dec_ms = (time.perf_counter() - t0) * 1000
    assert shared_key_1 == shared_key_2

    return {
        "name": "ECDH (NIST P-256)",
        "quantum_safe": False,
        "shor_vulnerable": True,
        "keygen_ms": round(keygen_ms, 2),
        "enc_ms": round(enc_ms, 2),
        "dec_ms": round(dec_ms, 2),
        "total_exchange_ms": round(enc_ms + dec_ms, 2),
        "pk_size_bytes": len(pk_bytes),
        "sk_size_bytes": len(sk_bytes),
        "ct_size_bytes": len(pk_bytes), # Karşılıklı açık anahtar iletimi
        "security_bits": 128,
        "math_basis": "Eliptik Eğri Ayrık Logaritması (ECDLP)"
    }

def benchmark_kyber_768() -> Dict[str, Any]:
    # Keygen
    t0 = time.perf_counter()
    pk, sk = Kyber768.keygen()
    keygen_ms = (time.perf_counter() - t0) * 1000

    # Encapsulate
    t0 = time.perf_counter()
    ct, ss_enc = Kyber768.encapsulate(pk)
    enc_ms = (time.perf_counter() - t0) * 1000

    # Decapsulate
    t0 = time.perf_counter()
    ss_dec = Kyber768.decapsulate(ct, sk)
    dec_ms = (time.perf_counter() - t0) * 1000
    assert ss_enc == ss_dec

    return {
        "name": "CRYSTALS-Kyber-768 (Q-Shield PQC)",
        "quantum_safe": True,
        "shor_vulnerable": False,
        "keygen_ms": round(keygen_ms, 2),
        "enc_ms": round(enc_ms, 2),
        "dec_ms": round(dec_ms, 2),
        "total_exchange_ms": round(enc_ms + dec_ms, 2),
        "pk_size_bytes": len(pk),
        "sk_size_bytes": len(sk),
        "ct_size_bytes": len(ct),
        "security_bits": 192, # NIST Güvenlik Seviyesi 3 (AES-192 eşdeğeri kuantum dayanıklı)
        "math_basis": "Kafes Tabanlı Modül-LWE (Module Learning with Errors)"
    }

def benchmark_dilithium_3() -> Dict[str, Any]:
    t0 = time.perf_counter()
    pk, sk = Dilithium3.keygen()
    keygen_ms = (time.perf_counter() - t0) * 1000

    msg = b"Kuantum Sonrasi Dijital Sertifika ve Kimlik Dogrulama"
    t0 = time.perf_counter()
    sig = Dilithium3.sign(msg, sk)
    sign_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    valid = Dilithium3.verify(msg, sig, pk)
    verify_ms = (time.perf_counter() - t0) * 1000
    assert valid

    return {
        "name": "CRYSTALS-Dilithium-3 (Q-Shield Dijital İmza)",
        "quantum_safe": True,
        "shor_vulnerable": False,
        "keygen_ms": round(keygen_ms, 2),
        "sign_ms": round(sign_ms, 2),
        "verify_ms": round(verify_ms, 2),
        "pk_size_bytes": len(pk),
        "sk_size_bytes": len(sk),
        "sig_size_bytes": len(sig),
        "security_bits": 192, # NIST Seviye 3
        "math_basis": "Kafes Tabanlı Modül-SIS (Short Integer Solution)"
    }

def run_benchmarks():
    print("=" * 80)
    print("      Q-SHIELD PQC: HİBRİT KRİPTOGRAFİ PERFORMANS & GECİKME TESTLERİ")
    print("      NIST Kuantum Sonrası Standartları & Klasik Standartlar Karşılaştırması")
    print("=" * 80)

    print("\n[1/5] RSA-2048 testi çalıştırılıyor...")
    res_rsa2048 = benchmark_rsa_2048()

    print("[2/5] RSA-4096 testi çalıştırılıyor...")
    res_rsa4096 = benchmark_rsa_4096()

    print("[3/5] ECDH (NIST P-256) testi çalıştırılıyor...")
    res_ecdh = benchmark_ecdh_p256()

    print("[4/5] CRYSTALS-Kyber-768 (Q-Shield KEM) testi çalıştırılıyor...")
    res_kyber = benchmark_kyber_768()

    print("[5/5] CRYSTALS-Dilithium-3 (Q-Shield Dijital İmza) testi çalıştırılıyor...")
    res_dilithium = benchmark_dilithium_3()

    all_kem_results = [res_rsa2048, res_rsa4096, res_ecdh, res_kyber]

    print("\n" + "-" * 105)
    print(f"{'Algoritma':<30} | {'Kuantum Güvenli?':<16} | {'Keygen (ms)':<11} | {'Enc/KEM (ms)':<12} | {'Dec/KEM (ms)':<12} | {'PK Boyut':<9} | {'CT Boyut':<9}")
    print("-" * 105)
    for r in all_kem_results:
        qs_str = "EVET (Dirençli)" if r["quantum_safe"] else "HAYIR (Kırılır)"
        print(f"{r['name']:<30} | {qs_str:<16} | {r['keygen_ms']:<11} | {r['enc_ms']:<12} | {r['dec_ms']:<12} | {r['pk_size_bytes']:<6} B | {r['ct_size_bytes']:<6} B")
    print("-" * 105)

    print("\n" + "=" * 80)
    print("DİJİTAL İMZA ALGORİTMASI ANALİZİ:")
    print(f"Algoritma: {res_dilithium['name']}")
    print(f"Kuantum Güvenlik: {'Dirençli' if res_dilithium['quantum_safe'] else 'Savunmasız'}")
    print(f"İmzalama Süresi: {res_dilithium['sign_ms']} ms | Doğrulama: {res_dilithium['verify_ms']} ms")
    print(f"İmza Boyutu: {res_dilithium['sig_size_bytes']} bayt | Açık Anahtar: {res_dilithium['pk_size_bytes']} bayt")
    print("=" * 80)

    # JSON dosyasına kaydet
    output_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "kem_benchmarks": all_kem_results,
        "signature_benchmark": res_dilithium,
        "summary": {
            "pqc_kem": "CRYSTALS-Kyber-768",
            "pqc_signature": "CRYSTALS-Dilithium-3",
            "symmetric_cipher": "AES-256-GCM",
            "status": "PASSED"
        }
    }

    out_file = "benchmark_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    print(f"\n[OK] Tüm performans test sonuçları '{out_file}' dosyasına başarıyla kaydedildi.")

if __name__ == "__main__":
    run_benchmarks()
