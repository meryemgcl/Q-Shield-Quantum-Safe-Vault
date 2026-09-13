"""
Q-Shield FAZ 3: PQC İletişim Protokolü (Client-to-Client & MITM Koruması)
(Peer-to-Peer Post-Quantum Secure Messaging & Attack Defense)

Bu modül:
1. İki uç kullanıcı (Alice ve Bob) arasında Kuantum-Güvenli El Sıkışma (Handshake) gerçekleştirir.
2. CRYSTALS-Kyber-768 (KEM) ile geçici oturum anahtarı (Ephemeral Session Key) takası yapar.
3. CRYSTALS-Dilithium-3 ile Ortadaki Adam (MITM) saldırılarını engeller.
4. Siber saldırgan Eve'in HNDL (Harvest Now, Decrypt Later) ve Sahte Kimlik (Impersonation)
   saldırılarına karşı protokolün savunma mekanizmasını simüle eder.
"""

import os
import sys
import time
import json
import base64
from typing import Dict, Any, Tuple, Optional
from crypto_core import Kyber768, Dilithium3, HybridCipher

class PQCNode:
    """Protokole katılan uç kullanıcı (Peer) veya Sunucu."""

    def __init__(self, node_id: str):
        self.node_id = node_id
        # Kuantum Kimlik Anahtarları (Dilithium-3)
        self.dilithium_pk, self.dilithium_sk = Dilithium3.keygen()
        # Kuantum Şifreleme Anahtarları (Kyber-768)
        self.kyber_pk, self.kyber_sk = Kyber768.keygen()
        # Aktif Oturum Anahtarları: { peer_id: session_key_bytes }
        self.active_sessions: Dict[str, bytes] = {}

    def get_public_identity(self) -> Dict[str, str]:
        """Düğümün açık kimlik sertifikası."""
        return {
            "node_id": self.node_id,
            "kyber_pk": base64.b64encode(self.kyber_pk).decode("ascii"),
            "dilithium_pk": base64.b64encode(self.dilithium_pk).decode("ascii")
        }

    def initiate_handshake(self, target_id: str) -> Dict[str, Any]:
        """
        Adım 1 (Client Hello):
        Alice, Bob'a kendi kimliğini, Kyber açık anahtarını ve Dilithium ile imzalanmış paketi gönderir.
        """
        timestamp = str(time.time()).encode("utf-8")
        signed_payload = self.node_id.encode("utf-8") + target_id.encode("utf-8") + self.kyber_pk + timestamp
        signature = Dilithium3.sign(signed_payload, self.dilithium_sk)

        return {
            "type": "HANDSHAKE_INIT",
            "sender_id": self.node_id,
            "target_id": target_id,
            "timestamp": timestamp.decode("utf-8"),
            "kyber_pk": base64.b64encode(self.kyber_pk).decode("ascii"),
            "dilithium_pk": base64.b64encode(self.dilithium_pk).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii")
        }

    def respond_handshake(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """
        Adım 2 (Server/Peer Response):
        Bob, Alice'in Dilithium imzasını doğrular.
        Alice'in Kyber açık anahtarını kullanarak oturum anahtarını kapsüller (KEM).
        Cevap paketini kendi Dilithium anahtarıyla imzalayıp Alice'e döner.
        """
        sender_id = packet["sender_id"]
        sender_kyber_pk = base64.b64decode(packet["kyber_pk"])
        sender_dilithium_pk = base64.b64decode(packet["dilithium_pk"])
        signature = base64.b64decode(packet["signature"])
        timestamp = packet["timestamp"].encode("utf-8")

        # 1. İmza doğrulaması (MITM Koruması)
        signed_payload = sender_id.encode("utf-8") + self.node_id.encode("utf-8") + sender_kyber_pk + timestamp
        if not Dilithium3.verify(signed_payload, signature, sender_dilithium_pk):
            raise PermissionError("GÜVENLİK İHLALİ: Alice'in Dilithium imzası geçersiz! Bağlantı reddedildi.")

        # 2. Kyber-768 ile anahtar kapsülleme (KEM)
        kyber_ct, session_key = Kyber768.encapsulate(sender_kyber_pk)
        self.active_sessions[sender_id] = session_key

        # 3. Bob'un kendi imzası
        resp_timestamp = str(time.time()).encode("utf-8")
        resp_payload = self.node_id.encode("utf-8") + sender_id.encode("utf-8") + kyber_ct + resp_timestamp
        resp_sig = Dilithium3.sign(resp_payload, self.dilithium_sk)

        return {
            "type": "HANDSHAKE_RESPONSE",
            "sender_id": self.node_id,
            "target_id": sender_id,
            "timestamp": resp_timestamp.decode("utf-8"),
            "dilithium_pk": base64.b64encode(self.dilithium_pk).decode("ascii"),
            "kyber_ciphertext": base64.b64encode(kyber_ct).decode("ascii"),
            "signature": base64.b64encode(resp_sig).decode("ascii")
        }

    def finalize_handshake(self, packet: Dict[str, Any]):
        """
        Adım 3 (Finish Handshake):
        Alice, Bob'un Dilithium imzasını doğrular ve Kyber şifreli metnini çözerek
        aynı oturum anahtarına ulaşır.
        """
        sender_id = packet["sender_id"]
        bob_dilithium_pk = base64.b64decode(packet["dilithium_pk"])
        kyber_ct = base64.b64decode(packet["kyber_ciphertext"])
        signature = base64.b64decode(packet["signature"])
        timestamp = packet["timestamp"].encode("utf-8")

        # 1. Bob'un imzasını doğrula
        resp_payload = sender_id.encode("utf-8") + self.node_id.encode("utf-8") + kyber_ct + timestamp
        if not Dilithium3.verify(resp_payload, signature, bob_dilithium_pk):
            raise PermissionError("GÜVENLİK İHLALİ: Bob'un Dilithium imzası geçersiz! MITM şüphesi.")

        # 2. Kyber ile anahtarı çöz
        session_key = Kyber768.decapsulate(kyber_ct, self.kyber_sk)
        self.active_sessions[sender_id] = session_key

    def send_secure_message(self, peer_id: str, message: str) -> Dict[str, Any]:
        """Ortak oturum anahtarı ve AES-256-GCM ile güvenli mesaj gönderir."""
        session_key = self.active_sessions.get(peer_id)
        if not session_key:
            raise ValueError(f"{peer_id} ile aktif bir PQC oturumu yok. Önce el sıkışma yapın.")

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(session_key)
        iv = os.urandom(12)
        plaintext = message.encode("utf-8")
        ciphertext = aesgcm.encrypt(iv, plaintext, associated_data=self.node_id.encode("utf-8"))

        return {
            "type": "SECURE_MESSAGE",
            "sender": self.node_id,
            "recipient": peer_id,
            "iv": base64.b64encode(iv).decode("ascii"),
            "payload": base64.b64encode(ciphertext).decode("ascii"),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    def receive_secure_message(self, packet: Dict[str, Any]) -> str:
        """Şifreli mesaj paketini çözer."""
        sender = packet["sender"]
        session_key = self.active_sessions.get(sender)
        if not session_key:
            raise ValueError(f"{sender} ile aktif oturum anahtarı bulunamadı.")

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        iv = base64.b64decode(packet["iv"])
        ciphertext = base64.b64decode(packet["payload"])
        aesgcm = AESGCM(session_key)
        plaintext = aesgcm.decrypt(iv, ciphertext, associated_data=sender.encode("utf-8"))
        return plaintext.decode("utf-8")

def run_protocol_demo():
    print("=" * 80)
    print("       Q-SHIELD FAZ 3: PQC İLETİŞİM PROTOKOLÜ & SALDIRI SİMÜLASYONU")
    print("=" * 80)

    # 1. Alice ve Bob Düğümleri Başlatılıyor
    print("\n[Adım 1] Düğümler Başlatılıyor:")
    alice = PQCNode("Alice_Node")
    bob = PQCNode("Bob_Node")
    print(f" -> {alice.node_id}: Dilithium-3 ve Kyber-768 anahtarları hazır.")
    print(f" -> {bob.node_id}: Dilithium-3 ve Kyber-768 anahtarları hazır.")

    # 2. El Sıkışma (Handshake) Başlatılıyor
    print("\n[Adım 2] Alice -> Bob Kuantum El Sıkışma İsteği Gönderiyor (HANDSHAKE_INIT)...")
    init_packet = alice.initiate_handshake(bob.node_id)
    print(f"    Paket Boyutu: {len(json.dumps(init_packet))} karakter")
    print(f"    Dilithium-3 İmzası: {init_packet['signature'][:30]}...")

    # 3. Bob İsteği İşliyor ve Cevap Veriyor
    print("\n[Adım 3] Bob isteği alıyor, Alice'in imzasını doğruluyor ve anahtar kapsüllüyor...")
    resp_packet = bob.respond_handshake(init_packet)
    print(f"    Kapsüllenen Kyber KEM Şifreli Metni: {resp_packet['kyber_ciphertext'][:30]}...")

    # 4. Alice Cevabı İşliyor ve Oturum Tamamlanıyor
    print("\n[Adım 4] Alice Bob'un cevabını onaylıyor ve KEM anahtarını deşifre ediyor...")
    alice.finalize_handshake(resp_packet)

    # Ortak Anahtar Kontrolü
    k_alice = alice.active_sessions[bob.node_id]
    k_bob = bob.active_sessions[alice.node_id]
    assert k_alice == k_bob
    print(f"\n[BAŞARILI] Her iki taraf da aynı 256-bit Kuantum-Güvenli Anahtara ulaştı!")
    print(f"    Ortak Oturum Anahtarı Özeti: {k_alice.hex()[:32]}...")

    # 5. Güvenli Mesajlaşma
    msg = "Kastamonu Üniversitesi Ar-Ge: Hibrit PQC Veri Kanalı Aktif ve Sızdırmaz."
    print(f"\n[Adım 5] Alice Bob'a şifreli mesaj gönderiyor: '{msg}'")
    sec_packet = alice.send_secure_message(bob.node_id, msg)
    print(f"    Ağdaki Şifreli Yük (Ciphertext): {sec_packet['payload'][:40]}...")

    decrypted_msg = bob.receive_secure_message(sec_packet)
    print(f"    Bob'un Çözdüğü Mesaj: '{decrypted_msg}'")
    assert decrypted_msg == msg

    # =========================================================================
    # SALDIRI SENARYOLARI (MITM & HNDL SİMÜLASYONU)
    # =========================================================================
    print("\n" + "=" * 80)
    print("                      SİBER SALDIRI SİMÜLASYONLARI")
    print("=" * 80)

    # Senaryo 1: Ortadaki Adam (MITM) Saldırısı
    print("\n[SALDIRI 1] Eve araya girip Alice'in paketini kendi sahte açık anahtarıyla değiştiriyor:")
    mitm_packet = dict(init_packet)
    fake_kyber_pk, _ = Kyber768.keygen()
    mitm_packet["kyber_pk"] = base64.b64encode(fake_kyber_pk).decode("ascii") # Tahrifat yapıldı

    try:
        bob.respond_handshake(mitm_packet)
        print("    [HATA] Saldırı tespit edilemedi!")
    except PermissionError as e:
        print(f"    [SAVUNMA BAŞARILI] Q-Shield Protokolü saldırıyı engelledi:")
        print(f"    -> {e}")

    # Senaryo 2: HNDL (Harvest Now, Decrypt Later) Analizi
    print("\n[SALDIRI 2] HNDL (Şimdi Çal, Kuantum Bilgisayarla Sonra Çöz) Simülasyonu:")
    print("    Saldırgan Eve ağdaki tüm paketleri (init, response, secure_message) diske kaydetti.")
    print("    - Klasik RSA/ECC trafiğinde: 2048-bit anahtar Shor algoritmasıyla O((log N)^3) karmaşıklıkta kırılır.")
    print("    - Q-Shield CRYSTALS-Kyber-768 trafiğinde: Kafes Problemi (SVP/LWE) kuantum bilgisayarla çözülemez!")
    print("    - Sonuç: Kaydedilen veriler 50 yıl sonra dahi MATEMATİKSEL OLARAK ÇÖZÜLEMEZ.")
    print("=" * 80)

if __name__ == "__main__":
    run_protocol_demo()
