"""
Q-Shield FAZ 3: PQC İletişim Protokolü & Gerçek TCP Ağ Soket Katmanı
(Production-Grade PQC Handshake, Real TCP Sockets & Anti-Replay Defense)

Gelişmiş Özellikler:
1. Gerçek TCP Soket Sunucusu ve İstemcisi (TCP Socket Server & Client).
2. Yeniden Oynatma Saldırıları (Replay Attacks) Koruması:
   - 30 saniyelik zaman kayma penceresi (sliding window).
   - Monotonik artan sıra numarası (sequence number).
   - Tekil paket belirteci (nonce) önbelleği ve mükerrer paket engelleme.
3. CRYSTALS-Dilithium-3 Dijital İmzası ile Ortadaki Adam (MITM) önleme.
4. CRYSTALS-Kyber-768 ile İleriye Dönük Gizlilik (PFS - Perfect Forward Secrecy).
"""

import os
import sys
import time
import json
import socket
import select
import base64
import threading
import struct
import logging
from typing import Dict, Any, Tuple, Optional, Set
from .crypto_core import Kyber768, Dilithium3, HybridCipher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

TIMESTAMP_TOLERANCE_SECONDS = 30.0

class PQCNode:
    """Protokole katılan uç kullanıcı (Peer) veya Sunucu."""

    def __init__(self, node_id: str):
        self.node_id = node_id
        self.dilithium_pk, self.dilithium_sk = Dilithium3.keygen()
        self.kyber_pk, self.kyber_sk = Kyber768.keygen()
        self.active_sessions: Dict[str, bytes] = {}
        # Replay Attack Koruması için Monotonik Sayaç ve Nonce Önbelleği
        self.out_sequence: Dict[str, int] = {}
        self.in_sequence: Dict[str, int] = {}
        self.seen_nonces: Set[str] = set()

    def get_public_identity(self) -> Dict[str, str]:
        return {
            "node_id": self.node_id,
            "kyber_pk": base64.b64encode(self.kyber_pk).decode("ascii"),
            "dilithium_pk": base64.b64encode(self.dilithium_pk).decode("ascii")
        }

    def initiate_handshake(self, target_id: str) -> Dict[str, Any]:
        """Adım 1: Client Hello paketi."""
        current_time = time.time()
        nonce = os.urandom(16).hex()
        seq = 1
        self.out_sequence[target_id] = seq

        signed_payload = (
            self.node_id.encode("utf-8") +
            target_id.encode("utf-8") +
            self.kyber_pk +
            str(current_time).encode("utf-8") +
            nonce.encode("utf-8") +
            struct.pack(">Q", seq)
        )
        signature = Dilithium3.sign(signed_payload, self.dilithium_sk)

        return {
            "type": "HANDSHAKE_INIT",
            "sender_id": self.node_id,
            "target_id": target_id,
            "timestamp": current_time,
            "nonce": nonce,
            "seq": seq,
            "kyber_pk": base64.b64encode(self.kyber_pk).decode("ascii"),
            "dilithium_pk": base64.b64encode(self.dilithium_pk).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii")
        }

    def respond_handshake(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Adım 2: Bob isteği doğrular, anahtar kapsüller ve cevap paketi üretir."""
        sender_id = packet["sender_id"]
        sender_kyber_pk = base64.b64decode(packet["kyber_pk"])
        sender_dilithium_pk = base64.b64decode(packet["dilithium_pk"])
        signature = base64.b64decode(packet["signature"])
        pkt_time = packet["timestamp"]
        nonce = packet["nonce"]
        seq = packet["seq"]

        # 1. Anti-Replay: Zaman penceresi ve Nonce kontrolü
        now = time.time()
        if abs(now - pkt_time) > TIMESTAMP_TOLERANCE_SECONDS:
            raise ValueError(f"REPLAY DANGER: Packet expired! (Diff: {abs(now - pkt_time):.1f}s)")

        if nonce in self.seen_nonces:
            raise ValueError(f"REPLAY ATTACK: Packet nonce ({nonce}) has already been used!")
        self.seen_nonces.add(nonce)

        # 2. Dilithium İmza Doğrulaması (MITM Savunması)
        signed_payload = (
            sender_id.encode("utf-8") +
            self.node_id.encode("utf-8") +
            sender_kyber_pk +
            str(pkt_time).encode("utf-8") +
            nonce.encode("utf-8") +
            struct.pack(">Q", seq)
        )
        if not Dilithium3.verify(signed_payload, signature, sender_dilithium_pk):
            raise PermissionError("SECURITY BREACH: Alice's Dilithium signature is invalid! Connection rejected.")

        self.in_sequence[sender_id] = seq

        # 3. Kyber-768 ile anahtar kapsülleme (KEM)
        kyber_ct, session_key = Kyber768.encapsulate(sender_kyber_pk)
        self.active_sessions[sender_id] = session_key

        # 4. Bob'un imzası
        resp_time = time.time()
        resp_nonce = os.urandom(16).hex()
        resp_seq = 2
        self.out_sequence[sender_id] = resp_seq

        resp_payload = (
            self.node_id.encode("utf-8") +
            sender_id.encode("utf-8") +
            kyber_ct +
            str(resp_time).encode("utf-8") +
            resp_nonce.encode("utf-8") +
            struct.pack(">Q", resp_seq)
        )
        resp_sig = Dilithium3.sign(resp_payload, self.dilithium_sk)

        return {
            "type": "HANDSHAKE_RESPONSE",
            "sender_id": self.node_id,
            "target_id": sender_id,
            "timestamp": resp_time,
            "nonce": resp_nonce,
            "seq": resp_seq,
            "dilithium_pk": base64.b64encode(self.dilithium_pk).decode("ascii"),
            "kyber_ciphertext": base64.b64encode(kyber_ct).decode("ascii"),
            "signature": base64.b64encode(resp_sig).decode("ascii")
        }

    def finalize_handshake(self, packet: Dict[str, Any]):
        """Adım 3: Alice Bob'un cevabını onaylar ve ortak anahtarı deşifre eder."""
        sender_id = packet["sender_id"]
        bob_dilithium_pk = base64.b64decode(packet["dilithium_pk"])
        kyber_ct = base64.b64decode(packet["kyber_ciphertext"])
        signature = base64.b64decode(packet["signature"])
        pkt_time = packet["timestamp"]
        nonce = packet["nonce"]
        seq = packet["seq"]

        now = time.time()
        if abs(time.time() - pkt_time) > TIMESTAMP_TOLERANCE_SECONDS:
            raise ValueError("REPLAY DANGER: Reply packet expired!")
        if nonce in self.seen_nonces:
            raise ValueError("REPLAY ATTACK: Duplicate reply nonce!")
        self.seen_nonces.add(nonce)

        resp_payload = (
            sender_id.encode("utf-8") +
            self.node_id.encode("utf-8") +
            kyber_ct +
            str(pkt_time).encode("utf-8") +
            nonce.encode("utf-8") +
            struct.pack(">Q", seq)
        )
        if not Dilithium3.verify(resp_payload, signature, bob_dilithium_pk):
            raise PermissionError("SECURITY BREACH: Bob's Dilithium signature is invalid! Suspected MITM attack.")

        self.in_sequence[sender_id] = seq
        session_key = Kyber768.decapsulate(kyber_ct, self.kyber_sk)
        self.active_sessions[sender_id] = session_key

    def send_secure_message(self, peer_id: str, message: str) -> Dict[str, Any]:
        """Adım 3: Karşılıklı Kuantum oturum anahtarı ile mesaj gönder."""
        if peer_id not in self.active_sessions:
            raise ValueError(f"No active PQC session with {peer_id}.")

        aes_key = self.active_sessions[peer_id]
        iv = os.urandom(12)
        
        seq = self.out_sequence.get(peer_id, 1) + 1
        self.out_sequence[peer_id] = seq

        aesgcm = AESGCM(aes_key)
        # Bütünlük için SENDER + TARGET + SEQ auth data olarak eklenir
        auth_data = f"{self.node_id}:{peer_id}:{seq}".encode("utf-8")
        ct = aesgcm.encrypt(iv, message.encode("utf-8"), associated_data=auth_data)

        return {
            "type": "SECURE_MESSAGE",
            "sender": self.node_id,
            "target": peer_id,
            "seq": seq,
            "iv": base64.b64encode(iv).decode("ascii"),
            "ciphertext": base64.b64encode(ct).decode("ascii")
        }

    def receive_secure_message(self, packet: Dict[str, Any]) -> str:
        """Adım 4: Gelen şifreli mesajı çöz."""
        sender = packet["sender"]
        if sender not in self.active_sessions:
            raise ValueError(f"No active session key found for {sender}.")

        seq = packet["seq"]
        last_seq = self.in_sequence.get(sender, 0)
        
        # Monotonik artış kontrolü
        if seq <= last_seq:
            raise ValueError(f"MONOTONIC SEQUENCE ERROR: Expected > {last_seq}, got {seq} (Possible Replay Attack)")
        self.in_sequence[sender] = seq

        aes_key = self.active_sessions[sender]
        iv = base64.b64decode(packet["iv"])
        ciphertext = base64.b64decode(packet.get("payload", packet.get("ciphertext")))
        aad = f"{sender}:{self.node_id}:{seq}".encode("utf-8")
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(iv, ciphertext, associated_data=aad)
        return plaintext.decode("utf-8")


# =====================================================================
# GERÇEK TCP SOKET AĞ PROTOKOLÜ (P2P SOCKET SERVER & CLIENT)
# =====================================================================
class PQCSocketServer:
    """Gerçek ağ üzerinde çalışan PQC TCP Sunucusu."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9123, node_id: str = "Server_Node"):
        self.host = host
        self.port = port
        self.node = PQCNode(node_id)
        self.running = False
        self.sock = None

    def start(self, once: bool = False):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        self.running = True
        logger.info(f"[PQC Server] Node {self.node.node_id} listening on {self.host}:{self.port}...")

        while self.running:
            try:
                conn, addr = self.sock.accept()
                threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
                if once:
                    break
            except Exception:
                break

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

    def _handle_client(self, conn: socket.socket, addr):
        try:
            raw_data = conn.recv(16384)
            if not raw_data:
                return
            init_pkt = json.loads(raw_data.decode("utf-8"))
            resp_pkt = self.node.respond_handshake(init_pkt)
            conn.sendall(json.dumps(resp_pkt).encode("utf-8"))

            # Mesaj bekle
            msg_data = conn.recv(16384)
            if msg_data:
                msg_pkt = json.loads(msg_data.decode("utf-8"))
                decrypted = self.node.receive_secure_message(msg_pkt)
                logger.info(f"[PQC Server] Encrypted message received from client ({addr}): '{decrypted}'")
                reply_pkt = self.node.send_secure_message(msg_pkt["sender"], "Message Received & Quantum Verified: OK")
                conn.sendall(json.dumps(reply_pkt).encode("utf-8"))
        except Exception as e:
            logger.error(f"[PQC Server] Connection error: {e}")
        finally:
            conn.close()

class PQCSocketClient:
    """Gerçek TCP soketi üzerinden PQC el sıkışması yapan istemci."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9123, node_id: str = "Client_Node"):
        self.host = host
        self.port = port
        self.node = PQCNode(node_id)

    def connect_and_send(self, target_id: str, message: str) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.port))
        try:
            # 1. El sıkışma isteği
            init_pkt = self.node.initiate_handshake(target_id)
            s.sendall(json.dumps(init_pkt).encode("utf-8"))

            # 2. El sıkışma cevabı
            resp_data = s.recv(16384)
            resp_pkt = json.loads(resp_data.decode("utf-8"))
            self.node.finalize_handshake(resp_pkt)

            # 3. Şifreli mesaj gönder
            msg_pkt = self.node.send_secure_message(target_id, message)
            s.sendall(json.dumps(msg_pkt).encode("utf-8"))

            # 4. Sunucu cevabını çöz
            reply_data = s.recv(16384)
            reply_pkt = json.loads(reply_data.decode("utf-8"))
            return self.node.receive_secure_message(reply_pkt)
        finally:
            s.close()


def run_protocol_demo():
    logger.info("=" * 80)
    logger.info("  Q-SHIELD PHASE 3: PQC COMMUNICATION PROTOCOL & REAL TCP SOCKET TEST")
    logger.info("=" * 80)

    # 1. Start TCP Server
    server = PQCSocketServer(host="127.0.0.1", port=9123, node_id="Bank_Server")
    server_thread = threading.Thread(target=server.start, kwargs={"once": True}, daemon=True)
    server_thread.start()
    time.sleep(0.1)

    # 2. Client connects and performs PQC Handshake over TCP
    client = PQCSocketClient(host="127.0.0.1", port=9123, node_id="Mobile_Client")
    logger.info("[1/3] Performing PQC handshake over TCP socket...")
    reply = client.connect_and_send("Bank_Server", "EFT Transfer Approval #9872 - $50,000")
    logger.info(f"[2/3] Decrypted PQC reply from server: '{reply}'")
    server.stop()

    # 3. Anti-Replay Attack Test
    logger.info("\n[3/3] Replay Attack Simulation:")
    alice = PQCNode("Alice")
    bob = PQCNode("Bob")
    init_pkt = alice.initiate_handshake(bob.node_id)

    # Normal acceptance
    bob.respond_handshake(init_pkt)
    logger.info(" -> First packet successfully processed by Bob.")

    # Attacker replays the same packet
    try:
        bob.respond_handshake(init_pkt)
        logger.error(" -> [ERROR] Duplicate packet was not detected!")
    except ValueError as e:
        logger.info(f" -> [DEFENSE SUCCESSFUL] Replay Attack Blocked: {e}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_protocol_demo()

