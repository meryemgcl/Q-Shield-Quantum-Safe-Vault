"""
Q-Shield FAZ 4: Post-Quantum Siber Güvenlik Kontrol Paneli (Interactive Dashboard)
Kastamonu Üniversitesi 1. Ar-Ge Proje Pazarı

Çalıştırma:
    streamlit run faz4_dashboard.py
"""

import streamlit as st
import pandas as pd
import json
import time
import os
import base64
from pathlib import Path
from .crypto_core import Kyber768, Dilithium3, HybridCipher
from .benchmark import benchmark_rsa_2048, benchmark_rsa_4096, benchmark_ecdh_p256, benchmark_kyber_768, benchmark_dilithium_3
from .quantum_vault import QuantumVault
from .pqc_protocol import PQCNode

st.set_page_config(
    page_title="Q-Shield: Kuantum Sonrası Siber Güvenlik",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Özel CSS Tasarımı
st.markdown("""
<style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        color: #1E3A8A;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        font-size: 1.1rem;
        color: #4B5563;
        margin-bottom: 1.5rem;
    }
    .status-badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.85rem;
        background-color: #DEF7EC;
        color: #03543F;
    }
    .metric-box {
        background: #F3F4F6;
        border-radius: 8px;
        padding: 15px;
        border-left: 5px solid #2563EB;
    }
</style>
""", unsafe_allow_html=True)

# Kenar Çubuğu
with st.sidebar:
    st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/c/c5/Kastamonu_%C3%9Cniversitesi_logosu.svg/300px-Kastamonu_%C3%9Cniversitesi_logosu.svg.png", width=120)
    st.markdown("### **Q-Shield PQC**")
    st.markdown("**1. Ar-Ge Proje Pazarı**")
    st.markdown("---")
    st.markdown("**Standartlar:**")
    st.markdown("- NIST FIPS 203: ML-KEM (Kyber)")
    st.markdown("- NIST FIPS 204: ML-DSA (Dilithium)")
    st.markdown("- FIPS 197: AES-256-GCM")
    st.markdown("---")
    st.markdown("**Proje Bütçesi:** 45.000 TL")
    st.markdown("**Mimari:** %100 Saf Yazılım (Kafes Kriptografisi)")
    st.markdown("---")
    st.info("Kuantum Bilgisayarlar (Shor Algoritması) RSA ve ECC'yi kırmadan önce verilerinizi koruyun.")

st.markdown('<div class="main-title">🛡️ Q-Shield: Kuantum Sonrası Kriptografi (PQC) Protokolü</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Kastamonu Üniversitesi Ar-Ge Proje Pazarı | Hibrit Veri Güvenliği ve Kuantum Kasası Prototipi</div>', unsafe_allow_html=True)

tabs = st.tabs([
    "📊 Faz 1: Kriptografik Karşılaştırma",
    "🗄️ Faz 2: Kuantum Kasası (Quantum Vault)",
    "🌐 Faz 3: Uçtan Uca İletişim & Siber Savunma",
    "💻 Faz 4: Mobil Entegrasyon & SDK"
])

# ==============================================================================
# SEKME 1: FAZ 1 BENCHMARK
# ==============================================================================
with tabs[0]:
    st.header("⚡ Faz 1: Algoritma Performans & Gecikme Analizi")
    st.write("Klasik asimetrik şifreleme (RSA, ECC) ile NIST onaylı Kuantum Sonrası Kriptografi (CRYSTALS-Kyber) karşılaştırması:")

    if st.button("🔄 Karşılaştırma Testlerini Canlı Çalıştır"):
        with st.spinner("Kriptografik anahtar üretimleri ve gecikme testleri yapılıyor..."):
            r_rsa2 = benchmark_rsa_2048()
            r_rsa4 = benchmark_rsa_4096()
            r_ecdh = benchmark_ecdh_p256()
            r_kyber = benchmark_kyber_768()
            st.session_state["benchmark_data"] = [r_rsa2, r_rsa4, r_ecdh, r_kyber]
            st.success("Testler tamamlandı!")

    if "benchmark_data" not in st.session_state:
        # Önceden kaydedilmiş dosya varsa yükle
        if Path("benchmark_results.json").exists():
            with open("benchmark_results.json", "r", encoding="utf-8") as f:
                saved = json.load(f)
                st.session_state["benchmark_data"] = saved["kem_benchmarks"]
        else:
            r_rsa2 = benchmark_rsa_2048()
            r_rsa4 = benchmark_rsa_4096()
            r_ecdh = benchmark_ecdh_p256()
            r_kyber = benchmark_kyber_768()
            st.session_state["benchmark_data"] = [r_rsa2, r_rsa4, r_ecdh, r_kyber]

    data = st.session_state["benchmark_data"]
    df = pd.DataFrame(data)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Kyber-768 Kuantum Durumu", "Tam Dirençli (NIST-3)", "Shor Algoritması Çözemez")
    with col2:
        st.metric("Kyber Açık Anahtar", f"{data[3]['pk_size_bytes']} Bayt", "1184 bayt standart")
    with col3:
        st.metric("Şifreli Zarf Boyutu", f"{data[3]['ct_size_bytes']} Bayt", "1088 bayt KEM")
    with col4:
        st.metric("Hibrit Simetrik Şifre", "AES-256-GCM", "Donanımsal Hız")

    st.subheader("📋 Kapsamlı Karşılaştırma Tablosu")
    display_df = df[["name", "quantum_safe", "keygen_ms", "enc_ms", "dec_ms", "pk_size_bytes", "ct_size_bytes", "security_bits", "math_basis"]]
    display_df.columns = ["Algoritma", "Kuantum Güvenli", "Keygen (ms)", "Şifreleme (ms)", "Deşifreleme (ms)", "Açık Anahtar (B)", "Şifreli Metin (B)", "Güvenlik Biti", "Matematiksel Temel"]
    st.dataframe(display_df, use_container_width=True)

    st.subheader("📈 Gecikme (Latency) Karşılaştırması (ms)")
    chart_data = df[["name", "keygen_ms", "enc_ms", "dec_ms"]].set_index("name")
    st.bar_chart(chart_data)

# ==============================================================================
# SEKME 2: FAZ 2 QUANTUM VAULT
# ==============================================================================
with tabs[1]:
    st.header("🗄️ Faz 2: Kuantum Kasası (Yerel Dosya Şifreleme)")
    st.write("Dosyalarınızı **CRYSTALS-Kyber-768** ve **AES-256-GCM** hibrit mimarisiyle sızdırmaz bir Kuantum Kasasında (.qvault) saklayın.")

    vault = QuantumVault()

    v_col1, v_col2 = st.columns(2)

    with v_col1:
        st.subheader("🔒 Dosyayı Kuantum Kasasına Kilitle")
        uploaded_file = st.file_uploader("Şifrelenecek Belgeyi / Resmi Seçin", type=None, key="vault_upload")
        if uploaded_file is not None:
            st.info(f"Yüklenen dosya: **{uploaded_file.name}** ({len(uploaded_file.getvalue())} bayt)")
            if st.button("🚀 Kuantum Kasasına Kilitle (.qvault)", key="btn_lock"):
                temp_path = Path("temp_upload_" + uploaded_file.name)
                temp_path.write_bytes(uploaded_file.getvalue())
                target_vault_path = vault.lock_file(str(temp_path), delete_original=True)
                st.success(f"Dosya kuantum kasasına kilitlendi: {Path(target_vault_path).name}")

                # İndirme Butonu
                vault_bytes = Path(target_vault_path).read_bytes()
                st.download_button(
                    label="💾 Şifreli .qvault Dosyasını İndir",
                    data=vault_bytes,
                    file_name=Path(target_vault_path).name,
                    mime="application/octet-stream"
                )

    with v_col2:
        st.subheader("🔓 Kuantum Kasasından Dosya Aç (Unlock)")
        vault_file = st.file_uploader(".qvault Formatındaki Kasa Dosyasını Yükleyin", type=["qvault"], key="vault_unlock")
        if vault_file is not None:
            if st.button("🔑 Kuantum Anahtarıyla Çöz ve Doğrula", key="btn_unlock"):
                temp_v = Path("temp_unlock_" + vault_file.name)
                temp_v.write_bytes(vault_file.getvalue())
                try:
                    restored_path = vault.unlock_file(str(temp_v))
                    restored_data = Path(restored_path).read_bytes()
                    st.success(f"Bütünlük doğrulandı! Orijinal dosya açıldı: {Path(restored_path).name}")
                    st.download_button(
                        label=f"📥 Açılan Dosyayı İndir ({Path(restored_path).name})",
                        data=restored_data,
                        file_name=Path(restored_path).name,
                        mime="application/octet-stream"
                    )
                    temp_v.unlink(missing_ok=True)
                except Exception as e:
                    st.error(f"Deşifreleme hatası: {str(e)}")

    st.markdown("---")
    st.subheader("📂 Kasadaki Mevcut Dosyalar")
    items = vault.list_vault()
    if items:
        st.table(pd.DataFrame(items)[["vault_file", "size_bytes", "modified_at", "quantum_status"]])
    else:
        st.write("Kasada henüz kilitli dosya bulunmuyor.")

# ==============================================================================
# SEKME 3: FAZ 3 PROTOKOL & SALDIRI SİMÜLASYONU
# ==============================================================================
with tabs[2]:
    st.header("🌐 Faz 3: Uçtan Uca İletişim Protokolü & Siber Saldırı Savunması")
    st.write("Alice ve Bob arasında CRYSTALS-Kyber KEM ve CRYSTALS-Dilithium dijital imzasıyla siber saldırılara karşı güvenli tünel:")

    col_alice, col_channel, col_bob = st.columns([3, 2, 3])

    if "sim_alice" not in st.session_state:
        st.session_state["sim_alice"] = PQCNode("Alice_Finans")
        st.session_state["sim_bob"] = PQCNode("Bob_Merkez_Banka")

    alice = st.session_state["sim_alice"]
    bob = st.session_state["sim_bob"]

    with col_alice:
        st.subheader("👩 Alice (İstemci)")
        st.markdown(f"**Düğüm:** `{alice.node_id}`")
        st.markdown(f"**Kyber PK:** `{base64.b64encode(alice.kyber_pk).decode()[:20]}...`")
        st.markdown(f"**Dilithium PK:** `{base64.b64encode(alice.dilithium_pk).decode()[:20]}...`")

    with col_bob:
        st.subheader("👨 Bob (Alıcı)")
        st.markdown(f"**Düğüm:** `{bob.node_id}`")
        st.markdown(f"**Kyber PK:** `{base64.b64encode(bob.kyber_pk).decode()[:20]}...`")
        st.markdown(f"**Dilithium PK:** `{base64.b64encode(bob.dilithium_pk).decode()[:20]}...`")

    with col_channel:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🤝 Kuantum El Sıkışmayı Gerçekleştir"):
            with st.spinner("PQC Handshake yürütülüyor..."):
                init_pkt = alice.initiate_handshake(bob.node_id)
                resp_pkt = bob.respond_handshake(init_pkt)
                alice.finalize_handshake(resp_pkt)
                st.session_state["handshake_done"] = True
                st.session_state["session_key"] = alice.active_sessions[bob.node_id].hex()
                st.success("El Sıkışma Tamamlandı!")

    if st.session_state.get("handshake_done"):
        st.success(f"🔐 Ortak 256-Bit Kuantum Oturum Anahtarı Türetildi: `{st.session_state['session_key'][:40]}...`")

        msg_input = st.text_input("Alice'in Bob'a Göndereceği Mesaj:", "Gizli Bütçe Aktarım Kodu: ARGE-KASTAMONU-2026-X")
        if st.button("📨 Güvenli Mesajı İlet"):
            packet = alice.send_secure_message(bob.node_id, msg_input)
            decrypted = bob.receive_secure_message(packet)
            st.info(f"**Ağ Üzerindeki Şifreli Paket:** `{packet['payload']}`")
            st.success(f"**Bob Tarafında Çözülen Mesaj:** `{decrypted}`")

    st.markdown("---")
    st.subheader("🚨 Siber Saldırı ve Savunma Simülatörü")

    att_col1, att_col2 = st.columns(2)
    with att_col1:
        st.markdown("#### 1. Ortadaki Adam (MITM) Saldırısı")
        st.write("Saldırgan Eve araya girip açık anahtarı sahtesiyle değiştirmeye çalışır.")
        if st.button("⚠️ MITM Saldırısı Başlat"):
            init_pkt = alice.initiate_handshake(bob.node_id)
            mitm_pkt = dict(init_pkt)
            fake_pk, _ = Kyber768.keygen()
            mitm_pkt["kyber_pk"] = base64.b64encode(fake_pk).decode("ascii")

            try:
                bob.respond_handshake(mitm_pkt)
                st.error("Saldırı engellenemedi!")
            except PermissionError as e:
                st.success("🛡️ SAVUNMA BAŞARILI: Dilithium-3 Dijital İmzası tahrifatı yakaladı ve sahte paketi engelledi!")

    with att_col2:
        st.markdown("#### 2. HNDL (Harvest Now, Decrypt Later) Tehdidi")
        st.write("Saldırganlar trafiği bugün kaydedip 10 yıl sonra kuantum bilgisayarla çözmeyi planlar.")
        if st.button("🧪 HNDL Kuantum Direnç Analizini Gör"):
            st.warning("Klasik RSA-2048: 20 Milyon Qubitlik Shor algoritmalı bilgisayarla 8 saatte tamamen kırılır!")
            st.success("Q-Shield (Kyber-768): Bilinen hiçbir kuantum algoritması Kafes (LWE) problemini polinom zamanda çözemez. Güvenlik Seviyesi: > 2^192 işlem!")

# ==============================================================================
# SEKME 4: FAZ 4 SDK & ENTEGRASYON
# ==============================================================================
with tabs[3]:
    st.header("💻 Faz 4: Mobil Entegrasyon & Geliştirici SDK")
    st.write("Q-Shield Protokolünü diğer uygulamalara entegre etmek için hazır kod kütüphaneleri:")

    st.subheader("📱 Android (Kotlin / Java) Entegrasyon Örneği (.aar SDK)")
    st.code("""
// Q-Shield Android SDK Entegrasyonu (Kotlin)
val qshield = QShieldAndroidClient(context)

// 1. Dosya şifreleme ve Kuantum Kasasına kilitleme
val vaultFile = qshield.lockFile(
    sourceFile = File("/sdcard/Documents/gizli_rapor.pdf"),
    algorithm = PQCAlgorithm.KYBER_768_AES_GCM
)

// 2. Ağ üzerinden başka bir cihaza PQC güvenli mesaj gönderme
qshield.sendQuantumMessage(
    recipientId = "Bank_Server",
    message = "Para Transfer Onayı #9841"
)
    """, language="kotlin")

    st.subheader("🐍 Python SDK Entegrasyonu")
    st.code("""
from qshield.sdk import QShieldClient

# Initialize client
client = QShieldClient(client_id="ArGe_Merkezi")

# Lock file into Quantum Vault
vault_path = client.lock_to_vault("gizli_planlar.docx")
print(f"Locked vault: {vault_path}")

# Unlock from vault
client.unlock_from_vault(vault_path)
    """, language="python")

    st.markdown("---")
    st.subheader("💰 Tahmini Proje Bütçesi Dağılımı")
    budget_df = pd.DataFrame([
        {"Kalem": "Geliştirme ve Test Cihazları/Ortamları", "Tutar (TL)": 15000, "Açıklama": "Mobil test cihazları ve geliştirme iş istasyonu"},
        {"Kalem": "Sızma Testleri ve Kriptografik Denetim Araçları", "Tutar (TL)": 20000, "Açıklama": "Yan kanal ve güvenlik denetimi yazılımları"},
        {"Kalem": "Protokol Bulut Sunucu Röle Giderleri", "Tutar (TL)": 10000, "Açıklama": "P2P sinyalleşme ve relay sunucu altyapısı"},
        {"Kalem": "TOPLAM", "Tutar (TL)": 45000, "Açıklama": "1. Ar-Ge Proje Pazarı kapsamında talep edilen bütçe"}
    ])
    st.table(budget_df)
