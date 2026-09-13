# Q-Shield PQC Kriptografi Protokolü - Proje Geliştirme Fazları

### FAZ 1: Şifreleme Çekirdeğinin İnşası (Core Cryptography)
*   Açık kaynaklı PQC kütüphanelerinin (OQS) Android ortamına (JNI/C++) entegre edilmesi.
*   Hibrit mimarinin kurulması (Metnin AES ile, anahtarın CRYSTALS-Kyber ile şifrelenmesi).
*   Gecikme (latency) testlerinin yapılması.

### FAZ 2: "Quantum Vault" Mobil Uygulaması (MVP)
*   Yerel "Kasa (Vault)" Android uygulamasının yazılması.
*   Dosyaların cihazda Kuantum şifrelemeyle kilitlenmesi.

### FAZ 3: PQC İletişim Protokolü (Client-to-Client)
*   Kullanıcıların kuantum şifreli dosyaları ağ üzerinden birbirine iletmesi.
*   Ortadaki Adam (MITM) saldırılarına karşı CRYSTALS-Dilithium dijital imza algoritması entegrasyonu.

### FAZ 4: İleri Seviye Genişleme
*   **Developer SDK / API:** Q-Shield'in .aar paketi olarak yayınlanıp diğer şirketlere satılması.
*   **Kuantum Güvenlikli VPN:** Ağ katmanında bir VPN mimarisine dönüştürülmesi.
