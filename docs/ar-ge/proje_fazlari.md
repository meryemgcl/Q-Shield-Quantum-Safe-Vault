# Q-Shield PQC Kriptografi Protokolü - Proje Geliştirme Fazları

Bu belge, kuantum güvenliği kavramının mobil uygulamadan uluslararası bir protokole dönüşmesini sağlayacak genişletilebilir geliştirme fazlarını içermektedir.

### FAZ 1: Şifreleme Çekirdeğinin İnşası (Core Cryptography) - [Mevcut Odak]
*   Açık kaynaklı PQC (Post-Quantum Cryptography) kütüphanelerinin (örneğin OQS kütüphanesi) Android geliştirme ortamına (JNI/C++) entegre edilmesi.
*   Hibrit mimarinin kurulması: Bir metnin AES-256 ile şifrelenmesi ve anahtarın CRYSTALS-Kyber algoritması ile sarmalanması (Key Encapsulation).
*   Şifreleme ve deşifreleme işleminin gecikme (latency) testlerinin cihaz üzerinde başarıyla yapılması.

### FAZ 2: "Quantum Vault" Mobil Uygulaması (MVP)
*   Kullanıcıların telefonlarındaki resim, PDF veya metin dosyalarını Kuantum algoritmasıyla kilitleyip saklayabildikleri yerel bir "Kasa (Vault)" Android uygulamasının yazılması.
*   Kullanıcı dostu arayüz ve şifreli dosya yönetimi.

### FAZ 3: PQC İletişim Protokolü (Client-to-Client)
*   Uygulamalar arası veri iletimi: Bir kullanıcının Kuantum anahtarı ile şifrelediği dosyayı ağ üzerinden başka bir kullanıcıya güvenle iletmesi.
*   Man-in-the-Middle (Ortadaki Adam) saldırılarına karşı CRYSTALS-Dilithium dijital imza algoritmasının sisteme dahil edilerek kimlik doğrulamanın kuantum güvenli hale getirilmesi.

### FAZ 4: İleri Seviye Genişleme (İnovasyon Kapıları)
*   **Developer SDK / API:** Q-Shield'in bir kütüphane (.aar paketi veya NPM modülü) haline getirilip piyasaya sürülmesi. WhatsApp, Telegram veya Banka uygulaması geliştiren yazılımcıların tek satır kodla kendi sistemlerine kuantum güvenliği katması.
*   **Kuantum Güvenlikli VPN:** Protokolün genişletilerek ağ katmanında bir VPN (Sanal Özel Ağ) mimarisine dönüştürülmesi.
