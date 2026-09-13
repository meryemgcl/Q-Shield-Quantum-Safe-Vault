# KASTAMONU ÜNİVERSİTESİ 1. AR-GE PROJE PAZARI BAŞVURU FORMU

**Proje Başlığı:** Q-Shield: Kuantum Sonrası Kriptografi (PQC) Tabanlı Hibrit Veri Güvenliği Protokolü
**Başvuru Alanı:** Fen Bilimleri / Yazılım ve Bilişim Teknolojileri

### Proje Özeti ve Anahtar Kelimeler
Mevcut dijital altyapılarda kullanılan RSA ve ECC şifreleme standartları, kuantum bilgisayarların gelişmesiyle kırılabilecek duruma gelecektir. Siber saldırganlar, verileri çalıp kuantum bilgisayarlar çıkınca çözmek üzere depolamaktadır (HNDL saldırıları). Bu projenin amacı, NIST onaylı Kuantum-Dirençli (örn. CRYSTALS-Kyber) algoritmaları kullanarak geleceğin tehditlerine karşı koyabilen hibrit bir mobil veri güvenlik yazılımı geliştirmektir. Proje, %100 saf yazılım ve ileri matematik mühendisliğine dayanır.
**Anahtar Kelimeler:** Kuantum Sonrası Kriptografi, Siber Güvenlik, Hibrit Şifreleme, Lattice-Based Cryptography.

### Projenin Amaç ve Hedefleri
*   **Amaç:** Kuantum bilgisayarların algoritmik gücüyle dahi kırılamayan matematiksel yapılara sahip güvenli bir iletişim protokolü oluşturmak.
*   **Hedefler:**
    1. Açık kaynaklı PQC kütüphanelerini mobil mimariye entegre etmek.
    2. AES-256 ile çalışan bir "Hibrit Şifreleme Mimarisi" kodlamak.
    3. Verilerin sızdırmaz bir "Kuantum Kasasında (Vault)" tutulacağı Android arayüzünü geliştirmek.

### Projenin Yenilikçi Yönü (Özgün Değeri)
1.  **Geleceğe Dayanıklılık:** 10 yıl sonrasının "Kuantum" tehditlerine karşı bağışıklık.
2.  **Hibrit Mimari Tasarımı:** Veri AES-256 ile, anahtar ise Kuantum algoritmasıyla şifrelenerek performanstan ödün verilmez.
3.  **Bağımsız Protokol (SDK):** Diğer firmaların uygulamalarına Kuantum güvenliği katabileceği bir API/SDK mimarisi.

### Projenin Yöntemi
Java/Kotlin (Android) ve C/C++ (Çekirdek Şifreleme) kullanılarak geliştirilecektir.
1. **Anahtar Kapsülleme (KEM):** CRYSTALS-Kyber algoritması ile güvenli anahtar takası.
2. **Hibrit Şifreleme Modülü:** Dosya AES-GCM ile şifrelenir, anahtar Kyber ile sarmalanır.
3. **Mobil Entegrasyon:** Kuantum şifreli dosya deposu için Android arayüzü yazılır.

### Tahmini Proje Bütçesi
*   Geliştirme ve Test Cihazları: 15.000 TL
*   Sızma Testleri ve Kriptografik Denetim Araçları: 20.000 TL
*   Sunucu Röle Giderleri: 10.000 TL
*   Toplam: 45.000 TL
