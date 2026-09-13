# KASTAMONU ÜNİVERSİTESİ 1. AR-GE PROJE PAZARI BAŞVURU FORMU

*(Aşağıdaki metinleri doğrudan yüklediğiniz PDF/Word formundaki ilgili kutucuklara kopyalayabilirsiniz.)*

---

**Proje Başlığı:** Q-Shield: Kuantum Sonrası Kriptografi (PQC) Tabanlı Hibrit Veri Güvenliği ve İletişim Protokolü
**Başvuru Alanı:** Fen Bilimleri / Yazılım ve Bilişim Teknolojileri

---

### Proje Özeti ve Anahtar Kelimeler
Mevcut dijital altyapılarda kullanılan RSA ve ECC gibi asimetrik şifreleme standartları, kuantum bilgisayarların gelişmesiyle birlikte birkaç yıl içinde tamamen kırılabilecek duruma gelecektir. Günümüzde siber saldırganlar, şifreli verileri çalıp kuantum bilgisayarlar erişilebilir olduğunda çözmek üzere depolamaktadır (HNDL saldırıları). Bu projenin amacı, ABD Ulusal Standartlar Enstitüsü (NIST) tarafından yeni onaylanan Kuantum-Dirençli "Kafes Tabanlı (Lattice-Based)" kriptografik algoritmaları (örn. CRYSTALS-Kyber) kullanarak geleceğin tehditlerine karşı koyabilen hibrit bir mobil veri güvenlik yazılımı (Android/Java) ve iletişim protokolü geliştirmektir. Proje, %100 saf yazılım ve ileri matematik mühendisliğine dayanmakta olup, donanım veya yapay zeka barındırmaz.
**Anahtar Kelimeler:** Kuantum Sonrası Kriptografi (PQC), Siber Güvenlik, Hibrit Şifreleme, Kafes Tabanlı Kriptografi, Veri Güvenliği.

### Projenin Amaç ve Hedefleri
*   **Amaç:** Klasik bilgisayarlarda çalışabilen, ancak kuantum bilgisayarların algalgoritmik gücüyle dahi kırılamayan matematiksel yapılara sahip güvenli bir dosya ve mesajlaşma protokolü oluşturmak.
*   **Hedefler:**
    1. Açık kaynaklı PQC (Post-Quantum Cryptography) kütüphanelerini mobil ve web mimarisine entegre etmek.
    2. Kuantum anahtarlarının boyut büyüklüğünden kaynaklanan performans kaybını önlemek için AES-256 ile çalışan bir "Hibrit Şifreleme Mimarisini" başarıyla kodlamak.
    3. Kurumların ve bireylerin kritik verilerini sızdırmaz bir "Kuantum Kasasında (Vault)" tutabileceği Android mobil arayüzünü geliştirmek.

### Projenin Yenilikçi Yönü (Özgün Değeri)
1.  **Geleceğe Dayanıklılık:** Sistem sadece bugünün değil, 10 yıl sonrasının "Kuantum" tehditlerine karşı şimdiden bağışıklık kazanmıştır.
2.  **Hibrit Mimari Tasarımı:** Kuantum algoritmaları çok güvenli olsa da yavaştır. Q-Shield, verinin kendisini hızlı (AES-256) algoritmalarla, bu kilidin anahtarını ise Kuantum algoritmalarıyla şifreleyerek performanstan ödün vermeden güvenlik sağlar.
3.  **Bağımsız (Standalone) Protokol:** Sistemin bir SDK/API mimarisiyle kodlanması sayesinde, diğer yazılım firmaları kendi uygulamalarını Q-Shield ile kuantum güvenli hale getirebilir.

### Ticari Potansiyeli ve İhtiyaç Durumu
Küresel olarak finans kurumları, ordular ve sağlık sektörü "Kuantum Felaketine (Quantum Apocalypse)" karşı altyapılarını değiştirmek üzere milyarlarca dolarlık bütçeler ayırmaktadır. Geliştirilen bu yazılım protokolü ve mobil kasa uygulaması, özellikle kurumsal iletişim, bankacılık ve askeri/endüstriyel casusluktan korunma alanlarında çok yüksek ticari değere ve doğrudan "Derin Teknoloji (Deep Tech) Start-up" potansiyeline sahiptir.

### Projenin Hedef Pazarı veya Etki Alanı
*   **Finans ve Bankacılık Sektörü:** Müşteri verilerini ve işlem geçmişlerini kuantum saldırılarından korumak isteyen finansal kuruluşlar.
*   **Kamu ve Savunma Sanayii:** Gizlilik derecesi yüksek askeri planların ve devlet sırlarının iletimi.
*   **Yazılım Ekosistemi (B2B):** Kendi uygulamalarına kuantum güvenliği katmak isteyen diğer yazılım şirketleri (API pazarı).

### Projenin Yöntemi
Proje, Java/Kotlin (Android) ve C/C++ (Çekirdek Şifreleme) kullanılarak 3 katmanlı bir mimariyle geliştirilecektir.
1. **Anahtar Kapsülleme Mekanizması (KEM):** Cihazlar arası güvenli anahtar takası NIST standartlarındaki CRYSTALS-Kyber algoritması ile yapılacaktır.
2. **Hibrit Şifreleme Modülü:** Cihaz tarafında (Client-side) dosya AES-GCM ile şifrelenecek, AES anahtarı Kyber ile sarmalanacaktır (Enveloping).
3. **Mobil Uygulama Entegrasyonu:** Kullanıcıların dosyalarını yükleyip Kuantum şifreli biçimde depolayabildiği veya karşı tarafa güvenle iletebildiği Android arayüzü yazılacaktır.

### Projenin Yapılabilirliği ve Sürdürülebilirliği
Proje, tamamen açık kaynaklı matematiksel kütüphanelerin (Örn: Open Quantum Safe projesi) üzerine inşa edilecek saf bir yazılım geliştirme sürecidir. Özel bir donanıma, Kuantum bilgisayara veya bulut AI altyapısına ihtiyaç duymadığı için standart bilgisayarlarla geliştirilebilir ve hemen ticarileştirilebilir. Yeni kriptografik algoritmalar çıktıkça güncellenebilecek "Çevik (Agile)" bir kod mimarisine sahip olacaktır.

### Tahmini Proje Bütçesi ve Gerekçesi
*   **Geliştirme ve Test Cihazları/Ortamları:** 15.000 TL
*   **Sızma Testleri (Pentest) ve Kriptografik Denetim (Audit) Araçları:** 20.000 TL
*   **Protokolün Bulut Sunucu Röle Giderleri (Yıllık):** 10.000 TL
*   **Toplam Tahmini Bütçe:** 45.000 TL (Yazılım Ar-Ge'si ve siber güvenlik doğrulama süreçleri için).

### Proje Çıktıları ve Kazanımlar
*   **Bilimsel Çıktı:** Mobil platformlarda kuantum sonrası kriptografik algoritmaların performans analizini içeren akademik makale çıktısı.
*   **Ekonomik Fayda:** Ülkemizin siber güvenlik altyapısında dışa bağımlılığı azaltacak yerli ve milli bir şifreleme protokolü girişimi.
*   **Sosyal Fayda:** HNDL saldırılarına karşı toplumsal ve kişisel verilerin mahremiyetini garanti altına alma.

### Referanslar
1. National Institute of Standards and Technology (NIST). (2022). Post-Quantum Cryptography Standardization.
2. Mosca, M. (2018). Cybersecurity in an era with quantum computers: Will we be ready? IEEE Security & Privacy.
