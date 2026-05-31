# Network Scanner
 
### Özellikler
* **ARP Tarama:** Scapy kütüphanesini kullanarak yerel ağdaki cihazlara ARP istekleri gönderir.
* **Otomatik Ağ Tespiti:** Sistemin mevcut ağ aralığını otomatik olarak belirler.
* **Üretici Bilgisi:** MAC adreslerini MacVendors API'si üzerinden sorgulayarak cihazın üretici bilgisini raporlar.
* **Trafik Analizi:** Ağdaki paket yoğunluğunu takip eder ve anlık trafik grafikleri oluşturur.
* **Masaüstü Kullanıcı Arayüzü (GUI):** Tüm verilerin tablo ve grafiklerle kullanıcı dostu bir arayüzde gösterilmesini sağlar.

---

Projeyi çalıştırmak için sisteminizde Python ve gerekli kütüphanelerin yüklü olması gerekir.

### Eklenecek Özellikler (Geliştirme Aşaması)

#### Saldırı Tespit Sistemi:
* Ping taramalarını tespit etme.
* Ağ trafiği belirlenen limitleri aştığında kullanıcıyı uyarma.

#### Masaüstü Kullanıcı Arayüzü (GUI) Geliştirmeleri:
* Şüpheli hareketler için arayüz üzerinden uyarı sistemi verilmesi.
