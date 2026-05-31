# ağ tarama
from scapy.all import sniff 
import scapy.all as scapy
import subprocess # işletim sisteminde komut çaliştırabilmek için(ip config, ip route) gerekli kütüphane
import requests # internetten veri çekmek için 
import time
import threading # aynı anda birden fazla iş yapabilmek için 
import json
import logging 
import platform # hangi işletim sistemide olduğumuzu öğrenmek için
import os # dosya klasör kontrolü
import webbrowser # Linke tıklayınca tarayıcıyı açmak için
import platform
from tkinter import messagebox # küçük uyarı penceresi için

# Log ayarları
logging.basicConfig(filename="ag_log.txt", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


wlan0_paket_sayisi = [0] * 20 # son 20 saniyede gelen paket sayısı 
son_durum_mesaji = ""
alarm_aktif = False
anlik_ping_sayisi = 0

# npcap kontrolü
def npcap_kontrol(): # windowsta ağ paketlerini yakalamak için gerekli
    if platform.system() == "Windows": 
        npcap_path = r"C:\Windows\System32\Npcap" # windows işletim sistemi kullanıyorsa varsayılan konumunda olup olmadığına bakılır
        
        if not os.path.exists(npcap_path):
            cevap = messagebox.askyesno(
                "Npcap Sürücüsü Eksik", 
                "Uygulamanın çalışması için Npcap sürücüsü gereklidir.\n\n"
                "Şimdi indirme sayfasına gitmek ister misiniz?"
            )
            
            if cevap: # Eğer 'Evet' derse
                webbrowser.open("https://npcap.com/#download")
            
            # Sürücü olmadan uygulama düzgün çalışmayacağı için bilgilendirip kapatabiliriz
            messagebox.showinfo("Bilgi", "Lütfen Npcap yükledikten sonra uygulamayı yeniden başlatın.")
            return False
    return True

if not npcap_kontrol(): # npcap_kontrol true ise bu kısım false çalışmadan ilerler 
    exit() # eğer npcap_kontrol false ise bu kısım çalışır ve kullanıcı yüklemediyse uygulamayı başlatma

# AĞ BİLGİLERİNİ GETİR
def ag_bilgilerini_getir():
    isletim_sistemi = platform.system() # işletim sistemi öğrenme
    aktif_arayuz = None #aktif ip
    ag_araligi = "192.168.1.0/24"
    try:
        if isletim_sistemi == "Linux":
            routes = subprocess.check_output(["ip", "route"]).decode().split('\n') #
            for line in routes:
                if line.startswith("default"):
                    aktif_arayuz = line.split()[4]  # ["default", "via", "192.168.1.1", "dev", "wlan0"] 4. elemanı alma
                    break
            for line in routes:
                if aktif_arayuz and aktif_arayuz in line and '/' in line and 'default' not in line:
                    ag_araligi = line.split()[0] # 192.168.1.0/24 dev wlan0 proto kernel bu çıktıdan ilk elemanı
                    break 
                    
        elif isletim_sistemi == "Windows":
            # conf.iface genellikle aktif olan kartı (Wi-Fi/Ethernet) otomatik seçer
            aktif_arayuz = scapy.conf.iface
            # Windows'ta alt ağı (subnet) bulmak için ipconfig kontrolü
            ipconfig = subprocess.check_output("ipconfig").decode(encoding='cp850')
            for line in ipconfig.split('\n'):
                if "IPv4 Address" in line or "IPv4 Adresi" in line:
                    # 192.168.1.15 -> 192.168.1.0/24 formatına çevirir
                    ip_parcalari = line.split(':')[-1].strip().split('.') # strip boşlukları siler. split (.) ya göre parçalar
                    ()
                    # IPv4 Address . . . . . . . . . . : 192.168.1.15 şekindeki çıktıyı (:)' dan böler -1. elemanı yani ip'yi alır
                    if len(ip_parcalari) == 4:
                        ag_araligi = f"{ip_parcalari[0]}.{ip_parcalari[1]}.{ip_parcalari[2]}.0/24" #ip parçalarını birleştirir ip aralığı oluşturur
                        break
    except Exception as e: 
        print(f"Sistem bilgisi alınırken hata oluştu: {e}")
    return aktif_arayuz, ag_araligi

# Program başlarken bu bilgileri bir kez alıyoruz
aktif_arayuz, HEDEF_AG = ag_bilgilerini_getir() # çoklu atama

# ÜRETİCİ MAC BULMA
def uretici_bul(mac_adresi):
    api_url = f"https://api.macvendors.com/{mac_adresi}"
    try:
        cevap = requests.get(api_url, timeout=5) # api_url'den request.get sayesinde veri çekeriz 
        #status code: sunucunun verdiği cevap kodu
        #404;bulunamadı , 500;sunucu hatası
        if cevap.status_code == 200:  # 200 = başarılı
            return cevap.text
        elif cevap.status_code == 429: # 429 =çok fazla istek
            return "API Limiti (Bekleyin)"
        else:
            return "Bilinmeyen Cihaz"
    except Exception:
        return "Bağlantı Hatası"

# PİNG TESPİTİ
def paket_analiz(paket):
    global anlik_ping_sayisi
    if paket.haslayer(scapy.ICMP): # gelen paketin ıcmp olup olmadığını kontrol eder
        anlik_ping_sayisi += 1  # daha önce tanımlanmış ping sayısı değişkenini etkiler 
        # bu kısımlar tehdit tespit sistemi eklendiğinde güncellenecek


# PAKET SAYMA YAZDIRMA
def paket_sayma():
    global anlik_ping_sayisi, son_durum_mesaji, alarm_aktif
    while True:
        anlik_ping_sayisi = 0
        try:
            gelen_paketler = sniff(timeout=1, iface=aktif_arayuz, filter="not arp", prn=paket_analiz) #prn = paket analizi
            toplam_paket = len(gelen_paketler)
            
            wlan0_paket_sayisi.pop(0) # ilk elemanı silme eski veriyi sil
            wlan0_paket_sayisi.append(toplam_paket) # yenisini ekle

            if anlik_ping_sayisi > 15:
                alarm_aktif = True
                son_durum_mesaji = f"DİKKAT: Olası Ping Taraması Tespit Edildi! ({anlik_ping_sayisi} Ping/sn)"
                logging.warning(son_durum_mesaji) 
            elif toplam_paket > 500:
                alarm_aktif = True
                son_durum_mesaji = f"DİKKAT: Anormal Ağ Yoğunluğu! ({toplam_paket} Paket/sn)"
                logging.warning(son_durum_mesaji)
            else:
                alarm_aktif = False
                son_durum_mesaji = f"Ağ Trafiği Normal ({toplam_paket} Paket/sn)"

        except Exception:
            pass 

def dinleme_baslat():
    threading.Thread(target=paket_sayma, daemon=True).start() # paket sayma fonksiyonunnu sürekli hale getirdik

# ANA TARAMA FONKSİYONU
def tarama_baslat(yeni_cihaz_callback=None): # bulunan cihazları anlık olarak bir başka fonksiyona bildirmek için kullanılır
    arp_istegi = scapy.ARP(pdst=HEDEF_AG) # pdst(protocol destination)→ ARP paketinin hedef IP adresini belirten parametre 
    #Ether() → Ethernet çerçevesi oluşturmak için Scapy’de kullanılan sınıf ağ katmanı paketi
    #Ethernet çerçevesi içinde kaynak MAC, hedef MAC, tip (ARP, IP vb.) gibi bilgiler vardır
    yayim_paketi = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # bu Ethernet çerçevesini ağdaki tüm cihazlara gönder
    birlesik_paket = yayim_paketi/arp_istegi # eth+arp

    cevaplar = scapy.srp(birlesik_paket, timeout=3, iface=aktif_arayuz, verbose=False)[0] #[0] → sadece cevap veren cihazları alıyoruz
    # srp =Send + Receive Packet → “paketi gönder, cevabı al”

    cihazlar_listesi = []

    for eleman in cevaplar:
        ip = eleman[1].psrc
        mac = eleman[1].hwsrc
        vendor = uretici_bul(mac)

        cihaz = {"ip": ip, "mac": mac, "vendor": vendor}
        cihazlar_listesi.append(cihaz)
        
        if yeni_cihaz_callback: 
            yeni_cihaz_callback(cihaz)

        time.sleep(1.2) 

    # with otomatik kapatma. W: yoksa oluştur yazma modu. indent 4 okunabilirlik için
    with open("cihazlar.json", "w") as cihazlar_dosyasi:
        json.dump(cihazlar_listesi, cihazlar_dosyasi, indent=4)
        logging.info("Ağ taraması tamamlandı, cihazlar.json güncellendi.")

    return cihazlar_listesi

