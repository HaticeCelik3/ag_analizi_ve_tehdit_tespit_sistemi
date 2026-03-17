
#Ağ Tarama Uygulaması - Siber Güvenlik Ödevi
#Yerel ağdaki cihazları tarar ve MAC adreslerinden üretici bilgilerini çeker.

import scapy.all as scapy
import subprocess
import requests 
import time


def uretici_bul(mac_adresi):
    api_url = f"https://api.macvendors.com/{mac_adresi}"
    try:
        response = requests.get(api_url, timeout=5)
        if response.status_code == 200:
            return response.text
        elif response.status_code == 429:
            return "API Limiti (Bekleyin)"
        else:
            return "Bilinmeyen Cihaz"
    except Exception:
        return "Bağlantı Hatası"


def ag_araligini_bul():
    try:
        route_output = subprocess.check_output(["ip", "route"]).decode()
        for line in route_output.split('\n'):
            if 'default via' not in line and '/' in line:
                return line.split()[0]
    except:
        return "192.168.1.1/24"



hedef_ag = ag_araligini_bul()
print(f"[*] Tespit edilen ağ aralığı: {hedef_ag}")

arp_istegi = scapy.ARP(pdst=hedef_ag)
yayim_paketi = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
birlesik_paket = yayim_paketi/arp_istegi

print("[*] Tarama yapılıyor ve üretici bilgileri çekiliyor...\n")
cevaplar = scapy.srp(birlesik_paket, timeout=2, verbose=False)[0]

print("IP Adresi\t\tMAC Adresi\t\tÜretici")
print("-" * 75)

for eleman in cevaplar:
    ip = eleman[1].psrc
    mac = eleman[1].hwsrc
    
  
    vendor = uretici_bul(mac)
   
    print(f"{ip}\t\t{mac}\t\t{vendor}")
  
    time.sleep(1.2)

print("\n[*] İşlem başarıyla tamamlandı.")