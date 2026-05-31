import customtkinter
import threading
import proje 
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import os
import sys

def uygulama_kapat():
    print("\n[!] Sistemden çıkış yapılıyor...")
    try:
        app.withdraw() # Pencereyi gizle
        app.quit()     # Döngüyü durdur
    except:
        pass
    os._exit(0) # İşletim sistemi seviyesinde bu Python sürecini öldür

app = customtkinter.CTk() # app uygulama arayüzü
app.geometry("800x800") 
app.title("Ağ Tarama ve Analiz Aracı")
customtkinter.set_appearance_mode("Dark")

# Başlık labeli düzenleme 
baslik_label = customtkinter.CTkLabel(app, text="Ağ Analizi ve Tehdit Tespit Sistemi ", font=("Arial", 24, "bold"))
baslik_label.pack(pady=10) # pack labelı forma ekler pady=padding

# Görsel alarm kısmı düzenleme
alarm_frame = customtkinter.CTkFrame(app, fg_color="transparent")
alarm_frame.pack(fill="x", padx=20, pady=5) # içi boş gözükmesin dolu göster

alarm_label = customtkinter.CTkLabel(alarm_frame, text="Ağ Trafiği Normal", font=("Arial", 16, "bold"), text_color="green")
alarm_label.pack()

# ANLIK AĞ YOĞUNLUĞU GRAFİĞİ
grafik_frame = customtkinter.CTkFrame(app)
grafik_frame.pack(pady=10, padx=20, fill="x") # grafik

# Matplotlib Ayarları

grafik_figur, eksen = plt.subplots(figsize=(7, 2), dpi=100) 
# plt.subplots() = hem bir figür (grafik alanı) hem de eksen (çizim alanı) oluşturur
grafik_figur.patch.set_facecolor('#2b2b2b') # grafik alanı arkaplan
eksen.set_facecolor("#2b2b2b") # eksen çizim alanı arka plan rengi
eksen.tick_params(colors='white') # x ve y eksenlerinde çizgi sayıları vs rengi
for cerceve in eksen.spines.values(): #
    cerceve.set_edgecolor('white') #kenar çizgileri rengi ayarlama

eksen.set_title("Anlık Paket Yoğunluğu (Son 20 Saniye)", color='white') # grafik başlığı

cizgi, = eksen.plot(proje.wlan0_paket_sayisi, color='cyan', linewidth=2)  #eksen.plot() → verileri grafiğe çiz
# proje.wlan0_paket_sayisi → 20 saniyelik paket sayısı verisi
eksen.set_ylim(0, 100) # Y ekseni limiti (dinamik olarak güncellenecek)

canvas = FigureCanvasTkAgg(grafik_figur, master=grafik_frame) # grafiği tkinterda gösterme. master grafiği tkinterda hangi alana
canvas.get_tk_widget().pack(pady=10) # canvası tkinter widgetine dönüştür

# KAYDIRILABİLİR SONUÇ EKRANI
sonuc_frame = customtkinter.CTkScrollableFrame(app, label_text="Aktif Cihazlar (IP | MAC | ÜRETİCİ)", width=700, height=250)
sonuc_frame.pack(pady=10)

durum_label = customtkinter.CTkLabel(app, text="Hazır. Tarama başlatmak için tıklayın.", text_color="gray")
durum_label.pack(pady=5)

# Fonksiyonlar
def arayuzu_guncelle():
    if not app.winfo_exists():  # Pencere kapandıysa döngüyü anında durdur
        return
        
    try:
        veri = proje.wlan0_paket_sayisi
        cizgi.set_ydata(veri)   # Grafiği Güncelle
        
        # Y eksenini dinamik olarak ayarla
        max_paket = max(veri) if max(veri) > 100 else 100
        eksen.set_ylim(0, max_paket + 20)
        
        canvas.draw()

        # Alarm sistemi
        if proje.alarm_aktif:
            alarm_label.configure(text=proje.son_durum_mesaji, text_color="red")
            alarm_frame.configure(fg_color="#4a0000") 
        else:
            alarm_label.configure(text=proje.son_durum_mesaji, text_color="green")
            alarm_frame.configure(fg_color="transparent")

        # Saniyede bir kendini tekrar çağır
        app.after(1000, arayuzu_guncelle)
        
    except Exception:
        pass    # Uygulama kapanırken son milisaniyede oluşabilecek grafik hatalarını yut

def tarama_calistir():
    for widget in sonuc_frame.winfo_children():
        widget.destroy()

    durum_label.configure(text="Tarama yapılıyor... (Cihazlar bulundukça eklenecek)", text_color="yellow")
    buton_tarama.configure(state="disabled")

    def ekrana_yazdir(cihaz):
        if not app.winfo_exists(): # Pencere yoksa işlem yapma
            return
        satir = f"IP: {cihaz['ip']:<16} MAC: {cihaz['mac']:<18} Üretici: {cihaz['vendor']}"
        item_label = customtkinter.CTkLabel(sonuc_frame, text=satir, font=("Courier", 12))
        item_label.pack(pady=2, anchor="w")

    def canli_guncelle(cihaz):
        app.after(0, ekrana_yazdir, cihaz)

    try:
        proje.tarama_baslat(yeni_cihaz_callback=canli_guncelle)
        durum_label.configure(text="İşlem tamam. Kayıtlar cihazlar.json ve ag_log.txt dosyasına yazıldı.", text_color="green")
    except Exception as e:
        durum_label.configure(text=f"Hata: {e}", text_color="red") 

    buton_tarama.configure(state="normal")

def start_scan():
    threading.Thread(target=tarama_calistir, daemon=True).start()

buton_tarama = customtkinter.CTkButton(app, text="Ağ Taramasını Başlat", command=start_scan, width=200, height=40)
buton_tarama.pack(pady=10)

proje.dinleme_baslat() # Arka planda paket dinlemeyi ve grafiği başlat
arayuzu_guncelle()


app.protocol("WM_DELETE_WINDOW", uygulama_kapat)
app.mainloop()
