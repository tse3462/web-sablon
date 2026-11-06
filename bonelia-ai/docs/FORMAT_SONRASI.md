# Format öncesi yedek, format sonrası tek tıkla kurulum

Program GitHub'da durur; **sunucunun verisi durmaz**. Format atmadan önce bir kez yedek alın.

## Format ÖNCESİ (ev bilgisayarı)
1. Bir USB bellek takın.
2. `deployment\windows\BONELIA-Yedekle.bat` dosyasına çift tıklayın ("Ja/Yes" deyin).
3. USB'de `BONELIA-Yedek` klasörü oluşur. İçinde:
   - `sunucu-TARİH` klasörü — sunucunun anahtarı, veritabanı (müşteriler, bilgisayarlar, Kasa, ayarlar),
     panel anahtarı, `server.home.toml` ve bu bilgisayarın Tailscale kimliği; her dosya SHA-256 ile kontrol edilir.
   - `BONELIA-Format-Sonrasi-Kur.bat` — format sonrası çift tıklanacak dosya.
   Son 5 yedek tutulur, eskileri kendiliğinden silinir.

**Dikkat:** yedekte sunucunun anahtarı var. USB'yi güvenli yerde saklayın; buluta / e-postaya koymayın.

## Format SONRASI
1. Windows'u kurun, internete bağlanın, USB'yi takın.
2. USB'deki `BONELIA-Yedek\BONELIA-Format-Sonrasi-Kur.bat` dosyasına çift tıklayın ("Ja/Yes").
3. Kendiliğinden yapılanlar:
   1. En yeni yedeği bulur ve her dosyayı kontrol eder (bozuk yedek asla kullanılmaz).
   2. Git, Python, Tailscale, RustDesk, Ollama'yı kurar (winget; olanları atlar).
   3. Tailscale kimliğini geri koyar → müşteri bilgisayarları sunucuyu **aynı adreste** bulur.
   4. BONELIA AI'yı GitHub'dan eski klasörüne indirir.
   5. Sunucu verisini geri koyar (sunucu başlamadan önce; böylece yeni anahtar üretilmez).
   6. Python ortamını kurar, gizli otomatik başlatmayı ayarlar, sunucu + telefon panelini başlatır.
   7. Yapay zekâ modelini indirir; bu bilgisayarın ajanını yeniden kaydeder (eski kaydı iptal eder).
4. Ekranın sonunda "Elle bakılacaklar" listesi varsa onlara bakın (ör. Tailscale'in bağlı olduğu).

Müşteri bilgisayarlarına hiçbir şey yapılmaz. Telefondaki panel adresi aynı kalır.
RustDesk bu bilgisayarda yeni bir ID alır; Kasa'daki şifresini ajan birkaç dakika içinde kendisi yeniler.

## Yedek yoksa
Script sorar; devam edilirse yeni ve boş bir sunucu kurulur — bu durumda bütün müşteri bilgisayarlarına USB ile
yeniden kurulum gerekir. Bu yüzden format öncesi yedek şarttır.
