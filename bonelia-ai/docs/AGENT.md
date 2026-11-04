# Sürekli izleme ve kendi kendine onarım (BONELİA AI Agent)

Amaç: Her küçük sorun için işletmeye gitmek zorunda kalmamak.

## Bir kez (ev sunucusunda)
```bat
bonelia-server --config deployment\server.home.toml allow-repairs ten_... --level 1 --include-devices
```
* `--level 1`: güvenli onarımlar kendiliğinden yapılır (ör. otomatik çalışması gereken ama durmuş bir hizmeti başlatmak).
* `--level 2`: ayrıca tekrar tekrar çöken hizmetler **kendiliğinden** yeniden başlatılır (sahibin kararı: kendi işletmeleri
  için tıklama onayı bir şey katmıyor). Saatte en fazla 2 kez; her çökme için bir kez; kritik Windows hizmetlerine dokunulmaz.
* `--include-devices`: bu müşterinin USB'lerine onarım ve "bilgisayara kur" yetkisi verir.

## Her bilgisayarda (USB ile, sessiz kurulum)
1. USB'yi takın, **Bu-Bilgisayara-Kur.bat** dosyasına çift tıklayın, Windows'un yönetici sorusuna **Evet** deyin.
2. **Yalnızca ilk seferde** USB parolası sorulur. Program USB'ye sınırlı bir **kurulum anahtarı** (`config/install.key`)
   kaydeder; sonraki bilgisayarlarda hiçbir şey sorulmaz.
3. Sonunda "kuruldu" mesajı çıkar; USB çıkarılabilir.

Kurulum anahtarı yalnızca bilgisayar kurabilir: müşteri verisini okuyamaz, onarım yapamaz. USB kaybolursa
`bonelia-server devices` ile anahtarı bulun ve `bonelia-server revoke <id>` ile iptal edin; kurulu bilgisayarlar
çalışmaya devam eder. Kurulu bilgisayarlar (agent) da yalnızca bulgu gönderir ve kendi bilgisayarını onarır;
başka verileri okuyamaz.

Agent, Windows açılınca **SYSTEM** hesabıyla arka planda başlar (pencere yok), 5 dakikada bir tarar:
* yeni **Önemli / Kontrol edin** bulgularını sunucuya gönderir (yapay zekâ analizi),
* güvenli onarımları yapar ve sonucu bağımsız olarak doğrular,
* **günde bir kez** düzenli bakım yapar (bir sorun oluşmasa da): geçici klasörlerdeki 7 günden
  eski dosyaları siler — yani "bilgisayar kendi diskini temizler". Bu da müşterinin onayından
  (seviye 1) geçer; onay yoksa yapılmaz.
* her işlemi sunucunun denetim kaydına yazar.

Agent'ın kendi kimliği vardır (USB'den bağımsız, sunucuda ayrı cihaz). Anahtarı Windows DPAPI ile o bilgisayara bağlı
şifrelenir; dosya başka bir bilgisayara kopyalanırsa işe yaramaz.

## Evden takip: Kontrol Paneli
Ana sayfa bir bakışta durumu gösterir: büyük yazıyla **HER ŞEY TAMAM** (yeşil), **N ÖNEMLİ SORUN** (sarı)
veya **N BİLGİSAYAR SESSİZ** (kırmızı); altında Durum / Bilgisayarlar / Onarımlar / Bildirimler / Müşteriler
kutuları ve **Uygulamalarım**: kendi programlarınızın ve admin panellerinizin adresleri, tek dokunuşla açılır
(Düzenle → ekle / düzenle / sırala / sil). Uygulamalarım yalnızca **adres** tutar, şifre tutmaz; giriş her
programın kendi sayfasında yapılır. Saatler telefonun yerel saatiyle gösterilir. Telefonda menü alttadır.

`deployment\windows\BONELIA-Kontrol-Paneli.bat` dosyasına çift tıklayın. Tarayıcıda (yalnızca bu bilgisayarda) açılır:
* **Genel bakış:** müşteri sayısı, çevrimiçi bilgisayarlar, son 24 saatteki önemli sorunlar, son 7 gündeki onarımlar
* **Bilgisayarlar:** çevrimiçi (yeşil) / sinyal yok (kırmızı, 15 dakikadan uzun), son durum;
  **Yedek** (bu bilgisayarın yedek klasörü), **İptal et**, **Sil**
* **Sorunlar:** önemli (isteğe bağlı "kontrol edin") bulgular ve yapay zekânın açıklaması
* **Onarımlar:** ne yapıldı, doğrulandı mı, neyin izni yoktu
* **Müşteriler:** onarım izni seviyesi (0 / 1 / 2) tek tıkla
* **Ayarlar:** telefona Telegram bildirimi (aşağıya bakın)

Komutla: `bonelia-server --config deployment\server.home.toml alerts --hours 24`.

## Kendi kendine yapılan onarımlar (seviye 1)
| Durum | Onarım | Doğrulama |
|---|---|---|
| Otomatik çalışması gereken hizmet durmuş | hizmeti başlat | hizmet "running" |
| DNS ad çözümleme zaman aşımı | DNS önbelleğini temizle | DNS sorgusu çalışıyor |
| Sistem diski %90+ dolu | 7 günden eski geçici dosyaları sil | eski geçici dosya kalmadı (kullanımdakiler hariç) |
| Düzenli bakım (günde bir, sorun beklenmeden) | 7 günden eski geçici dosyaları sil | eski geçici dosya kalmadı (kullanımdakiler hariç) |

## Disk sağlığı ve yedek kontrolü (sadece okur, uyarır)
Ajan bunları kendiliğinden kontrol eder; bir şey **onarmaz** (bozuk disk veya eksik yedek bir insan ister),
ama **önemli** bulgu olarak panele ve telefona bildirir:

| Kontrol | Ne zaman uyarır |
|---|---|
| Disk sağlığı (Windows / SMART) | disk "Uyarı/Sağlıksız", SMART arıza öngörüsü, düzeltilemeyen okuma/yazma hataları, SSD ömrü %90+ |
| Disk erken uyarı (sadece panel) | SSD ömrü %80+, disk 65 °C üstü |
| Yedek klasörü | klasör yok (harici disk takılı değil), klasör boş, son yedek sınırdan eski (varsayılan 2 gün) |
| Windows yedeği | son başarılı yedek 8 günden eski, ya da hiç başarılı olmamış |
| Hiç yedek yok (sadece panel) | ne klasör tanımlı ne Windows yedeği var |

Yedek klasörünü panelde **Bilgisayarlar → Yedek** ile her bilgisayar için ayrı tanımlayın
(ör. `D:\Kasa\Yedek`, `E:\` veya `\\NAS\yedek`). Ayar bir sonraki döngüde (≈5 dk) ajana ulaşır.
Ajan yalnızca dosyaların **tarihlerine** bakar, içeriklerini okumaz. Disk sağlığı 6 saatte, yedekler saatte bir kontrol edilir.

Bir sorun çözülüp sonra **tekrar** oluşursa yeniden bildirilir.

## Her açılışta otomatik (sunucu + panel)
Bir kez `deployment\windows\BONELIA-Kur-Otomatik.bat` dosyasına çift tıklayın: ev sunucusu ve telefon paneli
bilgisayar her açıldığında arka planda birlikte başlar. Elle başlatmak için `BONELIA-Baslat.bat`.

## Bildirimler
Ev bilgisayarınızda Windows bildirimi (`deployment\server.home.toml` → `[notify] windows_toast = true`):
* ⚠ önemli sorun bulundu (aynı sorun 6 saatte bir kez)
* ✅ onarıldı / ❌ onarım başarısız
* 🔒 bir onarım için izin gerekli (ör. müşteri seviye 1'de, hizmet yeniden başlatma gerekiyor)
* 📴 bir bilgisayar 30 dakikadır sinyal vermiyor

### Telefona Telegram (tamamen panelden, telefonla)
1. Telegram'da **@BotFather** → `/newbot` → bota bir ad verin (sonu `bot` ile bitmeli). Size bir **anahtar (token)** verir.
2. Panel → **Ayarlar** → anahtarı yapıştırın → **Kaydet**.
3. Telegram'da kendi botunuzu açıp **Başlat**'a basın (veya bir mesaj yazın) → panelde **Bağla**.
4. Bota "bildirimler artık bu sohbete gelecek" mesajı gelir. **Test mesajı gönder** ile istediğiniz zaman deneyin.

Yeniden başlatma veya komut gerekmez; sunucu bir sonraki bildirimden itibaren kullanır. Anahtar ev sunucusunun
veritabanında saklanır ve panel onu bir daha göstermez. Kapatmak için **Bildirimleri kapat**.
(Eski yöntem — `BONELIA_TELEGRAM_BOT_TOKEN` + `[notify] telegram_chat_id` — hâlâ çalışır.)

## Güncelleme (işletmelere gitmeden)
Yeni sürümün USB paketini indirdikten sonra ev bilgisayarında:
```bat
bonelia-server --config deployment\server.home.toml publish-agent G:\BONELIA-AI-Portable\BoneliaAI-Konsol.exe
```
Kurulu bilgisayarlar yaklaşık 15 dakika içinde yeni sürümü indirir, **sunucunuzun imzasını doğrular** ve kendini
yeniler. İmzası tutmayan bir dosya kurulmaz.

## Kaldırma
USB'deki **Bu-Bilgisayardan-Kaldir.bat** (veya `BoneliaAI-Konsol.exe agent-uninstall`), sonra sunucuda
`bonelia-server revoke <device_id>`.

## Ağ: diğer bilgisayarlar evdeki sunucuya Tailscale ile ulaşır
Bir kez (evde):
1. Ev bilgisayarına Tailscale kurun, Tailscale adresini (`100.x.y.z`) öğrenin.
2. `deployment\server.home.toml` içinde `host = "100.x.y.z"` yapın, sunucuyu yeniden başlatın.
3. USB'de `config\settings.json` içine `"agent_server_url": "http://100.x.y.z:8742"` ekleyin.
4. Tailscale yönetim panelinde **yeniden kullanılabilir, etiketli** bir auth key oluşturun ve
   USB'de `config\tailscale-authkey.txt` dosyasına yazın. Tailscale ACL ile etiketli cihazların yalnızca
   `100.x.y.z:8742` adresine erişmesine izin verin.
5. Tailscale Windows MSI kurulum dosyasını USB'deki `tailscale\` klasörüne koyun.

Bundan sonra **Bu-Bilgisayara-Kur.bat** Tailscale'i de sessizce kurar ve bağlar. Bağlantı yoksa agent bulguları
tekrar dener, **onarım yapmaz** (izin ve denetim sunucuda). Auth key dosyası USB'de şifresizdir; USB kaybolursa
anahtarı Tailscale panelinden iptal edin.
