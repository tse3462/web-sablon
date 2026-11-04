# Sürekli izleme ve kendi kendine onarım (BONELİA AI Agent)

Amaç: Her küçük sorun için işletmeye gitmek zorunda kalmamak.

## Bir kez (ev sunucusunda)
```bat
bonelia-server --config deployment\server.home.toml allow-repairs ten_... --level 1 --include-devices
```
* `--level 1`: güvenli onarımlar kendiliğinden yapılır (ör. otomatik çalışması gereken ama durmuş bir hizmeti başlatmak).
* `--level 2`: ayrıca "hizmeti yeniden başlat" ekranda tek tıkla yapılabilir. Agent seviye-2 işlemleri **kendi başına yapmaz**,
  sunucuya uyarı olarak bildirir.
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
* her işlemi sunucunun denetim kaydına yazar.

Agent'ın kendi kimliği vardır (USB'den bağımsız, sunucuda ayrı cihaz). Anahtarı Windows DPAPI ile o bilgisayara bağlı
şifrelenir; dosya başka bir bilgisayara kopyalanırsa işe yaramaz.

## Evden takip: Kontrol Paneli
`deployment\windows\BONELIA-Kontrol-Paneli.bat` dosyasına çift tıklayın. Tarayıcıda (yalnızca bu bilgisayarda) açılır:
* **Genel bakış:** müşteri sayısı, çevrimiçi bilgisayarlar, son 24 saatteki önemli sorunlar, son 7 gündeki onarımlar
* **Bilgisayarlar:** çevrimiçi (yeşil) / sinyal yok (kırmızı, 15 dakikadan uzun), son durum; **İptal et**
* **Sorunlar:** önemli (isteğe bağlı "kontrol edin") bulgular ve yapay zekânın açıklaması
* **Onarımlar:** ne yapıldı, doğrulandı mı, neyin izni yoktu
* **Müşteriler:** onarım izni seviyesi (0 / 1 / 2) tek tıkla

Komutla: `bonelia-server --config deployment\server.home.toml alerts --hours 24`.

## Kendi kendine yapılan onarımlar (seviye 1)
| Durum | Onarım | Doğrulama |
|---|---|---|
| Otomatik çalışması gereken hizmet durmuş | hizmeti başlat | hizmet "running" |
| DNS ad çözümleme zaman aşımı | DNS önbelleğini temizle | DNS sorgusu çalışıyor |
| Sistem diski %90+ dolu | 7 günden eski geçici dosyaları sil | eski geçici dosya kalmadı (kullanımdakiler hariç) |

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
