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

## Her bilgisayarda bir kez (USB ile)
1. USB'yi takın, **Bu-Bilgisayara-Kur.bat** dosyasına çift tıklayın, Windows'un yönetici sorusuna **Evet** deyin.
2. USB parolasını girin. Bitti; USB'yi çıkarabilirsiniz.

Agent, Windows açılınca **SYSTEM** hesabıyla arka planda başlar (pencere yok), 5 dakikada bir tarar:
* yeni **Önemli / Kontrol edin** bulgularını sunucuya gönderir (yapay zekâ analizi),
* güvenli onarımları yapar ve sonucu bağımsız olarak doğrular,
* her işlemi sunucunun denetim kaydına yazar.

Agent'ın kendi kimliği vardır (USB'den bağımsız, sunucuda ayrı cihaz). Anahtarı Windows DPAPI ile o bilgisayara bağlı
şifrelenir; dosya başka bir bilgisayara kopyalanırsa işe yaramaz.

## Evden takip
```bat
bonelia-server --config deployment\server.home.toml alerts --hours 24
```
Son 24 saatteki önemli bulguları ve yapılan/reddedilen onarımları gösterir.

## Kaldırma
USB'deki **Bu-Bilgisayardan-Kaldir.bat** (veya `BoneliaAI-Konsol.exe agent-uninstall`), sonra sunucuda
`bonelia-server revoke <device_id>`.

## Ağ
Agent'ın çalıştığı bilgisayar ev sunucusuna ulaşabilmelidir. Sunucu ile aynı bilgisayarda değilse
**Tailscale** her iki bilgisayara kurulmalı ve sunucu `host = "100.x.y.z"` ile başlatılmalıdır. Bağlantı yoksa agent
bulguları tekrar dener, **onarım yapmaz** (izin ve denetim sunucuda).
