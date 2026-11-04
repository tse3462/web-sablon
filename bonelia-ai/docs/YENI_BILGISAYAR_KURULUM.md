# Yeni iş yeri bilgisayarı kurulum çeklisti

Her yeni bilgisayara BONELİA kurmak = o bilgisayara **ajanı** (izleyen arka plan
programı) kurmak. Kurduğun an senin telefon panelinde görünür.

---

## A) Bir kerelik hazırlık (evde, USB'yi hazırlarken)

USB'ye şu iki şeyi koy:

1. **Tailscale kurulum dosyası** — `tailscale-setup-*.exe` (tailscale.com'dan bir kez indir).
2. **BONELİA hazır sürümü** — `BONELIA-AI-Portable` klasörü (içinde `BoneliaAI-Agent.exe`,
   `Bu-Bilgisayara-Kur.bat` vb.). Bu, kendi içinde Python'u olan sürümdür; o yüzden yeni
   bilgisayarlarda Python sorunu **çıkmaz**.

> Not: USB, senin ev sunucunun **Tailscale adresine** göre hazırlanır (bir kerelik ayar).
> Böylece USB'den kurulan her ajan doğrudan senin sunucuna bağlanır.

---

## B) Her yeni bilgisayarda (ilk sefer, sırayla)

**1. Tailscale (ağ bağlantısı — şart):**
- USB'deki `tailscale-setup-*.exe` → kur.
- **Kendi hesabınla** giriş yap.
- **"Run unattended / sürekli bağlı"** seçeneğini aç (biri çıkış yapsa bile bağlı kalsın).

**2. Güvenlik (kimse karıştırmasın):**
- Çalışanlar için **standart (yönetici olmayan)** Windows hesabı kullan.
- **Yönetici hesabına şifre** koy — sadece sende olsun.
- Böylece çalışan: Tailscale'i kaldıramaz, ajanı durduramaz, sistemi değiştiremez.

**3. BONELİA ajanı (tek tık):**
- USB'deki `Bu-Bilgisayara-Kur.bat` → çift tıkla → yönetici izni "Evet".
- Ajan **SYSTEM** olarak sessizce kurulur, sunucuna bağlanır, çalışmaya başlar.
- Kod/şifre girmene gerek yok (install key USB'de).

**4. Kontrol:**
- Telefonundaki panelde "Bilgisayarlar" listesine o bilgisayar düşer — online'sa **yeşil**.

---

## Bundan sonra (o bilgisayarda)

Tamamen otomatik, sen orada olmadan:
- Her açılışta kendiliğinden başlar.
- Sorunları bulur, güvenli onarımları yapar (hizmet başlatma, DNS, disk temizliği).
- Her gün geçici dosyaları temizler.
- Durumu + sorunları + onarımları telefon paneline raporlar.

Senin tek yapman: ara sıra **telefondan panele bakmak.**

---

## Özet (çok kısa)

| Adım | Ne |
|---|---|
| 1 | Tailscale kur + giriş + "sürekli bağlı" |
| 2 | Çalışan = standart hesap, yönetici = şifreli (sende) |
| 3 | USB'den `Bu-Bilgisayara-Kur.bat` → Evet |
| 4 | Telefon panelinde yeşil görünür |

Tek USB ile her iş yerine: tak → kur → bitti.
