# BONELİA AI v0.1 — Kabul testi (gerçek USB + gerçek yapay zekâ)

Bu belge, v0.1'in tamamlandı sayılması için gereken iki gerçek testi adım adım anlatır:
**A)** Ev bilgisayarında BONELİA AI Server + Ollama (yerel yapay zekâ), **B)** gerçek USB bellekle gerçek bir Windows bilgisayarda deneme.

Gerekenler: Windows 10/11 ev bilgisayarı (sunucu), bir USB bellek, bir test bilgisayarı (ilk deneme için ev bilgisayarının kendisi de olabilir).

---

## A. Ev bilgisayarı: BONELİA AI Server + yerel yapay zekâ

### A1. Gerekli programlar
1. **Python 3.12**: https://www.python.org/downloads/ → kurulumda **"Add python.exe to PATH"** kutusunu işaretleyin.
2. **Git**: https://git-scm.com/download/win (varsayılan ayarlarla kurun).

### A2. Kodu indirin ve kurun
Başlat menüsünde **"cmd"** yazıp Komut İstemi'ni açın ve sırayla yazın:
```bat
cd C:\
git clone https://github.com/tse3462/web-sablon
cd web-sablon
git checkout claude/bonelia-ai-architecture-z57jp0
cd bonelia-ai
py -3.12 -m venv .venv
.venv\Scripts\activate
pip install -e ".[server]"
```
Sonraki tüm sunucu komutları bu pencerede (`(.venv)` yazısı görünürken) çalıştırılır. Pencereyi kapatırsanız tekrar:
`cd C:\web-sablon\bonelia-ai` ve `.venv\Scripts\activate`.

### A3. Donanımı ölçün ve model seçin
```bat
mkdir C:\BoneliaAI
bonelia-server --data-dir C:\BoneliaAI\server-data hw-check
```
Çıktıdaki `recommended_local_model` satırına bakın (ör. `qwen2.5:7b-instruct` veya daha zayıf bilgisayarda `qwen2.5:3b-instruct`).

### A4. Ollama'yı kurun ve modeli indirin
1. https://ollama.com/download adresinden Windows sürümünü indirip kurun.
2. Yeni bir Komut İstemi'nde (A3'te önerilen modelle):
   ```bat
   ollama pull qwen2.5:7b-instruct
   ollama run qwen2.5:7b-instruct "Merhaba, kısa cevap ver."
   ```
   Bir cevap geliyorsa yerel yapay zekâ çalışıyor. İndirme birkaç GB'tır.
   Ekran kartı yoksa 7B model yavaş olabilir (bir analiz birkaç dakika sürebilir); o durumda 3B modeli seçin.

### A5. Sunucu ayar dosyası
```bat
copy deployment\server.example.toml C:\BoneliaAI\server.toml
notepad C:\BoneliaAI\server.toml
```
Kontrol edin / değiştirin:
* `data_dir = "C:/BoneliaAI/server-data"`
* `ollama_model = "qwen2.5:7b-instruct"` (A4'te indirdiğiniz modelin **tam** adı)
* İlk test aynı bilgisayardaysa `host = "127.0.0.1"` kalsın. Başka bir bilgisayardan bağlanacaksanız A7'ye bakın.

### A6. Sunucuyu başlatın
```bat
bonelia-server --config C:\BoneliaAI\server.toml serve
```
Bu pencere açık kalmalı. Tarayıcıda `http://127.0.0.1:8742/v1/health` açın: `"available": true` görünüyorsa sunucu modeli görüyor demektir.

### A7. (Başka bilgisayardan bağlanmak için) Tailscale
1. https://tailscale.com/download → ev bilgisayarına **ve** test bilgisayarına kurun, ikisinde de aynı hesapla giriş yapın.
2. Ev bilgisayarındaki Tailscale simgesinden `100.x.y.z` ile başlayan adresi öğrenin.
3. `server.toml` içinde `host = "100.x.y.z"` yazın, sunucuyu (A6) yeniden başlatın. Windows Güvenlik Duvarı sorarsa **Özel ağlar** için izin verin.

Sunucu, şifreleme olmadan internete açık bir adreste çalışmayı bilerek reddeder; Tailscale bağlantıyı şifreler.

### A8. Müşteri ve USB kayıt kodu oluşturun
İkinci bir Komut İstemi açın (A2'deki gibi `.venv\Scripts\activate`), sonra:
```bat
bonelia-server --config C:\BoneliaAI\server.toml tenant-add "Test Müşteri"
```
Çıkan `ten_...` değerini kopyalayın:
```bat
bonelia-server --config C:\BoneliaAI\server.toml enroll-code ten_BURAYA --scopes diagnose
```
Çıkan `ABCD-EFGH-...` kodunu not edin. **30 dakika** geçerlidir ve tek kullanımlıktır.

---

## B. USB bellek ile gerçek test

### B1. Paketi USB'ye koyun
1. GitHub'a giriş yapıp en son başarılı çalıştırmayı açın: https://github.com/tse3462/web-sablon/actions → "BONELIA AI" → en üstteki yeşil çalıştırma.
2. Sayfanın altındaki **Artifacts** bölümünden `BONELIA-AI-Portable-windows` dosyasını indirin (14 gün saklanır).
3. ZIP'i açın ve içindeki dosyaları USB'de `BONELIA-AI-Portable` adlı bir klasöre kopyalayın.

### B2. USB'yi kaydedin (yalnızca ilk kez)
1. Test bilgisayarında USB'deki `BONELIA-AI-Portable` klasörünü açın.
2. Klasörün adres çubuğuna `cmd` yazıp Enter'a basın (o klasörde Komut İstemi açılır).
3. Yazın (sunucu adresi: aynı bilgisayarsa `http://127.0.0.1:8742`, Tailscale ile `http://100.x.y.z:8742`):
   ```bat
   BoneliaAI-Konsol.exe enroll --server http://127.0.0.1:8742 --code ABCD-EFGH-... --label "USB 01"
   ```
4. En az 10 karakterlik bir **USB parolası** belirleyin ve unutmayın. Parola olmadan USB'deki veriler açılamaz.

Windows "bilinmeyen yayıncı" (SmartScreen) uyarısı gösterirse **"Ek bilgi" → "Yine de çalıştır"** seçin. Program henüz kod imzalı değil (bilinen eksik). Şirket bilgisayarlarında bu engellenebilir.

### B3. Kontrollü bir test hatası oluşturun
Başlat → "cmd" → sağ tık → **Yönetici olarak çalıştır**:
```bat
eventcreate /T ERROR /ID 999 /L APPLICATION /SO BoneliaTest /D "Test: Kassenexport fehlgeschlagen (connection refused)"
```
"SUCCESS" yazmalı. Bu, gerçek bir müşteri kaydını değiştirmez; yalnızca Windows günlüğüne bir test satırı ekler.

### B4. Programı çalıştırın
1. USB'deki `BoneliaAI.exe` dosyasına çift tıklayın; tarayıcıda BONELİA AI ekranı açılır.
2. Üstteki kutuya USB parolasını girip **Kilidi aç**. Sol üstte **"Bağlı"** görünmeli.
3. **Tarama** sekmesi → "Merkezi AI ile analiz et" işaretli → **Son hatalar (1 saat)**.

**Beklenen:** Listede `BoneliaTest 999` hatası görünür. Altındaki küçük satırda analiz kaynağı **`ollama:qwen2.5:...`** yazar (yalnızca `rules` yazıyorsa yapay zekâ kullanılmamıştır; bkz. Sorun giderme).

### B5. Diğer denemeler
1. **AI Sohbet**: "Son yarım saatteki hataları incele." yazıp **Sor**.
2. **Rapor**: hedef klasöre `C:\Users\Public\Desktop` yazıp **Dışa aktar** → masaüstünde JSON/TXT/HTML raporu oluşur.
3. **USB'yi çıkarın**: birkaç saniye içinde program kapanmalı (tarayıcı sayfası artık yanıt vermez).
4. **Sonraki bilgisayar**: aynı USB'yi başka bir bilgisayara takın, `BoneliaAI.exe`'yi açın ve parolayla kilidi açın (tekrar kayıt gerekmez).
5. **Kayıp USB senaryosu** (sunucuda):
   ```bat
   bonelia-server --config C:\BoneliaAI\server.toml devices
   bonelia-server --config C:\BoneliaAI\server.toml revoke dev_BURAYA
   ```
   Sonra USB'de tekrar tarama yapın: sunucu cihazı reddetmeli ("yetkisi iptal edilmiş").
6. **Denetim kaydı**: `bonelia-server --config C:\BoneliaAI\server.toml audit --verify` → `audit chain OK`.

---

## Sorun giderme
| Belirti | Olası neden / çözüm |
|---|---|
| Analiz kaynağı hep `rules` | Ollama çalışmıyor ya da `server.toml`'daki model adı `ollama list` çıktısıyla aynı değil. `http://127.0.0.1:8742/v1/health` içinde `"available": true` olmalı. Sunucuyu yeniden başlatın. |
| "Bağlantı yok" | Sunucu penceresi kapalı, adres yanlış veya güvenlik duvarı engelliyor. Tailscale'de iki bilgisayarın da "Connected" olduğunu kontrol edin. |
| `enrollment_rejected` | Kod 30 dakikayı geçmiş veya daha önce kullanılmış. A8'deki ikinci komutla yeni kod üretin. |
| Analiz çok uzun sürüyor | Model büyük, ekran kartı yok. 3B modele geçin (`ollama pull qwen2.5:3b-instruct`, `server.toml`'u güncelleyin). |
| Program açılmıyor | SmartScreen / şirket güvenlik politikası. B2'deki notu uygulayın veya kendi bilgisayarınızda deneyin. |

## Bana iletin
Test bitince şunları gönderin; sonuçları test belgesine işleyip eksikleri düzelteyim:
1. Dışa aktarılan **JSON raporu** (kişisel veri içermemesi gerekir — kontrol edin).
2. `hw-check` çıktısı ve kullandığınız model adı.
3. `audit --verify` sonucu.
4. Hangi adımda ne gördüğünüz; özellikle beklenenden farklı olanlar (ekran görüntüsü yeterli).
