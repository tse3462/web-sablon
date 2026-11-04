# BONELİA AI — Test Planı ve Sonuçları (v0.1)

Çalıştırma: `cd bonelia-ai && pip install -e ".[dev]" && python -m pytest -q -rs tests` (yalnız çekirdek)
Eklenti: `pip install -e adapters/veedelkorb && python -m pytest -q adapters/veedelkorb/tests`

## Kategoriler (Master prompt §31)

| Kategori | Dosya | Kapsam |
|---|---|---|
| Unit | `tests/unit/test_redact_crypto.py` | PII/secret temizleme, takma ad, çitleme, injection tespiti, imza, kasa, veri anahtarı, sahte sunucu imzası |
| Unit | `tests/unit/test_diagnostics.py` | Event Log XML ayrıştırma (gerçek RenderedXml formatı), bozuk XML, sınıflandırma, gruplama, istisna kodu, metrik olayları, sınırlı log okuma |
| Unit | `tests/unit/test_repair_policy.py` | Seviye 0–3, parametre doğrulama, kapsam/rol, onay kuralları, hız sınırı, üretim koruması, zaman aşımı, bağımsız doğrulama |
| Unit | `tests/unit/test_ai.py` | İstem çitleme, çıktı doğrulama, hibrit yönlendirme, önbellek, bütçe/izin, Ollama ve OpenAI protokolleri |
| Unit | `tests/unit/test_recognize.py` | Evrensel uygulama tanıma (olay ↔ kurulu program), yanlış eşleşme koruması |
| Integration | `tests/integration/test_modularity.py` | Çekirdek–eklenti bağımsızlığı: statik import/ad taraması, eklentisiz tam akış, bozuk/çöken eklenti izolasyonu, gizli anahtar sınırlaması, araç ad alanı, müşteri bazlı atama |
| Eklenti (ayrı) | `adapters/veedelkorb/tests/` | `saglik` sözleşmesi, token yalnız başlıkta, güvenli eylem yalnız TEST, yalnız `plugin_api` kullanımı, entry point keşfi, çekirdek sunucu üzerinden uçtan uca |
| Unit | `tests/unit/test_portable.py` | USB düzeni, USB çıkarılınca kapanma |
| Integration | `tests/integration/test_server_e2e.py` | Gerçek uvicorn sunucusu + Ollama protokolünü konuşan test modeli üzerinden USB–Server, rapor, kayıt, iptal, izolasyon, sahte sunucu, tekrar, sunucu kapanması, AI hataları, araç geçidi, sohbet |
| Integration | `tests/integration/test_cli_e2e.py` | Gerçek `bonelia-server` ve `BoneliaAI` CLI süreçleri; Windows'ta `eventcreate` ile gerçek kontrollü hata |
| Integration | `tests/integration/test_ui.py` | Yerel UI belirteci, Host kontrolü, CSP, kayıtsız USB'de düz metin yazılmaması |
| Windows | `tests/windows/test_windows_real.py` | Gerçek Event Log, kontrollü olay, kurulu uygulamalar, hizmetler, Security günlüğünün reddi |

### Failure tests eşlemesi
İnternet/sunucu kesintisi → `test_server_down_then_back_queue_drains` · AI cevap vermiyor/yavaş/bozuk → `test_ai_failures_fall_back_to_rules[slow|garbage|error]` · USB çıkarılması → `test_usb_removal_triggers_shutdown` (+ derlenmiş ikili ile elle doğrulandı) · Bozuk log → `test_parser_survives_corrupt_and_truncated_xml`, `test_log_tail_is_bounded` · Doğrulama başarısızlığı → `test_gateway_reports_unverified_when_independent_check_fails` · Bozuk kuyruk → `test_offline_queue_is_bounded_and_survives_corruption`.

Henüz otomatik testi olmayan: uygulama sürüm uyuşmazlığı (sürüme özgü bağdaştırıcı yok), güvenli güncelleme (özellik yok).

## Gerçekleşen sonuçlar

| Ortam | Sonuç | Tarih |
|---|---|---|
| Linux, yalnız çekirdek (eklenti kurulu değil) | **111 geçti, 5 atlandı** (5 = yalnız Windows) | 2026-11-04 |
| Linux, çekirdek + VeedelKorb eklentisi | **125 geçti, 5 atlandı** | 2026-11-04 |
| Linux, eklenti kaldırıldıktan sonra (modülerlik + CLI e2e) | **14 geçti** | 2026-11-04 |
| PyInstaller ikilisi (Linux) | Derlendi; `--version`, `scan --json`, UI (`/` 200, belirteçsiz 403, belirteçli 200), USB klasörü silinince süreç kapandı | 2026-11-04 |
| GitHub Actions `windows-latest` (gerçek Windows Server, run #4) | **Tüm testler geçti** (yalnız-Windows testleri dahil); `BoneliaAI.exe` derlendi; exe gerçek Application/System günlüklerini okudu (`ok:15`, `ok:8`), 59 kurulu programı tanıdı, `eventcreate` ile yazılan kontrollü hatayı (`BoneliaAISmoke/997`) tespit etti; kayıtsız taramada USB'ye düz metin rapor yazmadı | 2026-11-04 |
| GitHub Actions `ubuntu-latest` (run #4) | Eklentisiz çekirdek ✓, çekirdek + VeedelKorb ✓, eklenti kaldırıldıktan sonra ✓ | 2026-11-04 |

### İlk gerçek kabul denemesi — sahibin bilgisayarı (2026-11-04)
Gerçek USB bellek (G:), Almanca Windows 11 (10.0.26300), ev sunucusu aynı bilgisayarda (Python 3.14), Ollama `qwen2.5:3b-instruct` (CPU).

| Adım (§35) | Sonuç |
|---|---|
| USB'den kurulumsuz başlatma, cihaz kaydı | ✓ |
| Sunucuya imzalı bağlantı, AI modeli görünür | ✓ (`qwen2.5:3b-instruct ✓`) |
| Gerçek olay günlüğü okuma, kontrollü hata (`eventcreate` BoneliaTest/999) tespiti | ✓ |
| Kişisel veri temizleme (MAC → `[mac]`, kullanıcı yolları) | ✓ (2. denemede, MAC kuralı eklendikten sonra) |
| Yerel AI ile neden/çözüm açıklaması | ✓ 4 olay AI ile analiz edildi; 1 AI cevabı geçersizdi → kural teşhisine güvenli dönüş |
| Ticari kayıt değiştirilmedi | ✓ (salt okunur) |

Bu denemenin bulduğu ve düzeltilen sorunlar: 30 sn istemci zaman aşımı "çevrimdışı" sanıldı; Almanca karakterler bozuktu; MAC adresi gizlenmiyordu; yer tutucu kayıt kodunda Python hata dökümü; kuyruktaki eski analiz yeni sonucu geciktirdi; küçük modelin `"null"` araç adı yanlış uyarı üretti, kendini tekrar etti ve "yüksek güven" iddia etti (AI artık en fazla "orta" güven verebilir); başarısız AI denemeleri süre sınırına sayılmıyordu; hem sunucu hem USB için siyah konsol penceresi gerekiyordu.

Gözlem: 3B model ilk teşhis için kullanılabilir ama açıklamaları genel kalabiliyor; donanım uygunsa 7B önerilir.

Henüz yapılmadı: AI Sohbet, rapor dışa aktarma, USB çıkarma ve ikinci bilgisayar adımları gerçek USB ile; kayıp USB (iptal) senaryosu.

### Sahibin bilgisayarında kendi kendine onarım (2026-11-04)
USB'den `Bu-Bilgisayara-Kur.bat` ile Agent kuruldu (USB parolası bir kez). Yazdırma biriktiricisi (Spooler) elle durduruldu;
kimse dokunmadan Agent **13:06:54**'te "Hizmet durmuş: Druckwarteschlange" (Önemli) buldu, **13:08:36**'da başlattı,
`stopped → running` bağımsız olarak doğrulandı (`executed_verified`), sunucu denetim kaydına yazıldı (`alerts`).
Bulunan kusurlar: kurulum dosyası ikinci kez çalışınca WinError 32 (düzeltildi); arayüzdeki "Dene" düğmesi parametre gerektiren
araçlarda gereksiz `denied` kaydı üretiyordu (düzeltildi).

### Gerçek Windows'ta doğrulanan onarım ve Agent (GitHub Actions run #15–16, 2026-11-04)
* Yazdırma biriktiricisi (Spooler) gerçekten durduruldu; `windows.start_service` başlattı, `windows.restart_service` yeniden başlattı; her ikisi bağımsız durum kontrolüyle doğrulandı.
* Agent: `agent-install` (DPAPI makine kapsamı + SYSTEM zamanlanmış görevi), durdurulan hizmeti tek döngüde **kendi kendine** onardı (`executed_verified`), sunucu denetim kaydına yazıldı, `agent-uninstall` görevi ve dosyaları kaldırdı.
* Çift tıklanan `BoneliaAI.exe` konsol penceresi olmadan arayüzü sundu; sunucu `.bat` dosyaları (arka planda başlat/durdur, otomatik başlatma aç/kapa) çalıştı.

### Gerçek Windows'un bulduğu hatalar (Linux'ta görünmeyen)
| Hata | Düzeltme | Regresyon testi |
|---|---|---|
| Çevrimdışı kuyruk: Windows'un kaba saat çözünürlüğünde aynı dosya adı → kayıtlar sessizce üzerine yazıldı (veri kaybı) | Rastgele son ek | `test_offline_queue_never_overwrites_entries_in_the_same_clock_tick` |
| CLI, cp1252 konsolda Türkçe/sembol karakterlerde çöktü | stdout/stderr UTF-8 | `test_cli_survives_windows_legacy_console_encoding` |
| psutil Windows hizmet API farkı → hizmet listesi okunamadı | Alan seçimi `as_dict()` sonrası | `test_installed_apps_and_services` (Windows) |
| Kayıt kodu `-` ile başlayabiliyordu → `--code` bağımsız değişkeni bozuldu | base32, gruplu, büyük/küçük harf ve tire duyarsız kodlar | `test_enrollment_codes_are_cli_safe_and_typo_tolerant` |

**Önemli:** Linux'ta başarılı derleme ve test, Windows taşınabilir sürümünün çalıştığının kanıtı değildir. Windows kanıtı yalnızca `windows` CI işi veya gerçek bir Windows test bilgisayarıdır.

## v0.1 kabul senaryosu (Master prompt §35) — durum

| Adım | Durum |
|---|---|
| 1–2 USB takılır, program elle başlatılır | Windows CI'da exe çalıştırıldı ✓; gerçek USB bellekte elle test **yapılmadı** |
| 3 Uygulama tanıma | Kayıt defteri ile (Windows testi) |
| 4–5 Hata kayıtları okunur, kontrollü hata tespit edilir | `eventcreate` ile Windows CI'da |
| 6 Kişisel veri kontrolü | Otomatik testli |
| 7–9 AI'ya bağlanılır, neden ve çözüm | Ollama **protokolü** ile test edildi; gerçek model **çalıştırılmadı** (ortamda model indirilemedi) |
| 10 Risk/izin değerlendirmesi | Otomatik testli |
| 11 Ticari kayıt değiştirilmez | Tüm yazma araçları kapalı; testli |
| 12 Rapor | JSON/TXT/HTML, şifreli USB saklama |
| 13 USB çıkarılınca sonlanma | Testli + ikili ile doğrulandı (Linux) |
| 14 Sonraki bilgisayarda aynı paket | Aynı paketin iki kopyası iki ayrı cihaz olarak testli |

Gerçek Windows bilgisayarda gerçek USB bellek ve gerçek yerel model ile uçtan uca test, v0.1'in **tamamlandı** sayılması için hâlâ gereklidir.
