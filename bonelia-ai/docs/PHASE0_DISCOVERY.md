# FAZ 0 — Keşif Bulguları (2026-11-04)

Bu belge, geliştirme ortamında **gerçekten erişilen ve doğrulanan** bilgileri listeler. Erişilemeyen şeyler açıkça belirtilmiştir.

## 1. Geliştirme ortamı

| Öğe | Durum |
|---|---|
| İşletim sistemi | Linux bulut konteyneri (Windows **değil**) |
| Python | 3.13 (CI'da 3.12) |
| Node / Rust / Docker | Var (kullanılmadı) |
| .NET SDK | **Yok** |
| Ollama | **Yok**; ikili dosya GitHub'dan indirilebilir, ancak model kayıtları (`registry.ollama.ai`, `huggingface.co`) ağ politikasınca **engelli (403)** |
| PyPI | Erişilebilir |
| Windows test makinesi | **Yok** → gerçek Windows doğrulaması GitHub Actions `windows-latest` üzerinde yapılır |

Sonuç: Bu ortamda gerçek bir yerel LLM çalıştırılamadı. AI katmanı, Ollama'nın gerçek HTTP protokolünü konuşan bir test sunucusuyla doğrulandı. Gerçek model testi ev sunucusunda yapılmalıdır (bkz. `ROADMAP.md`).

## 2. GitHub erişimi

Hesap: `tse3462`. Erişilebilir depolar:

| Depo | Görünürlük | Not |
|---|---|---|
| `tse3462/web-sablon` | public | Basit HTML/CSS şablonu. BONELİA AI, mevcut dosyalara dokunmadan `bonelia-ai/` klasörüne eklendi |
| `tse3462/veedelkorb` | private | Salt okunur klonlandı ve incelendi |

**VediCore, KanSlide/Kanslay, BONELIA Finance uygulama depoları mevcut erişimde bulunamadı.** Bu uygulamalar için hiçbir API, dosya veya tablo adı varsayılmadı; bağdaştırıcıları `planned` olarak işaretlendi.

## 3. Supabase projeleri (yalnızca listeleme / şema okuma)

| Proje | Ref | Bölge |
|---|---|---|
| VeedelKorb | `fviasumzqracjzjouyds` | eu-central-1 |
| BONELIA-Finance | `aorijstuztjerxucfcnn` | eu-west-1 |
| BONELIA-Finance-TEST | `ggaiohbmdgdrrzcyqfmc` | eu-west-1 |
| BNL-Delivery | `vnbxemwjcotvciqghckt` | eu-central-1 |
| bonelia-ai-rezervation | `tdsxkmjlzgjriugepdlh` | eu-central-1 |

Hiçbir projede yazma, migration, fonksiyon dağıtımı veya ayar değişikliği yapılmadı. BONELIA Finance şeması bu fazda incelenmedi (Faz 6).

## 4. VeedelKorb — önceki bulguların yeniden doğrulanması

| Önceki bulgu | Doğrulama (kaynak) |
|---|---|
| `health_check` | **Tablo değil**, `public.health_check()` RPC fonksiyonu; yalnızca `service_role` (migration `20261030140000_gelismis_saglik.sql`) |
| `ai_alarm_context` | `public.ai_alarm_context()` RPC; kişisel verisiz sayaçlar (migration `20261026150821_alarm_saglik_baglami.sql`) |
| `ai_safe_action` | `public.ai_safe_action(p_action, p_note)`; izin listesi: `run_dispatch, run_scheduled, run_payment, run_invoice, kick_notify, kick_payment_jobs, retry_failed_notifications`; saatte en fazla 3; `private.ai_actions` kaydı |
| `client_errors` | `public.client_errors` tablosu mevcut (canlıda 0 satır); sunucu tarafı gizleme `private.redact_client_error` |
| `job_heartbeats` | **`private.job_heartbeats`** (public değil) |
| `saglik` Edge Function | ACTIVE (v9), `verify_jwt=false`, `Authorization: Bearer HEALTH_CHECK_TOKEN`, `?context=agent` |
| Sipariş/ödeme/fatura | `orders`, `payments`, `invoices`, `fatura`, `odeme`, `odeme-isleri`, `stripe-webhook` mevcut |
| BONELIA Finance bağlantısı | `muhasebe-senkron` Edge Function mevcut (içerik incelenmedi) |
| AI kontrolü kapalı | `ai_alarm_context().ai_control.enabled` alanı ile okunabilir. **Etkinleştirilmedi.** |

`HEALTH_CHECK_TOKEN` bu ortamda yoktur; canlı `saglik` uç noktası **çağrılmadı**. VeedelKorb bağdaştırıcısı yanıt sözleşmesine (`supabase/functions/_shared/health.mjs`) göre yazıldı ve bu sözleşmeye uygun test verileriyle doğrulandı.

## 5. Teknoloji kararı

| Karar | Gerekçe |
|---|---|
| Tek Python kod tabanı (istemci + sunucu) | Ortak `contracts.py` ile USB ve sunucu sözleşmesi asla ayrışmaz; ortamda .NET yok; tüm mantık Linux'ta test edilebilir |
| Portable: PyInstaller tek dosya `BoneliaAI.exe` | Kurulum gerektirmez; Windows runner'da derlenir ve test edilir |
| UI: yerel tarayıcı arayüzü (127.0.0.1 + rastgele belirteç) | Ek çalışma zamanı (WebView2/.NET) gerektirmez; modern arayüz; mimari web Control Center'a genişleyebilir |
| Sunucu: FastAPI + SQLite (v0.1) | Ev bilgisayarında sıfır bakım; şema PostgreSQL'e taşınabilir |
| AI: Ollama (yerel) + OpenAI uyumlu (isteğe bağlı) | Model değişimi yalnızca sunucu yapılandırmasıdır |
| Kimlik: cihaz başına Ed25519 + istek/yanıt imzası | USB kaybı tek cihazla sınırlı; sahte sunucu tespit edilir |
| Ağ: Tailscale veya TLS | Düz HTTP yalnızca loopback / Tailscale (100.64.0.0/10) adreslerine izinli |

Gözden geçirme noktası: Windows'a özgü derin entegrasyon (ETW, WMI olay aboneliği, Agent hizmeti) gerekirse Agent bileşeni .NET ile yazılabilir; sözleşmeler JSON olduğundan bu ayrım mümkündür.
