# VeedelKorb Entegrasyonu (Faz 4 başlangıcı — salt okunur)

## Ne yapar
Sunucu, VeedelKorb'un mevcut `saglik` Edge Function'ını `?context=agent` ile çağırır ve yanıtı BONELİA AI olaylarına çevirir:

| `saglik` alanı | BONELİA olayı |
|---|---|
| `checks[].name` (başarısız kontroller) | `veedelkorb.check:<ad>` |
| `context.jobs[].ok_age_s` > beklenen | `veedelkorb.job:<iş>` (dispatch/scheduled_tick 15 dk, payment(_jobs)/notify 30 dk, invoice 6 sa, retention 36 sa, backup 30 sa) |
| `cron.failed_1h` > 0 | `veedelkorb.cron.failed_1h` |
| `notifications.failed_24h`, `queued_old_30m` | bildirim olayları |
| `payments.attention` | ödeme olayı |
| `invoices.pending` | fatura olayı |
| `orders.waiting_supplier_15m`, `delivery_failed` | sipariş olayları |
| HTTP 401 / erişilemez | yapılandırma / bağlantı olayı |

Eşik değerleri ilk tahminlerdir; gerçek çalışma verisiyle ayarlanmalıdır.

Okunan veri yalnızca toplu sayaçlardır; müşteri, sipariş, ödeme satırlarına erişilmez.

## Gizli anahtarlar
`BONELIA_VEEDELKORB_HEALTH_TOKEN` yalnızca ev sunucusunun ortam değişkenidir. USB'ye hiçbir zaman gönderilmez; yanıtlarda da yer almaz (testli).

## Kurulum (sahibin yapacağı adımlar)
1. `bonelia-server tenant-add "VeedelKorb" --environment test` → `ten_…`
2. `server.toml`: `[adapters.veedelkorb] tenant_id = "ten_…"`, `url = "https://<ref>.supabase.co"`
3. Ortam değişkeni: `BONELIA_VEEDELKORB_HEALTH_TOKEN=<HEALTH_CHECK_TOKEN>` (VeedelKorb'daki mevcut secret; **değiştirilmez**)
4. USB kaydı: `bonelia-server enroll-code ten_… --scopes diagnose,adapter:veedelkorb`
5. USB: `BoneliaAI.exe veedelkorb` veya UI'de "VeedelKorb sağlık analizi"

## Onay gerektiren ve YAPILMAMIŞ işler
* Canlı `saglik` uç noktasının BONELİA AI sunucusundan çağrılması (token sahibin onayıyla verilmeli).
* VeedelKorb AI kontrolünün etkinleştirilmesi — **yapılmadı, yapılmayacak** (sahibin açık kararı gerekir).
* `veedelkorb.retry_failed_notifications` (VeedelKorb'un kendi `ai_safe_action('retry_failed_notifications')` işlemi): yalnızca ayrı bir VeedelKorb **TEST** Supabase projesi için `BONELIA_VEEDELKORB_TEST_SERVICE_KEY` ile yapılandırılabilir; kod üretim ortamı için yürütücü oluşturmayı reddeder. Mevcut Supabase listesinde ayrı bir VeedelKorb TEST projesi **görülmedi**.
* Ödeme ve fatura işlemleri (`run_payment`, `run_invoice`) çift kayıt riski nedeniyle BONELİA AI araç listesine **eklenmedi**.
