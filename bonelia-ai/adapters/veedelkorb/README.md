# bonelia-adapter-veedelkorb — isteğe bağlı VeedelKorb modülü

> Bu paket BONELİA AI'nin **parçası değildir**. VeedelKorb yalnızca ilk test ve örnek bağlantı modülüdür.
> Paket kurulmadığında veya kaldırıldığında BONELİA AI normal çalışır (CI'da her çalıştırmada test edilir).

* Yalnızca **okur**: VeedelKorb'un mevcut `saglik` Edge Function'ını `?context=agent` ile çağırır.
* VeedelKorb'un kaynak koduna, Supabase veritabanına veya canlı servislerine **hiçbir değişiklik yapmaz**.
* Yalnızca `bonelia.plugin_api` arayüzünü kullanır (testli); çekirdeğin iç yapısına bağlı değildir.
* Çekirdek bu modüle yalnızca kendi bildirdiği iki ortam değişkenini verir; başka hiçbir gizli anahtarı göremez.

## Ne okur
| `saglik` alanı | BONELİA olayı |
|---|---|
| `checks[].name` | `veedelkorb.check:<ad>` |
| `context.jobs[].ok_age_s` > beklenen | `veedelkorb.job:<iş>` (dispatch/scheduled_tick 15 dk, payment(_jobs)/notify 30 dk, invoice 6 sa, retention 36 sa, backup 30 sa — ilk tahminler) |
| `cron.failed_1h`, `notifications.*`, `payments.attention`, `invoices.pending`, `orders.*` | ilgili sayaç olayları |
| HTTP 401 / erişilemez | yapılandırma / bağlantı olayı |

Yalnızca toplu sayaçlar okunur; müşteri, sipariş ve ödeme satırlarına erişilmez.

## Kurulum (ev sunucusu, sahibin onayıyla)
```bash
pip install -e adapters/veedelkorb
```
`server.toml`:
```toml
[adapters.veedelkorb]
enabled = true
tenant_ids = ["ten_..."]                 # bu modülü kullanabilecek müşteri(ler)
url = "https://<project-ref>.supabase.co"
environment = "test"
```
Ortam değişkeni (yalnızca sunucuda): `BONELIA_VEEDELKORB_HEALTH_TOKEN` = VeedelKorb'daki mevcut `HEALTH_CHECK_TOKEN` (değiştirilmez).
USB kaydı: `bonelia-server enroll-code ten_... --scopes diagnose,adapter:veedelkorb`, sonra `BoneliaAI.exe adapter veedelkorb`.

Kaldırma: `pip uninstall bonelia-adapter-veedelkorb` — sunucu yeniden başlatıldığında modül listeden düşer; çekirdek etkilenmez.

## Yapılmamış ve onay gerektiren işler
* Canlı `saglik` uç noktasının çağrılması (token sahibin onayıyla verilmeli).
* VeedelKorb AI kontrolünün etkinleştirilmesi — **yapılmadı, yapılmayacak**.
* `veedelkorb.retry_failed_notifications` aracı (VeedelKorb'un kendi `ai_safe_action('retry_failed_notifications')` işlemi) yalnızca ayrı bir **TEST** projesi için `BONELIA_VEEDELKORB_TEST_SERVICE_KEY` ile oluşturulabilir. Üretim ortamı için yürütücü oluşturulmaz, araç varsayılan olarak kapalıdır. Ayrı bir VeedelKorb TEST Supabase projesi şu an görünmüyor.
* Ödeme ve fatura işlemleri (`run_payment`, `run_invoice`) çift kayıt riski nedeniyle **eklenmedi**.

## Test
```bash
pip install -e adapters/veedelkorb && python -m pytest adapters/veedelkorb/tests
```
