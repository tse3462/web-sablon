# BONELİA AI — Tehdit Modeli (v0.1)

## Korunan varlıklar
Müşteri teknik verileri ve kişisel veriler · müşteri sistemlerinin bütünlüğü · finansal kayıtlar · cihaz anahtarları · sunucu anahtarı ve API anahtarları · denetim kaydı · AI maliyet bütçesi.

## Güven sınırları
1. Müşteri bilgisayarı ↔ USB programı (müşteri bilgisayarı güvenilir değildir).
2. USB ↔ ev sunucusu (ağ güvenilir değildir).
3. Sunucu ↔ AI modeli (model çıktısı güvenilir değildir).
4. Log/olay metni ↔ AI istemi (log içeriği saldırgan kontrolünde olabilir).

## Tehditler ve önlemler

| # | Tehdit | Önlem | Test |
|---|---|---|---|
| T1 | USB kaybolur/çalınır | Anahtar ve veriler scrypt+AES-GCM kasada; parola olmadan okunamaz; cihaz sunucuda anında iptal | `test_lost_usb_is_revoked_without_affecting_others`, `test_vault_encrypts_and_rejects_wrong_passphrase` |
| T2 | Bir USB'nin ele geçirilmesi diğerlerini etkiler | Cihaz başına ayrı anahtar ve kapsam; tek kiracıya bağlı | `test_same_package_runs_on_next_computer`, `test_tenant_isolation` |
| T3 | Sahte sunucu | Kayıtta sunucu anahtarı alınır (isteğe bağlı parmak izi sabitleme); tüm yanıtlar imzalı, istemci doğrular | `test_fake_server_is_detected`, `test_enrollment_pins_expected_server_key` |
| T4 | İstek sahteciliği / tekrar | Ed25519 istek imzası (yöntem, yol, zaman, nonce, gövde özeti); ±300 sn; nonce tekrar tablosu | `test_unsigned_tampered_and_replayed_requests_rejected` |
| T5 | Müşteriler arası veri karışması | `tenant_id` yalnızca doğrulanmış cihazdan; bağdaştırıcı kiracıya atanır | `test_tenant_isolation` |
| T6 | Loglarda prompt injection | Rastgele sınırla çitleme; şema doğrulama; izin listesi dışı araç silinir; AI hiçbir şey yürütemez; uyarı gösterilir | `test_prompt_injection_cannot_produce_commands`, `test_prompt_injection_in_log_is_flagged_and_secret_redacted` |
| T7 | AI'nın yetkisini genişletmesi | Politika bağlamı yalnızca sunucu DB'sinden; seviye 3 kodda engelli; araçlar varsayılan kapalı | `test_level3_is_hard_blocked_even_if_enabled_and_approved`, `test_builtin_registry_defaults_are_safe` |
| T8 | Sınırsız komut çalıştırma | Genel kabuk/PowerShell aracı yok; parametreler tür/desen/seçenek ile doğrulanır | `test_parameter_validation`, `test_tool_gateway_over_api` |
| T9 | Kişisel veri sızıntısı (AI/sunucu) | İstemcide ve sunucuda `redact_text`; host adı takma ad; komut satırları toplanmaz; Security günlüğü okunmaz | `test_redaction_*`, `test_v01_scenario_scan_analyze_report` |
| T10 | Gizli anahtar sızıntısı | API/servis anahtarları yalnızca sunucu ortam değişkenlerinde; USB'ye yazılmaz; eklentiler yalnızca kendi bildirdiği `BONELIA_<ID>_*` değişkenlerini görür | `test_adapter_receives_only_its_config_and_declared_prefixed_secrets`, eklenti: `test_adapter_sends_token_only_in_header_and_uses_agent_context` |
| T11 | Yerel UI'nin başka sayfalarca kötüye kullanımı | Yalnızca 127.0.0.1, rastgele belirteç, Host başlığı kontrolü (DNS rebinding), CSP, frame-ancestors none | `test_ui_requires_token_and_local_host` |
| T12 | Kontrolsüz otomatik onarım | Seviye 1 için müşteri otomatik listesi + idempotent + doğrulayıcı + saatlik sınır; seviye 2 için tek kullanımlık onay; onay yürütmeden ÖNCE tüketilir | `test_level2_approval_rules`, `test_approval_consumed_before_execution` |
| T13 | "Düzeldi" yanılgısı | Bağımsız doğrulayıcı yoksa yürütme reddedilir; doğrulama başarısızsa `executed_unverified` | `test_gateway_reports_unverified_when_independent_check_fails` |
| T14 | Denetim kaydının değiştirilmesi | SHA-256 hash zinciri, `audit --verify` | `test_audit_chain_and_minimal_content` |
| T15 | Büyük/bozuk girdi ile çökme veya bellek tükenmesi | 1 MB gövde sınırı, log kuyruğu okuma sınırı, XML olay bazında kurtarma, kuyruk sınırı | `test_oversized_body_rejected`, `test_log_tail_is_bounded`, `test_parser_survives_corrupt_and_truncated_xml` |
| T16 | Açık ağa yayın | Sunucu TLS veya Tailscale olmadan dış adrese bağlanmayı reddeder; istemci düz HTTP'yi yalnızca loopback/Tailscale'e kabul eder | `test_server_refuses_public_bind_without_tls`, `test_plain_http_only_for_loopback_or_tailscale` |
| T17 | Maliyet patlaması | Günlük/aylık bütçe; fiyatı bilinmeyen model bulutta kullanılmaz; parmak izi önbelleği; istek başına AI olay sınırı | `test_cloud_requires_tenant_permission_consent_and_budget`, `test_local_ai_used_and_cached` |

| T18 | Kötü/bozuk uygulama eklentisi | Varsayılan kapalı; izolasyonlu yükleme; yalnız kendi gizli anahtarları; araçlar ad alanında, kapalı, seviye 3 yok; müşteri bazlı atama. Not: eklenti sunucu sürecinde çalışır — yalnızca güvenilir, incelenmiş eklentiler kurulmalıdır | `test_modularity.py` |

## Kalan riskler (v0.1)
* **Kod imzası yok**: `BoneliaAI.exe` henüz Authenticode ile imzalı değil; SmartScreen uyarısı ve değiştirilmiş kopya riski. Build manifestosu (SHA-256) imzanın yerini tutmaz. → Faz 9.
* **Güvenli güncelleme yok**: güncellemeler şimdilik elle; imzalı güncelleme kanalı Faz 9.
* **Müşteri bilgisayarı güvenilmez**: kötü amaçlı yazılım bulunan bir bilgisayarda kasa parolası tuş kaydıyla yakalanabilir. Cihaz iptali ve kısa ömürlü kayıt kodları etkiyi sınırlar.
* **Redaksiyon kusursuz değildir**: desen tabanlıdır. Serbest metindeki isimler (ör. "Herr Müller") yakalanmayabilir. Bulut AI için ayrıca müşteri onayı istenir.
* **SQLite** tek düğümlüdür; yedekleme yöneticinin sorumluluğundadır.

## GDPR/DSGVO notları (hukuki değerlendirme yerine geçmez)
Veri minimizasyonu (Art. 5), sözleşmeli işleme (Art. 28 — müşteri ile AVV gerekir), bulut AI kullanımı için ayrı onay ve AB dışı aktarım değerlendirmesi (Art. 44 vd.), saklama süresi (`retention_days` alanı mevcut; otomatik silme işi henüz yok — Faz 9). Kesin uyum değerlendirmesi bir veri koruma uzmanınca yapılmalıdır.
