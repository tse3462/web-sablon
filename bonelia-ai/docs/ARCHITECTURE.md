# BONELİA AI — Mimari (v0.1)

## 1. Bileşenler

```
 Müşteri bilgisayarı (Windows)                         Ev bilgisayarı / özel sunucu
 ┌───────────────────────────────┐                      ┌──────────────────────────────────────┐
 │ USB: BONELIA-AI-Portable      │   imzalı HTTPS       │ BONELİA AI Server (FastAPI)          │
 │  BoneliaAI.exe                │   veya Tailscale     │  API Gateway + Device Auth           │
 │   ├ Collectors (salt okunur)  │ ───────────────────▶ │  Tenant / Device Registry (SQLite)   │
 │   │  Event Log, uygulamalar,  │  Ed25519 istek imzası│  Diagnostic Engine (kurallar)        │
 │   │  hizmetler, metrikler,    │ ◀─────────────────── │  AI Provider Router ─┬─ Ollama (yerel)│
 │   │  izinli log dosyaları     │  Ed25519 yanıt imzası│                      └─ OpenAI (ops.) │
 │   ├ Kural motoru (çevrimdışı) │                      │  Repair Policy Engine + Tool Gateway │
 │   ├ PII temizleme             │                      │  Approvals, Audit (hash zinciri)     │
 │   ├ Yerel UI (127.0.0.1)      │                      │  Knowledge Base, Cost Ledger         │
 │   ├ Şifreli kasa / rapor /    │                      │  Adapter Registry (entry points):    │
 │   │  çevrimdışı kuyruk        │                      │   (isteğe bağlı eklenti paketleri)   │
 │   └ USB çıkarılınca kapanır   │                      └──────────────────────────────────────┘
 └───────────────────────────────┘
```

* **Portable Monitor** (`src/bonelia/monitor/`) — USB'den çalışır, kurulum gerektirmez, otomatik başlamaz.
* **Server** (`src/bonelia/server/`) — tek AI merkezi; yönetim işlemleri yalnızca sunucudaki yerel CLI ile.
* **Agent** — Faz 7 (henüz yok). Aynı `collectors` + `client` paketlerini hizmet olarak çalıştıracak.
* **Control Center** — v0.1'de `bonelia-server` CLI (tenants, devices, revoke, approve, audit, usage). Web paneli Faz 7.

## 2. Depo yapısı

```
bonelia-ai/
  src/bonelia/
    contracts.py          ortak, sürümlü veri sözleşmeleri (USB ⇄ Server)
    collectors/           windows_events (wevtutil), system (psutil/winreg), log_files (sınırlı okuma)
    diagnostics/          knowledge (bilinen imzalar TR/DE/EN), engine (sınıflandırma, gruplama, kural teşhisi)
    ai/                   providers (Ollama, OpenAI uyumlu), prompting (fence + şema doğrulama), router (hibrit), costs
    repair/               tools (ToolSpec), policy (seviye 0–3), gateway (yürütme + doğrulama + denetim), builtin_tools
    adapters/             base (sözleşme), registry (keşif + izolasyon), generic_windows; resources/planned_adapters.json
    plugin_api.py         eklenti paketlerinin kullanabileceği TEK kararlı arayüz
    diagnostics/recognize evrensel uygulama tanıma (olay ↔ kurulu program eşleştirme)
    security/             redact (PII/secret), crypto (Ed25519, AES-GCM kasa), untrusted (prompt injection)
    server/               app (API), store (SQLite), config, cli, hwprobe
    monitor/              cli, session, scan, client, reports, offline_queue, portable, ui + static/index.html
  tests/                  unit/, integration/ (gerçek soketler, test_modularity), windows/ (yalnız gerçek Windows)
adapters/                 İSTEĞE BAĞLI uygulama eklentileri, her biri ayrı paket
  veedelkorb/             bonelia-adapter-veedelkorb (ilk örnek; salt okunur)
  scripts/                build_portable.py, boneliaai_entry.py
  deployment/             server.example.toml
  docs/
```

Önerilen `apps/` + `packages/` ayrımı bilinçli olarak tek Python paketi içinde modüllere indirgendi: v0.1'de tek dil ve tek sürüm, ayrı paket yönetimi maliyetinden daha değerlidir. Sözleşmeler JSON olduğundan bileşenler ileride ayrılabilir.

## 3. Teşhis akışı (Master prompt §12)

1. **Gözlem** — Collectors yalnızca okur (Application/System günlükleri; Security günlüğü okunmaz).
2. **Kanıt** — Her kanıt `Evidence` olarak yapılandırılır, `redact_text` ile temizlenir.
3. **Uygulama tanıma** — kayıt defteri (Uninstall anahtarları) + olay verisindeki uygulama adı/sürümü; bağdaştırıcı eşlemesi.
4. **Geçmiş** — parmak izi (fingerprint) ile gruplama; sunucuda önceki olaylar ve onaylı bilgi tabanı.
5. **Olası nedenler** — kural motoru (her zaman), gerekirse yerel AI, izinle bulut AI.
6. **Eksik veri** — `missing_information`.
7. **Çözüm seçenekleri** — `RecommendedAction`; varsayılan olarak manuel.
8. **Risk** — her araç bir `RiskLevel` taşır.
9. **Yetki** — politika motoru (sunucu veritabanından, AI'dan bağımsız).
10. **Yöntem** — Tool Gateway (dry-run varsayılan).
11. **Doğrulama** — araç kendi bağımsız `verifier`'ı olmadan gerçek yürütme yapamaz.
12. **Rapor** — JSON/TXT/HTML (PDF: tarayıcıdan yazdır). Yapılmayan müdahale raporda görünmez.

## 4. Hibrit AI

`HybridRouter.analyze`: kurallar → (hata/kritik veya düşük güven ise) yerel model → (zayıf sonuç + müşteri izni + operatör onayı + bütçe + bilinen fiyat) bulut → aksi halde kural sonucu. Aynı parmak izi 6 saat önbellekte; tekrar eden hata ikinci kez ücret üretmez. Her çağrı `ai_calls` tablosuna model, token, tahmini ücret, süre, müşteri ve hata sınıfıyla yazılır.

Model çıktısı: tek JSON nesnesi, şema doğrulaması, izin listesinde olmayan `tool_id` silinir, `is_definitive` her zaman `false`, komut benzeri öneriler işaretlenir.

## 5. Kontrollü müdahale

| Seviye | Anlam | v0.1 davranışı |
|---|---|---|
| 0 | Salt okuma | Etkin (`generic.collect_snapshot`) |
| 1 | Güvenli otomatik | Yalnızca: araç etkin + doğrulayıcı var + idempotent + müşterinin otomatik listesinde + müşteri seviyesi ≥1 + (üretimse) açık üretim izni |
| 2 | Yönetici onaylı | Tek kullanımlık, parametre özetine bağlı, süreli onay (`bonelia-server approve`) |
| 3 | Kritik | **Kod düzeyinde engelli**; veritabanında da etkinleştirilemez |

İstemci tarafı araçlar (ör. `windows.restart_service`) v0.1'de yalnızca dry-run'dır. Eklentilerin araçları kendi ad alanlarında (`<adapter_id>.*`) kalır, varsayılan kapalıdır ve seviye 3 olamaz.

## 6. Çok müşterili yapı ve çoklu USB

* Her USB kopyası kayıt sırasında **kendi** Ed25519 anahtarını üretir; sunucu yalnızca açık anahtarı saklar.
* Cihaz → tek kiracı (tenant) + kapsam listesi (`diagnose`, `adapter:<id>`, `repair:windows` …).
* Tüm kiracı sorgularında `tenant_id` kimliği doğrulanmış cihazdan türetilir; istek gövdesinden asla alınmaz.
* Kayıp USB: `bonelia-server revoke <device_id>` → anında 403; diğer cihazlar etkilenmez.

## 7. Çevrimdışı çalışma

Sunucu yoksa: yerel kural teşhisi, sistem metrikleri, rapor. Olaylar şifreli ve sınırlı kuyruğa (200 kayıt / 5 MB) alınır ve sunucu dönünce gönderilir. Müdahale kuyruğa alınmaz; bağlantı olmadan uzak işlem yapılmaz.

## 8. Dağıtım

* Ev sunucusu: `pip install bonelia-ai[server]`, `deployment/server.example.toml`, `bonelia-server serve`. Varsayılan dinleme 127.0.0.1; dışarıya yalnızca Tailscale (100.x) veya TLS ile.
* USB: GitHub Actions `windows` işi `BONELIA-AI-Portable` klasörünü üretir (artefakt). Klasör olduğu gibi birden çok USB'ye kopyalanır; her kopya ayrı kaydedilir.

## 9. Modüler uygulama bağdaştırıcıları (eklentiler)

**İlke:** BONELİA AI çekirdeği — evrensel teşhis motoru, AI sunucusu, USB uygulaması, onarım motoru — hiçbir
uygulamaya bağımlı değildir. Uygulamaya özel bağlantılar ayrı, isteğe bağlı paketlerdir. VeedelKorb yalnızca ilk
örnek modüldür.

```
 bonelia (çekirdek)                          bonelia_adapter_<id> (ayrı paket, isteğe bağlı)
 ┌───────────────────────────┐   entry point  ┌───────────────────────────────┐
 │ adapters/registry.py      │ ◀───────────── │ PLUGIN = manifest + create()  │
 │  keşif: "bonelia.adapters"│                │ ServerAdapter.health()        │
 │  izolasyon, durum, araçlar│                │ ServerAdapter.tools() (ops.)  │
 │ plugin_api.py (kararlı)   │ ─────────────▶ │ yalnızca bonelia.plugin_api   │
 └───────────────────────────┘    import      └───────────────────────────────┘
```

| Kural | Uygulama | Test |
|---|---|---|
| Çekirdek hiçbir eklentiyi adıyla import etmez veya anmaz | AST taraması + metin taraması | `test_core_never_imports_an_adapter_package`, `test_core_code_does_not_name_any_specific_application_adapter` |
| Eklenti yalnızca `bonelia.plugin_api` kullanır | AST taraması (eklenti testi) | `test_plugin_uses_only_the_public_plugin_api` |
| Eklenti olmadan tam akış çalışır | Sıfır eklentiyle USB → sunucu → teşhis; CI'da eklenti hiç kurulmadan tüm çekirdek testleri | `test_full_universal_flow_with_zero_adapters`, CI "Core tests without any adapter package" |
| Eklenti kaldırılınca çekirdek çalışır | CI: kur → test → kaldır → tekrar test | CI "Uninstall adapter and re-test core" |
| Bozuk eklenti izole edilir | import/başlatma hatası → `load_error`; çalışma hatası → 502 yalnız o eklentide | `test_broken_adapters_are_isolated`, `test_crashing_adapter_does_not_affect_core_or_other_adapters` |
| En az yetki | Eklenti yalnızca kendi yapılandırma bölümünü ve bildirdiği `BONELIA_<ID>_*` değişkenlerini görür | `test_adapter_receives_only_its_config_and_declared_prefixed_secrets` |
| Araç güvenliği | Ad alanı `<id>.*`, varsayılan kapalı, seviye 3 reddedilir | `test_adapter_tools_are_namespaced_disabled_and_never_critical` |
| Müşteri bazlı atama | `tenant_ids`; atanmamış müşteri ne eklentiyi ne araçlarını görür | `test_adapter_and_its_tools_are_assigned_per_customer` |

Bir eklenti varsayılan olarak **kapalıdır**; kurulu olması yetmez, `server.toml`'da `enabled = true` ve
`tenant_ids` gerekir. Yeni bir uygulama desteği = yeni bir paket; çekirdek değişmez.

API: `GET /v1/adapters` (çekirdek + planlanan + yüklü eklentiler ve durumları), `POST /v1/adapters/{id}/health`
(kapsam `adapter:{id}`). USB: `BoneliaAI.exe adapters`, `BoneliaAI.exe adapter <id>`; arayüz düğmeleri sunucudan dinamik gelir.
