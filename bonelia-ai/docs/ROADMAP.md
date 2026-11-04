# BONELİA AI — Durum ve Yol Haritası

| Faz | Durum (2026-11-04) |
|---|---|
| 0 Keşif ve tasarım | ✅ `PHASE0_DISCOVERY.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `TEST_PLAN.md` |
| 1 Portable Monitor MVP | 🟡 Kod + testler hazır; Windows CI doğrulaması bekleniyor; gerçek USB ile elle test yapılmadı |
| 2 AI Server | 🟡 API, cihaz kimliği, olay yönetimi, analiz, sağlık; gerçek Ollama modeliyle test yapılmadı |
| 3 AI Diagnostic Engine | 🟡 Kural motoru + bilgi tabanı tablosu + AI yönlendirme; onaylı bilgi tabanı girişi için henüz CLI komutu yok (yalnızca `Store.add_knowledge`) |
| 4 VeedelKorb | 🟡 Salt okunur bağdaştırıcı sözleşmeye göre hazır; canlı/test ortamında çalıştırılmadı (token yok) |
| 5 Controlled Repair Engine | 🟡 Politika + geçit + doğrulama + denetim hazır; gerçek yürütme yalnızca sunucu tarafı ve TEST ortamı |
| 6 Çoklu program | ⏳ BONELIA Finance deposu bulunamadı; Supabase TEST projesi mevcut |
| 7 Çoklu USB + Agent | 🟡 Çoklu USB/iptal hazır; Agent ve web Control Center yok |
| 8 SAP pilotu | ⏳ Yalnızca manifest (Service Layer / resmî API) |
| 9 Ticari hazırlık | ⏳ Kod imzası, güvenli güncelleme, saklama süresi işleri yok |

## Sahibin kararı / erişimi gereken konular
1. **Ev sunucusu**: Ollama kurulumu ve model seçimi (`bonelia-server hw-check` çıktısına göre). Bu ortamda model indirilemedi.
2. **Ağ**: Tailscale mı yoksa alan adı + TLS mi?
3. **VeedelKorb**: `HEALTH_CHECK_TOKEN`'ın BONELİA AI sunucusuna verilmesi; ayrı TEST Supabase projesi oluşturulması (ücret doğurabilir — onay gerekir).
4. **Depolar**: VediCore, KanSlide/Kanslay ve BONELIA Finance uygulama depolarına erişim.
5. **Kod imzası sertifikası** (Authenticode, ücretli).
6. **Bulut AI**: OpenAI hesabı/bütçesi ve müşteri onay metni.

## Sonraki teknik görevler (öncelik sırasıyla)
1. Windows CI sonucunu doğrula; hataları düzelt.
2. Ev sunucusunda gerçek Ollama modeliyle `analyze` uçtan uca testi; sonuçları `TEST_PLAN.md`'ye ekle.
3. Gerçek USB bellek + gerçek Windows bilgisayarda kabul senaryosu (§35).
4. `bonelia-server knowledge-add` (onaylı bilgi tabanı girişi) ve bilgi tabanı arama ekranı.
5. Saklama süresi (`retention_days`) temizleme işi.
6. Agent (Windows hizmeti, yalnızca izinli uygulamalar, kaldırma komutu).
7. Web Control Center (salt okunur önce).
8. İmzalı sürüm ve güncelleme kanalı.
