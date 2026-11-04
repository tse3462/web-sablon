# BONELİA AI

**Universal AI Diagnostic, Monitoring & Control Platform** — v0.1 (geliştirme sürümü)

USB'den çalışan taşınabilir bir teknik servis programı (**Portable Monitor**) ve ev bilgisayarında çalışan merkezi bir yapay zekâ sunucusu (**BONELİA AI Server**). Program Windows hata kayıtlarını salt okunur inceler, kişisel verileri temizler, kural motoru + yerel/bulut AI ile olası nedenleri açıklar ve müdahaleleri yalnızca güvenli araç geçidinden, izin ve doğrulama ile önerir.

> v0.1 **salt okunurdur**: hiçbir ticari kayıt, ayar veya hizmet değiştirilmez. Seviye 3 (kritik) müdahaleler kodda engellidir.

Arayüz dilleri: Türkçe, Almanca, İngilizce.

## Hızlı başlangıç

### Ev sunucusu
```bash
pip install -e ".[server]"
cp deployment/server.example.toml server.toml           # data_dir, Ollama modeli
bonelia-server --config server.toml hw-check            # donanım + model boyutu önerisi
bonelia-server --config server.toml tenant-add "Müşteri A"          # -> ten_...
bonelia-server --config server.toml enroll-code ten_... --scopes diagnose   # tek kullanımlık kod (30 dk)
bonelia-server --config server.toml serve
```

### USB (Windows)
GitHub Actions `windows` işinin `BONELIA-AI-Portable-windows` artefaktını USB'ye kopyalayın.
```bat
BoneliaAI.exe enroll --server http://100.x.y.z:8742 --code <kod> --label "USB 01"
BoneliaAI.exe                     :: yerel arayüzü açar
BoneliaAI.exe scan --mode quick   :: çevrimdışı yerel teşhis
BoneliaAI.exe analyze --app "PosKasse"
```
Kayıp USB: `bonelia-server revoke <device_id>`.

### Geliştirme
```bash
pip install -e ".[dev]"
python -m pytest -q -rs
python scripts/build_portable.py      # dist/BONELIA-AI-Portable
```

## Belgeler
* [Faz 0 keşif bulguları](docs/PHASE0_DISCOVERY.md)
* [Mimari](docs/ARCHITECTURE.md)
* [Tehdit modeli](docs/THREAT_MODEL.md)
* [Test planı ve sonuçları](docs/TEST_PLAN.md)
* [VeedelKorb entegrasyonu](docs/VEEDELKORB.md)
* [Durum ve yol haritası](docs/ROADMAP.md)

## Bilinen eksikler (dürüst durum)
* Gerçek bir yerel LLM ile test yapılmadı (geliştirme ortamında model indirilemedi); AI katmanı Ollama protokolüyle test edildi.
* Gerçek Windows doğrulaması GitHub Actions `windows-latest` ile yapılır; gerçek USB bellekle elle test henüz yok.
* `BoneliaAI.exe` kod imzası, güvenli güncelleme, Agent ve web Control Center henüz yok.
* PDF raporu: v0.1'de HTML rapor tarayıcıdan "PDF olarak yazdır" ile alınır.
