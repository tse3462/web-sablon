# Kurtarma ve telefondan erişim

## Telefondan / uzaktan kontrol paneli (Tailscale)
1. Ev bilgisayarına Tailscale kurun; adresini (`100.x.y.z`) öğrenin (`tailscale ip -4`).
2. Telefonunuza Tailscale uygulamasını kurun, aynı hesapla girin.
3. Ev bilgisayarında paneli o adrese açın:
   `bonelia-server --config deployment\server.home.toml dashboard --host 100.x.y.z`
4. Ekranda yazan `http://100.x.y.z:PORT/#...` bağlantısını telefonda açın (bir kez; yer imine ekleyin).

İnternete açık değildir; yalnızca Tailscale ağınızdaki cihazlar erişir, ayrıca parola (token) ister. Panel yalnızca
127.0.0.1 veya bir Tailscale (100.x) adresinde açılır; başka adresleri reddeder.

## Rehberli Windows kurtarma (açılan ama sorunlu bilgisayar)
USB'deki **Bu-Bilgisayari-Kurtar.bat** dosyasına çift tıklayın (onarım adımları için yönetici sorusuna "Evet").
Tarayıcıda açılan ekranda, Windows'un kendi resmî araçlarıyla, sırayla:
1. **İncele (güvenli):** geri yükleme noktaları, disk sağlığı, bekleyen yeniden başlatma — hiçbir şey değiştirmez.
2. **Windows dosyalarını onar:** `sfc /scannow`, `DISM /RestoreHealth` — bozuk sistem dosyalarını onarır, kişisel verilere dokunmaz.
3. **Disk kontrolü:** `chkdsk /f /r` sonraki açılışta (onay ister).
4. **Sistem geri yükleme:** seçili bir noktaya döner ve yeniden başlar (onay ister); kişisel dosyalar etkilenmez.
5. **Hiç açılmıyorsa:** bu adım Windows kurtarma ortamında (WinRE) yapılır; ekranda `bootrec` adımları gösterilir.

Komut satırından (ör. WinRE): `BoneliaAI-Konsol.exe recover disk-health | sfc | dism | chkdsk --yes | restore --sequence N --yes`.

## Önyüklenebilir kurtarma USB'si (hiç açılmayan Windows) — elle, doğrulanmadı
Dürüst not: gerçek "USB'den önyüklenen" kurtarma ortamı Windows'un kendi WinRE/WinPE'sini ve Microsoft araçlarını
gerektirir; bu ortamda oluşturulup test edilemedi. Önerilen yol:
1. Microsoft'tan Windows kurtarma/kurulum medyası oluşturun (Media Creation Tool) veya kendi WinRE USB'nizi hazırlayın.
2. `BoneliaAI-Konsol.exe` dosyasını o USB'ye kopyalayın.
3. Sorunlu bilgisayarı bu USB'den başlatın, komut istemini açın ve yukarıdaki `recover` komutlarını ya da ekrandaki
   `bootrec` adımlarını uygulayın.
Her Windows her zaman kurtarılamaz; bazı durumlarda yeniden kurulum gerekir. Veri kurtarma bu aracın işi değildir.
