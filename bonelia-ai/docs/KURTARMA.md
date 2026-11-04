# Kurtarma ve telefondan erişim

## Telefondan kontrol paneli (en kolay yol)
Bir kez (ev bilgisayarında):
1. Ev bilgisayarına ve telefona **Tailscale** kurun, ikisinde de aynı hesapla giriş yapın (ücretsiz).
2. `deployment\windows\BONELIA-Panel-Kur.bat` dosyasına **çift tıklayın**. Bu, paneli her açılışta arka planda
   kendiliğinden başlatır ve Tailscale adresini kendisi bulur. Açılan not defterinde telefon bağlantısı yazar.
3. O bağlantıyı telefona gönderin, bir kez açıp ana ekrana/yer imlerine ekleyin. Adres hep aynı kalır.

Bundan sonra komut yazmanıza gerek yok: telefondan o bağlantıya dokunmanız yeterli (Tailscale açık olsun).
Kapatmak: `BONELIA-Panel-Otomatik-KAPAT.bat`. Panel internete açık değildir; yalnızca Tailscale ağınızdaki cihazlar
erişir ve parola (token) ister.

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
