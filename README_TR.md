# ESCrypter 0.2.0 — test edilmiş geliştirme adayı

Release derlemesi, çekirdek/ECP işleyici testleri ve GUI temel kontrolleri yapıldı.
Gerçek ortam Ubuntu 24.04 amd64 idi. Debian 13 ve gerçek SSH/SFTP doğrulaması
bu ortamın kısıtları nedeniyle bekliyor. Ayrıntılar: **docs/DEBUG_REPORT_TR.md**.
Bu GitHub kaynak paketinde derlenmiş dosya bulunmaz. Tek `.deb` için
`bash package-single-deb.sh` çalıştırın. Yükleme: [GitHub rehberi](docs/GITHUB_YUKLEME_TR.md).

## Yeni düzen

Ana pencerede Dosya / İşlemler / Anahtarlar / Görünüm / Ayarlar / Yardım ve
Bağlantılar menüleri bulunur. Yerel çalışma, açık paket, uzak sunucu ve aktarımlar
sekmeleri taşınabilir ve kapatılabilir. Yerel ana ekranda iki ana eylem vardır:
Şifrele ve Paket Aç. İşler alt panelde, teknik ayrıntılar isteğe bağlı görünür.
Beş kilit simgesi Qt kaynaklarına gömülüdür; paket dışında SVG aramaya bağlı değildir.
Dil ve tema ayarlardan değişir. Bazı teknik hata/durum metinleri İngilizcedir;
tam çeviri ve erişilebilirlik kontrolü sonraki aşamadadır.

## Değişmeyen paket biçimi

Son dosya `.esc` uzantılı sıkıştırmasız TAR'dır. `escs/esc10` ... `escs/esc100`
altında onar, toplam 100 benzersiz dört basamaklı `.esc` veri parçası bulunur.
`files/manifest.xml` parola korumalı anahtar/sıralama bilgisini taşır.
XZ sonrası rastgele dolgu şifrelenir; dış paket en az 4 MB olur. Parça başına
4 MB zorunluluğu yoktur. İmza, TAR başlıklarının birebir baytlarını değil
parçaların ve metadata kayıtlarının yollarını/boyutlarını/içeriklerini kapsar.
Kaynak dosyalar korunur; mevcut hedefler üzerine yazılmaz.

## Yerel işlemler

Anahtarlar menüsünde imza anahtarı oluşturun veya seçin. Şifrele işleminde arşiv
ve imza parolaları ayrı sorulur. Kurtarma anahtarı isteğe bağlıdır; arşiv dışında
gizli saklanmalıdır. İmza anahtarı dosyası çözme için gerekmez.

Paket Aç, imzayı doğrulayıp paket bilgilerini okur. İçerik listesini açmak için
İşlemler → İçerik listesini aç kullanılır; adlar ancak tam içerik doğrulamasından
sonra gösterilir. Önizleme en fazla 10000 kayıt / 512 KiB JSON listesiyle sınırlıdır.
Daha büyük listelerde normal çözme işlemini kullanın.

Güvenilen imzalayanlar bölümüne bağımsız kanaldan doğruladığınız 32 baytlık açık
anahtarları alın. İmzanın geçerli olması ile sahibine güvenilmesi ayrı durumlardır.
Parola değişikliği yeni paket üretir; eski kopyalar eski parola ile açılır.
Kurtarma anahtarının yetkisi arşiv parolası değişince ortadan kalkmaz.

## Uzak işlemler

Sunucu için Qt gerekmez; `escrypter-core` CLI ve Agent'ı içerir. Kurulumdan sonra,
normal kullanıcı hesabında ayrı veri ve anahtar kökleri oluşturun:

```bash
mkdir -m 700 -p ~/ESCrypter-data ~/ESCrypter-keys
escrypter-agent --init ~/ESCrypter-data ~/ESCrypter-keys
systemctl --user enable --now escrypter-agent.service
```

Bu hizmet kurulum komutları hedef sunucuda uygulanır; burada systemd kurulumu doğrulanamadı.
SSH oturumu kapansa da hizmetin sürmesi için sunucu yöneticisinin uygun kullanıcı
hizmeti/lingering ayarını yapması gerekir. Sunucu yeniden başlatılınca yarım
kalan şifreleme devam ettirilmez; iş interrupted olarak işaretlenir.

Bağlantılar → Yeni bağlantı ile kullanıcı, adres, port ve known_hosts dosyasını
seçin. Sunucu anahtarını önce güvenilir kanaldan doğrulayın. Şifreli SSH özel
anahtarlarını ssh-agent'a yükleyin. Kimlik bilgileri süreç argümanlarına yazılmaz.
SSH için özel shell komutu alanı sunulmaz; yalnız sabit ECP bridge komutu çalışır.

ECP sunucuda dosya listeleme, iş başlatma, ilerleme, iptal ve çıktı bilgilerini
iletir. Dosya baytlarını SFTP taşır. ECP portu açılmaz; SSH bağlantısı kullanılır.
Sunucuda işle menüsü kullanıldığında sunucu açık verilere ve gereken parolalara
ulaşabilir. Gizli saklama için yerelde şifreleyip yalnız `.esc` paketini yükleyin.

İmza anahtarlarını sunucu anahtar köküne ayrı ve güvenli biçimde hazırlayın.
ECP işlerinde yollar yapılandırılmış köklere göredir; mutlak yol kabul edilmez.
Agent olmayan SFTP sunucularında aktarım yapılabilir ama ECP iş yönetimi yoktur;
bu modda mutlak SFTP yolu kullanılır.

## Aktarımlar

libcurl SFTP desteği derleme zamanında mevcut olmalıdır. GUI bunu aktarım
başlangıcında kontrol eder. Sunucu anahtarı doğrulaması zorunludur.
ECP yüklemeleri özel geçici yola gider; boyut/SHA-256 eşleşince sonlandırılır.
Devam ettirme öncesi kısmi dosya özeti karşılaştırılır. İmzalı teslim makbuzu
SSH ile kimliği doğrulanan Agent anahtarıyla kontrol edilip yerelde saklanır.
ECP olmadan aktarımda bağımsız uzak dosya özeti/makbuz güvencesi verilmez.

GNU Wget SFTP için kullanılmaz. Ayrı HTTPS indirme menüsü Wget kullanır; yönlendirmeler kabul edilmez.
İndirilen `.esc` paketlerini kullanmadan önce imzalarını doğrulayın.

## Kaynaktan derleme

```bash
sudo apt update
sudo apt install build-essential cargo rustc cmake pkg-config python3 \
  qt6-base-dev qt6-svg-dev libsodium-dev liblzma-dev libcurl4-openssl-dev \
  openssh-client wget
./build.sh
bash package-single-deb.sh --no-build
```

35 Rust bağımlılığının tam kaynakları `vendor/` içinde; Cargo.lock sürümleri sabitler.
Derleme bunları çevrimdışı kullanır. Lisans envanteri gerçek çözülmüş kaynaklar ve
kurulu sistem paketlerinden üretilir; GUI içine gömülür (`draft: false`).

```bash
./tests/run-checks.sh
# Unix soketlerine izin veren bir sistemde ayrıca:
python3 tests/ecp_integration.py target/release
```

Kurulum, testlerden sonra:

```bash
sudo apt install ./dist/ESCrypter_0.2.0-1_amd64.deb
escrypter-gui
```

## Lisans ve sınırlar

Yeni ESCrypter kodu **GPL-3.0-only** lisanslıdır. Tam metin LICENSE dosyasındadır.
0.1.0 MIT bildirimi korunur; eski sürüme verilmiş lisans hakları geri alınmaz.
Bağımlılıkların kendi lisansları ve bildirimleri geçerlidir. GPLv3 sırf ağ
üzerinden kullanımdan dolayı AGPL benzeri kaynak sunma şartı oluşturmaz.

Uygulama açık kaynak lisanslarını Yardım menüsünde çevrimdışı gösterir. Bu sürüm
henüz doğrulanmış/denetlenmiş bir üretim sürümü değildir. Belleğin tamamen
silinmesi, SSD güvenli silme, sistemdeki zararlı yazılıma karşı koruma veya
sunucu yöneticisinden gizlilik vaat edilmez. Ani kapanma özel geçici dizinde
açık veri bırakabilir; işaretli, sahibi olan süreci bitmiş çalışma klasörleri
Ayarlar bölümünden seçilerek temizlenebilir.

Detaylar: docs/IMPLEMENTATION_STATUS.md, docs/ECP.md, FORMAT.md.
Geçmiş sonuçlar `docs/validation/` ve `docs/DEBUG_REPORT_TR.md` içindedir.
Yeni test çalıştırmaları `test-results/` üretir.
