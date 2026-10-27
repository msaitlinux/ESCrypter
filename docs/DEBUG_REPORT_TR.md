# ESCrypter 0.2.0 hata ayıklama raporu

Tarih: 24 Ekim 2026. Hedef: Debian 13. Gerçek test ortamı: Ubuntu 24.04.3,
amd64; Rust 1.75, Qt 6.4.2, libsodium 1.0.18. Bu bir geliştirme adayıdır.
Bağımsız güvenlik denetimi veya üretim sertifikasyonu yapılmadı.

## Düzeltilen sorunlar

- İkinci ajan, hizmet kilidini almadan kalıcı iş kayıtlarını değiştirebiliyordu.
  Kilit artık durum yükleme, kurtarma ve anahtar oluşturmanın öncesinde alınır.
- Yükleme dosyasının atomik taşınması ile durum kaydı arasındaki kesinti için
  kalıcı sonlandırma niyeti ve tekrar deneme eklendi. Kurtarma sırasında hedefin
  boyutu ve SHA-256 özeti yeniden doğrulanır; mevcut başka hedef ezilmez.
- GUI makbuz doğrulaması artık imzaya ek olarak aktarım kimliği, SHA-256 ve dosya
  boyutunu karşılaştırır. Önceden tamamlanan yüklemelerin makbuzları da doğrulanır.
  İmza alan ayırıcısının doğru uzunluğu 21 bayttır; ilk inceleme şüphesi testle
  giderildi. Sabit sayı yerine derleyicinin hesapladığı uzunluk kullanılır.
- ECP bağlantısı kesildiğinde istemci sessizce SFTP-only moda geçmez.
- Özet hesaplama ve ECP yanıtı bekleme işlemleri kapanış/iptal hesabına katıldı.
  İptal edilen işlemlerin gecikmiş geri çağrıları yeni aktarım başlatmaz.
- Kuyruktaki aktarım iptalleri görünür duruma işlendi; seçili bekleyen iş de
  iptal edilebilir. Başlatılamayan yerel işlerin bekleyen parola kopyaları silinir.
- İndirmeler O_NOFOLLOW ile açılır; yeni geçici dosyada O_EXCL kullanılır.
  Bağlantı olmayan normal dosya ve sahiplik denetlenir; flush/fsync hatası
  başarılı aktarım gibi bildirilmez. SFTP-only indirme tekrarları farklı geçici
  dosya kullanır. Sıfır uzunluklu eski ECP geçici dosya çakışması hata verir;
  kullanıcı dosyayı inceleyip kaldırmadan üzerine yazılmaz.
- Wget indirmeleri pencere kapanışında izlenir; iptal sırasında kapanan ilerleme
  penceresine geçersiz işaretçiyle erişim giderildi.
- Çalışma klasörü temizliği UID, pozitif PID ve sembolik bağlantı kontrolleriyle
  sınırlandı. Aynı kullanıcı hesabındaki kötü niyetli süreçlere karşı tam bir
  dosya sistemi sandbox'ı olduğu iddia edilmez.
- Çekirdek ve GUI .deb paketlerinin belge yolları ayrıldı; ortak dosya sahipliği
  çakışması giderildi. Geçersiz CLI komutları artık başarısız dönüş kodu verir.
- Lisans kataloğu gerçek derleme bağımlılıklarıyla üretildi (`draft: false`).
  Çözümlenmiş 35 Rust bağımlılığının kaynakları ve Cargo.lock dağıtıma eklendi.

## Otomatik kontroller

`tests/run-checks.sh` sonuçları `test-results/` içindedir:

- 14 Rust birim testi: kripto doğrulama/final tag, XML sınırları, ECP çerçeve
  sınırları, 4096 deterministik bozuk çerçeve denemesi, yol politikası, kimlik
  tekrarları, aktarım özeti/makbuzu, kota/çakışma, sonlandırma kurtarması ve olay
  halkası. Bu, kapsamlı fuzzer veya bağımsız protokol denetimi değildir.
- 18 CLI entegrasyon testi: 100 parça/10 dizin/minimum toplam boyut; Türkçe adlar,
  boş dosya/dizin; yanlış parola; kurtarma; kurcalama/eksik/tekrarlı parça/yol;
  imzalayan güveni; parola değişimi; üzerine yazmama; symlink reddi; çok bloklu
  içerik; arşiv kuyruğu; iptal temizliği; içerik listesi; anahtar parolası/açık
  anahtar; paket bilgisi; sınırlar; dosya izinleri; geçersiz komutlar.
- GUI offscreen regresyon programı: 5 SVG kaynak, lisans kataloğu, Türkçe ve
  İngilizce × açık/koyu/sistem teması, sekmeler, iki ana eylem, dosya ekleme
  tekrarları; doğru/yanlış makbuz senaryoları. Ekran çıktısı ayrıca incelendi.
- Release derlemeleri ve .deb oluşturma/çıkarma, paketler arası dosya çakışma
  kontrolü. Sistem kurulumu ve Debian 13 çalıştırmasıyla eşdeğer değildir.

## Küçük performans örnekleri

`test-results/benchmark.json`: 32 MiB tekrarlı veri ve 8 MiB rastgele veri,
fast/balanced/high profillerinde toplam 6 şifreleme–çözme çifti; bütün çıktılar
SHA-256 ile kaynaklarla eşleşti. İşçi başına 1 GiB sanal bellek sınırı uygulandı.
Tekrarlı veri yaklaşık 4,11 MB paket üretti; rastgele veri yaklaşık 8,46 MB.
Bu tek çalıştırmalık örnekler kapasite veya >4 GiB aktarım testi değildir.
Ortamın süreç görünürlüğü güvenilir RSS ölçümü vermediği için bellek tüketimi
sayıları rapora dahil edilmedi. Ubuntu üzerinde APT kurulum simülasyonu da geçti;
bu, gerçek kurulum/kaldırma testi değildir.

## Bu ortamda tamamlanamayan kontroller

Unix soketi bind ve chroot işlemleri `Operation not permitted` ile engelleniyor.
Bu yüzden gerçek ajan soketi, SSH/SFTP sunucu fixture'ı ve temiz Debian 13
kurulumu burada çalıştırılamadı. `tests/ecp_integration.py` bu ortamda 77 koduyla
"UNAVAILABLE" bildirir; başarılı test sayısına katılmaz.

Özellikle şu doğrulamalar açık kalır: gerçek SSH host-key değişimi/reconnect,
SFTP resume ve >4 GiB aktarımlar, kullanıcı değiştirilerek peer UID testi,
systemd yeniden başlatma/çocuk süreç kapanışı, Debian 13 kurulum-kaldırma,
Wayland/X11 gerçek masaüstü, ARM64, ekran okuyucu ve tüm diyalogların elle testi.
Buradaki otomatik kontroller bunların yerine geçmez. `.deb` dosyaları Ubuntu
24.04 amd64 üzerinde derlenmiş deneysel çıktılardır; Debian 13 için kaynaklardan
yeniden derleme ve hedef sistemde doğrulama gerekir.

## Kalan ürün sınırları

Bazı ileri durum/hata metinleri İngilizcedir. Dil değişikliği tüm sekme etiketleri
 için sekmeleri yeniden açmayı gerektirir. Sunucu upload rezervasyonu geçmişinin
otomatik temizliği yoktur; yönetici durdurulmuş ajan üzerinde bakım yapmalıdır.
ECP olmayan SFTP sunucusundaki rename davranışı sunucu uygulamasına bağlıdır;
çakışmayan yeni hedef adları kullanılmalıdır. Şifreleme işlerinin ortadan
sürdürülmesi yoktur. SSH hesabı ve sunucu yöneticisi güven sınırının içindedir.
