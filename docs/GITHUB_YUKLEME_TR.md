# GitHub'a yükleme

1. ZIP'i çıkarın. `ESCrypter/` içindeki README.md, Cargo.toml, src/, gui/,
   vendor/ ve gizli `.github/`, `.cargo/` dizinleri depo kökünde olmalı.
2. GitHub'da `ESCrypter` adlı boş bir depo oluşturun. Hazır LICENSE/README seçmeyin;
   bunlar bu pakette mevcut. ZIP dosyasını olduğu gibi depoya yüklemek yerine
   içindeki dosyaları Git ile gönderin (çok sayıda vendor dosyası vardır).
3. Bu klasörde aşağıdaki komutları çalıştırın; KULLANICI yerine hesabınızı yazın:

```bash
git init -b main
git add .
git add -f vendor
git update-index --chmod=+x build.sh package-deb.sh package-single-deb.sh tests/run-checks.sh
git commit -m "Initial ESCrypter source and GitHub project files"
git remote add origin https://github.com/KULLANICI/ESCrypter.git
git push -u origin main
```

Git kimliği sorarsa kendi adınızı/e-postanızı yapılandırın. Kimlik doğrulama için
GitHub'ın desteklediği yöntemi kullanın; erişim tokenini dosyalara veya URL'ye yazmayın.

## İlk yüklemeden sonra

- Security ayarlarından private vulnerability reporting'i etkinleştirin.
- Actions sekmesinde Ubuntu ve Debian 13 işlerinin sonucunu kontrol edin.
  YAML hazırlanmış olması bu kontrollerin geçmiş olduğu anlamına gelmez.
- Ana dal için başarılı CI ve PR incelemesi gerektiren koruma kuralı ekleyin.
- Gerekiyorsa güvenlik iletişim kanalınızı SECURITY.md'ye ekleyin.
- İlk sürümü prerelease olarak yayımlayın. Başarılı hedef derlemesinin tek `.deb`
  çıktısını ve SHA256SUMS'u Release'e ekleyin. Kaynak ağaçta binary tutulmaz.
- Uygulama 0.2.0, birleşik Debian paket revizyonu 0.2.0-1'dir. Etiketi örneğin
  `v0.2.0-rc.1` kullanın; test edilmemiş sürümü stable ilan etmeyin.

Workflow depoya/release'e yazma izni istemez; yalnız kontrol ve build artifact
üretir. Gerçek SSH/SFTP ve masaüstü oturum testleri ayrı doğrulanmalıdır.
Action sürümlerinin resmi belgeleri: https://github.com/actions/checkout ve
https://github.com/actions/upload-artifact (26 Ekim 2026'da incelendi).
