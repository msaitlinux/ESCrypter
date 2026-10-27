#include "receipt.h"
#include "window.h"
#include <iostream>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      std::cerr << "FAIL line " << __LINE__ << ": " #x << "\n";                \
      return 1;                                                                \
    }                                                                          \
  } while (0)
int main(int argc, char **argv) {
  QApplication app(argc, argv);
  QCoreApplication::setOrganizationName("ESCrypter");
  QCoreApplication::setApplicationName("ESCrypter-test");
  QTemporaryDir temp;
  CHECK(temp.isValid());
  QSettings::setPath(QSettings::NativeFormat, QSettings::UserScope,
                     temp.path());
  for (auto name : {"locked", "unlocked", "key", "verified", "warning"}) {
    QSvgRenderer svg(QString(":/icons/") + name + ".svg");
    CHECK(svg.isValid());
    auto pix = lockIcon(name).pixmap(64);
    CHECK(!pix.isNull());
    CHECK(pix.toImage().pixelColor(32, 32).alpha() > 0);
  }
  QFile catalog(":/licenses/catalog.json");
  CHECK(catalog.open(QIODevice::ReadOnly));
  auto json = QJsonDocument::fromJson(catalog.readAll()).object();
  CHECK(!json["draft"].toBool());
  CHECK(json["components"].toArray().size() > 30);
  for (auto language : {"tr", "en"})
    for (auto theme : {"light", "dark", "system"}) {
      QSettings settings("ESCrypter", "ESCrypter");
      settings.setValue("language", language);
      settings.setValue("theme", theme);
      Window w;
      w.show();
      app.processEvents();
      auto tabs = w.findChild<QTabWidget *>();
      CHECK(tabs);
      CHECK(tabs->tabsClosable());
      CHECK(tabs->isMovable());
      CHECK(w.menuBar()->actions().size() == 7);
      CHECK(!w.windowIcon().isNull());
      auto workspace = w.findChild<Workspace *>();
      CHECK(workspace);
      CHECK(workspace->findChildren<QPushButton *>().size() == 2);
      auto path = temp.filePath("Türkçe.txt");
      QFile f(path);
      CHECK(f.open(QIODevice::WriteOnly));
      f.write("hello");
      f.close();
      workspace->addPaths({path, path});
      CHECK(workspace->paths().size() == 1);
      QAction *newTab = nullptr;
      for (auto a : w.findChildren<QAction *>())
        if (a->shortcut() == QKeySequence("Ctrl+T"))
          newTab = a;
      CHECK(newTab);
      newTab->trigger();
      CHECK(tabs->count() == 2);
      if (QString(language) == "en" && QString(theme) == "dark" && argc > 1)
        CHECK(w.grab().save(argv[1]));
      w.close();
    }
  CHECK(sodium_init() >= 0);
  unsigned char pk[32], sk[64], sig[64];
  crypto_sign_keypair(pk, sk);
  auto payload = QJsonDocument(QJsonObject{{"v", 1},
                                           {"upload_id", "test-upload"},
                                           {"sha256", "abcd"},
                                           {"bytes", 42}})
                     .toJson(QJsonDocument::Compact);
  // Protocol domain length is explicitly 21, including the single NUL byte.
  QByteArray message("ESCrypter receipt v1\0", 21);
  message += payload;
  crypto_sign_detached(
      sig, nullptr,
      reinterpret_cast<const unsigned char *>(message.constData()),
      message.size(), sk);
  QString publicKey = QByteArray(reinterpret_cast<char *>(pk), 32).toHex();
  QJsonObject receipt{
      {"public_key", publicKey},
      {"signature",
       QString(QByteArray(reinterpret_cast<char *>(sig), 64).toHex())},
      {"payload_hex", QString(payload.toHex())}};
  CHECK(validReceipt(receipt, publicKey, "test-upload", "abcd", 42));
  CHECK(!validReceipt(receipt, publicKey, "another-upload", "abcd", 42));
  CHECK(!validReceipt(receipt, publicKey, "test-upload", "abcd", 43));
  CHECK(!validReceipt(receipt, "wrong-key", "test-upload", "abcd", 42));
  receipt["payload_hex"] = QString((payload + " ").toHex());
  CHECK(!validReceipt(receipt, publicKey, "test-upload", "abcd", 42));
  std::cout << "GUI smoke PASS: 5 SVG icons; license catalog; 6 language/theme "
               "combinations; tabs; input deduplication; receipt "
               "acceptance/rejection.\n";
}
