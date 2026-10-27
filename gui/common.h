#pragma once
#include <QSvgRenderer>
#include <QtWidgets>
#include <functional>
#include <memory>
inline bool turkish() {
  return QSettings("ESCrypter", "ESCrypter")
             .value("language", "tr")
             .toString() == "tr";
}
inline QString trText(const char *en, const char *tr) {
  return QString::fromUtf8(turkish() ? tr : en);
}
inline QIcon lockIcon(QString name = "locked") {
  QSvgRenderer svg(":/icons/" + name + ".svg");
  QIcon icon;
  for (int n : {16, 24, 32, 48, 64, 128, 256}) {
    QPixmap pix(n, n);
    pix.fill(Qt::transparent);
    QPainter p(&pix);
    svg.render(&p);
    p.end();
    icon.addPixmap(pix);
  }
  return icon;
}
inline QString newId() {
  return QUuid::createUuid().toString(QUuid::WithoutBraces);
}
inline QString stateHome() {
  auto p =
      QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
  QDir().mkpath(p);
  QFile::setPermissions(p,
                        QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);
  return p;
}
inline QString coreBinary() {
  QString p = QCoreApplication::applicationDirPath() + "/escrypter";
  return QFileInfo::exists(p) ? p : "escrypter";
}
inline QString secretDialog(QWidget *owner, QString title,
                            bool repeat = false) {
  QDialog d(owner);
  d.setWindowTitle(title);
  d.setWindowIcon(lockIcon("key"));
  QFormLayout l(&d);
  QLineEdit p, q;
  p.setEchoMode(QLineEdit::Password);
  q.setEchoMode(QLineEdit::Password);
  p.setMaxLength(4096);
  q.setMaxLength(4096);
  l.addRow(trText("Password", "Parola"), &p);
  if (repeat)
    l.addRow(trText("Repeat", "Tekrar"), &q);
  QCheckBox show(trText("Show password", "Parolayı göster"));
  l.addRow(&show);
  QObject::connect(&show, &QCheckBox::toggled, &d, [&](bool b) {
    p.setEchoMode(b ? QLineEdit::Normal : QLineEdit::Password);
    q.setEchoMode(b ? QLineEdit::Normal : QLineEdit::Password);
  });
  QPushButton generate(trText("Generate", "Üret"));
  if (repeat) {
    l.addRow(&generate);
    QObject::connect(&generate, &QPushButton::clicked, &d, [&] {
      QString s,
          alphabet =
              "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_";
      for (int i = 0; i < 24; i++)
        s += alphabet[QRandomGenerator::system()->bounded(alphabet.size())];
      p.setText(s);
      q.setText(s);
      show.setChecked(true);
    });
  }
  QDialogButtonBox b(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
  l.addRow(&b);
  QObject::connect(&b, &QDialogButtonBox::rejected, &d, &QDialog::reject);
  QObject::connect(&b, &QDialogButtonBox::accepted, &d, [&] {
    if (p.text().isEmpty() || p.text().contains('\n') ||
        p.text().contains('\r') ||
        (repeat && (p.text() != q.text() || p.text().size() < 12))) {
      QMessageBox::warning(
          &d, "ESCrypter",
          trText("Use matching passwords of at least 12 characters.",
                 "En az 12 karakterlik, eşleşen parolalar kullanın."));
      return;
    }
    d.accept();
  });
  if (d.exec() != QDialog::Accepted)
    return {};
  auto result = p.text();
  p.clear();
  q.clear();
  return result;
}
inline bool saveJson(QString path, const QJsonObject &obj) {
  QSaveFile f(path);
  if (!f.open(QIODevice::WriteOnly))
    return false;
  f.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
  auto bytes = QJsonDocument(obj).toJson();
  if (f.write(bytes) != bytes.size())
    return false;
  return f.commit();
}
inline QJsonObject loadJson(QString path) {
  QFile f(path);
  if (!f.open(QIODevice::ReadOnly) || f.size() > 8 * 1024 * 1024)
    return {};
  return QJsonDocument::fromJson(f.readAll()).object();
}
