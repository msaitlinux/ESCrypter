#include "transfers.h"
#include "receipt.h"
#include <QtConcurrent>
#include <curl/curl.h>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <mutex>
#include <sodium.h>
#include <sys/stat.h>
#include <unistd.h>
namespace {
QString digest(QString path,
               quint64 prefix = std::numeric_limits<quint64>::max()) {
  QFile f(path);
  if (!f.open(QIODevice::ReadOnly))
    return {};
  QCryptographicHash h(QCryptographicHash::Sha256);
  while (!f.atEnd() && prefix) {
    auto b = f.read(qMin<quint64>(1024 * 1024, prefix));
    if (b.isEmpty() && f.error() != QFile::NoError)
      return {};
    h.addData(b);
    prefix -= b.size();
  }
  return h.result().toHex();
}
QString quotePath(QString p) {
  p.replace("\\", "\\\\");
  p.replace("\"", "\\\"");
  return '"' + p + '"';
}
} // namespace
void Transfers::asyncDigest(QObject *, QString path, quint64 prefix,
                            std::function<void(QString)> done) {
  const auto epoch = generation;
  ++pendingOperations;
  auto w = new QFutureWatcher<QString>(this);
  connect(w, &QFutureWatcher<QString>::finished, this, [this, w, done, epoch] {
    auto result = w->result();
    w->deleteLater();
    if (epoch != generation)
      return;
    --pendingOperations;
    done(result);
  });
  w->setFuture(
      QtConcurrent::run([path, prefix] { return digest(path, prefix); }));
}
void Transfers::request(RemoteSession *peer, QString method, QJsonObject fields,
                        std::function<void(QJsonObject)> done) {
  const auto epoch = generation;
  ++pendingOperations;
  QPointer<Transfers> guard(this);
  peer->request(method, fields, [this, guard, epoch, done](QJsonObject r) {
    if (!guard || epoch != generation)
      return;
    --pendingOperations;
    done(r);
  });
}
void TransferWorker::run() {
  static std::once_flag init;
  std::call_once(init, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
  auto info = curl_version_info(CURLVERSION_NOW);
  bool supported = false;
  for (auto p = info->protocols; *p; p++)
    if (QByteArray(*p) == "sftp")
      supported = true;
  if (!supported) {
    emit outcome(false, "This libcurl build has no SFTP support");
    return;
  }
  if (!spec.remote.startsWith('/') || spec.remote.contains('\n') ||
      spec.remote.contains('\r')) {
    emit outcome(false, "An absolute SFTP path is required");
    return;
  }
  if (!QFileInfo(spec.profile.knownHosts).isFile()) {
    emit outcome(false, "A trusted known_hosts file is required");
    return;
  }
  QFile f;
  int flags = O_CLOEXEC | O_NOFOLLOW;
  flags |= spec.upload ? O_RDONLY
                       : (spec.offset ? O_WRONLY | O_APPEND
                                      : O_WRONLY | O_CREAT | O_EXCL);
  int fd = ::open(QFile::encodeName(spec.local).constData(), flags, 0600);
  if (fd < 0) {
    emit outcome(false, QString::fromLocal8Bit(strerror(errno)));
    return;
  }
  struct stat meta {};
  if (fstat(fd, &meta) != 0 || !S_ISREG(meta.st_mode) ||
      (!spec.upload && (meta.st_uid != getuid() || meta.st_nlink != 1))) {
    ::close(fd);
    emit outcome(false, "Unsafe local transfer file");
    return;
  }
  if (!f.open(fd, spec.upload ? QIODevice::ReadOnly : QIODevice::WriteOnly,
              QFileDevice::AutoCloseHandle)) {
    ::close(fd);
    emit outcome(false, f.errorString());
    return;
  }
  if (!spec.upload)
    f.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
  if (spec.offset > quint64(f.size()) ||
      (!spec.upload && spec.offset != quint64(f.size()))) {
    emit outcome(false, "Resume offset does not match local file");
    return;
  }
  auto c = curl_easy_init();
  if (!c) {
    emit outcome(false, "Cannot initialize libcurl");
    return;
  }
  QUrl url;
  url.setScheme("sftp");
  url.setHost(spec.profile.host);
  url.setPort(spec.profile.port);
  url.setPath(spec.remote);
  QByteArray u = url.toEncoded(), user = spec.profile.user.toUtf8(),
             known = QFile::encodeName(spec.profile.knownHosts),
             key = QFile::encodeName(spec.profile.key);
  char error[CURL_ERROR_SIZE] = {0};
  curl_easy_setopt(c, CURLOPT_ERRORBUFFER, error);
  curl_easy_setopt(c, CURLOPT_URL, u.constData());
  curl_easy_setopt(c, CURLOPT_USERNAME, user.constData());
  curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "sftp");
  curl_easy_setopt(c, CURLOPT_SSH_KNOWNHOSTS, known.constData());
  curl_easy_setopt(c, CURLOPT_SSH_AUTH_TYPES,
                   long(CURLSSH_AUTH_AGENT | CURLSSH_AUTH_PUBLICKEY));
  if (!key.isEmpty())
    curl_easy_setopt(c, CURLOPT_SSH_PRIVATE_KEYFILE, key.constData());
  curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 20L);
  curl_easy_setopt(c, CURLOPT_LOW_SPEED_LIMIT, 1L);
  curl_easy_setopt(c, CURLOPT_LOW_SPEED_TIME, 120L);
  curl_easy_setopt(c, CURLOPT_NOPROGRESS, 0L);
  curl_easy_setopt(c, CURLOPT_FAILONERROR, 1L);
  struct Context {
    QFile *f;
    TransferWorker *self;
    TransferSpec *s;
    quint64 written;
  };
  Context ctx{&f, this, &spec, spec.offset};
  curl_easy_setopt(c, CURLOPT_XFERINFODATA, &ctx);
  curl_easy_setopt(
      c, CURLOPT_XFERINFOFUNCTION,
      +[](void *p, curl_off_t dt, curl_off_t dn, curl_off_t ut,
          curl_off_t un) -> int {
        auto x = static_cast<Context *>(p);
        if (x->self->stop.load())
          return 1;
        emit x->self->progress((x->s->upload ? un : dn) + x->s->offset,
                               (x->s->upload ? ut : dt) + x->s->offset);
        return 0;
      });
  if (spec.upload) {
    curl_easy_setopt(c, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(c, CURLOPT_INFILESIZE_LARGE, curl_off_t(f.size()));
    curl_easy_setopt(c, CURLOPT_READDATA, &ctx);
    curl_easy_setopt(
        c, CURLOPT_READFUNCTION,
        +[](char *b, size_t size, size_t count, void *p) -> size_t {
          auto x = static_cast<Context *>(p);
          if (x->self->stop.load())
            return CURL_READFUNC_ABORT;
          auto n = x->f->read(b, size * count);
          return n < 0 ? CURL_READFUNC_ABORT : size_t(n);
        });
    curl_easy_setopt(c, CURLOPT_SEEKDATA, &ctx);
    curl_easy_setopt(
        c, CURLOPT_SEEKFUNCTION,
        +[](void *p, curl_off_t offset, int origin) -> int {
          auto x = static_cast<Context *>(p);
          return origin == SEEK_SET && x->f->seek(offset) ? CURL_SEEKFUNC_OK
                                                          : CURL_SEEKFUNC_FAIL;
        });
  } else {
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &ctx);
    curl_easy_setopt(
        c, CURLOPT_WRITEFUNCTION,
        +[](char *b, size_t size, size_t count, void *p) -> size_t {
          auto x = static_cast<Context *>(p);
          auto n = size * count;
          if (x->self->stop.load() ||
              (x->s->limit && x->written + n > x->s->limit))
            return 0;
          auto wrote = x->f->write(b, n);
          if (wrote < 0)
            return 0;
          x->written += wrote;
          return size_t(wrote);
        });
  }
  if (spec.offset)
    curl_easy_setopt(c, CURLOPT_RESUME_FROM_LARGE, curl_off_t(spec.offset));
  if (spec.speed) {
    curl_easy_setopt(c, CURLOPT_MAX_SEND_SPEED_LARGE, curl_off_t(spec.speed));
    curl_easy_setopt(c, CURLOPT_MAX_RECV_SPEED_LARGE, curl_off_t(spec.speed));
  }
  curl_slist *commands = nullptr;
  QByteArray rename;
  if (!spec.renameTo.isEmpty()) {
    rename =
        ("rename " + quotePath(spec.remote) + " " + quotePath(spec.renameTo))
            .toUtf8();
    commands = curl_slist_append(commands, rename.constData());
    curl_easy_setopt(c, CURLOPT_POSTQUOTE, commands);
  }
  auto result = curl_easy_perform(c);
  if (!spec.upload && (!f.flush() || ::fsync(f.handle()) != 0) &&
      result == CURLE_OK)
    result = CURLE_WRITE_ERROR;
  curl_slist_free_all(commands);
  curl_easy_cleanup(c);
  emit outcome(
      result == CURLE_OK,
      result == CURLE_OK ? QString()
      : stop.load()
          ? "Cancelled"
          : QString::fromUtf8(error[0] ? error : curl_easy_strerror(result)));
}
Transfers::Transfers(QWidget *p) : QWidget(p) {
  auto l = new QVBoxLayout(this);
  auto intro = new QLabel(trText(
      "SFTP transfers · SSH host keys must already be trusted",
      "SFTP aktarımları · SSH sunucu anahtarı önceden güvenilir olmalı"));
  intro->setWordWrap(true);
  l->addWidget(intro);
  rows = new QTreeWidget;
  rows->setHeaderLabels({trText("File", "Dosya"), trText("Direction", "Yön"),
                         trText("Progress", "İlerleme"),
                         trText("Status", "Durum")});
  l->addWidget(rows);
  auto cancel = new QPushButton(lockIcon("warning"),
                                trText("Cancel selected", "Seçileni iptal et"));
  l->addWidget(cancel);
  connect(cancel, &QPushButton::clicked, this, [this] {
    for (auto w : workers)
      if (items[w]->isSelected())
        w->cancel();
    for (auto row : queuedRows)
      if (row->isSelected()) {
        row->setData(0, Qt::UserRole, true);
        row->setText(3, trText("Cancelled", "İptal edildi"));
      }
  });
}
void Transfers::pump() {
  int max = qBound(
      1, QSettings("ESCrypter", "ESCrypter").value("transfers", 2).toInt(), 4);
  while (running < max && !waiting.isEmpty()) {
    running++;
    auto fn = waiting.takeFirst();
    fn();
  }
}
bool Transfers::active() const {
  return running > 0 || pendingOperations > 0 || !waiting.isEmpty();
}
void Transfers::cancelAll() {
  ++generation;
  pendingOperations = 0;
  for (auto row : queuedRows)
    row->setText(3, trText("Cancelled", "İptal edildi"));
  queuedRows.clear();
  waiting.clear();
  for (auto w : workers)
    w->cancel();
}
void Transfers::launch(TransferSpec spec,
                       std::function<void(bool, QString)> done) {
  auto row = new QTreeWidgetItem(rows, {QFileInfo(spec.local).fileName(),
                                        spec.upload ? "↑" : "↓", "",
                                        trText("Queued", "Kuyrukta")});
  row->setIcon(0, lockIcon());
  queuedRows << row;
  const auto epoch = generation;
  waiting << [this, spec, done, row, epoch] {
    queuedRows.removeOne(row);
    if (row->data(0, Qt::UserRole).toBool()) {
      --running;
      return;
    }
    auto w = new TransferWorker(spec, this);
    workers << w;
    items[w] = row;
    row->setText(3, trText("Transferring", "Aktarılıyor"));
    connect(w, &TransferWorker::progress, this, [row](auto b, auto total) {
      row->setText(
          2, total > 0
                 ? QString::number(qMin<qint64>(100, 100 * b / total)) + "%"
                 : QString::number(b));
    });
    connect(w, &TransferWorker::outcome, this,
            [this, done, row, epoch](bool ok, QString detail) {
              row->setText(3, ok ? trText("Transferred; finalizing",
                                          "Aktarıldı; sonlandırılıyor")
                                 : detail);
              if (epoch == generation)
                done(ok, detail);
              if (ok)
                row->setText(
                    3, trText("Transport complete — see verification result",
                              "Aktarım tamam — doğrulama sonucuna bakın"));
            });
    connect(w, &QThread::finished, this, [this, w] {
      workers.removeOne(w);
      items.remove(w);
      w->deleteLater();
      running--;
      pump();
    });
    w->start();
  };
  pump();
}
void Transfers::upload(Profile profile, RemoteSession *session, QString local,
                       QString remote) {
  if (!QFileInfo(local).isFile())
    return;
  auto speed =
      QSettings("ESCrypter", "ESCrypter").value("bandwidth", 0).toULongLong() *
      1024;
  QPointer<RemoteSession> peer = session;
  if (profile.agent && (!session || !session->connected)) {
    QMessageBox::warning(this, "ECP",
                         trText("Reconnect ECP before transferring.",
                                "Aktarımdan önce ECP bağlantısını yenileyin."));
    return;
  }
  if (!profile.agent) {
    if (!remote.startsWith('/')) {
      QMessageBox::warning(this, "SFTP",
                           "Absolute remote path required without ECP");
      return;
    }
    auto temp = remote + ".part-" + newId();
    launch({profile, local, temp, remote, true, 0, 0, speed},
           [this](bool ok, QString e) {
             QMessageBox::information(
                 this, "SFTP",
                 ok ? trText("Upload complete. ECP receipt/remote digest "
                             "unavailable on this server.",
                             "Yükleme tamamlandı. Bu sunucuda ECP makbuzu/uzak "
                             "özet doğrulaması yok.")
                    : e);
           });
    return;
  }
  const auto size = QFileInfo(local).size();
  const auto pinned = peer->hello["receipt_public_key"].toString();
  asyncDigest(
      this, local, std::numeric_limits<quint64>::max(),
      [this, profile, peer, local, remote, speed, size, pinned](QString sha) {
        if (!peer || !peer->connected || sha.isEmpty())
          return;
        auto cache = loadJson(stateHome() + "/uploads.json");
        auto identity =
            QString(QCryptographicHash::hash(
                        (profile.host + ":" + QString::number(profile.port) +
                         ":" + profile.user + ":" + remote + ":" + sha)
                            .toUtf8(),
                        QCryptographicHash::Sha256)
                        .toHex());
        auto uid = cache[identity].toString();
        if (uid.isEmpty()) {
          uid = newId();
          cache[identity] = uid;
          saveJson(stateHome() + "/uploads.json", cache);
        }
        auto accept = [this, uid, sha, size, pinned](QJsonObject receipt) {
          if (!validReceipt(receipt, pinned, uid, sha, size)) {
            QMessageBox::warning(
                this, "ECP",
                trText(
                    "Receipt signature or content does not match this upload.",
                    "Makbuz imzası veya içeriği bu yüklemeyle eşleşmiyor."));
            return;
          }
          if (!saveJson(stateHome() + "/receipt-" + uid + ".json", receipt)) {
            QMessageBox::warning(
                this, "ECP",
                trText("Upload verified, but receipt could not be saved.",
                       "Yükleme doğrulandı ancak makbuz kaydedilemedi."));
            return;
          }
          QMessageBox::information(
              this, "ECP",
              trText("File finalized; signed receipt verified and saved.",
                     "Dosya sonlandırıldı; imzalı makbuz doğrulandı ve "
                     "kaydedildi."));
        };
        request(
            peer, "upload_prepare",
            {{"upload_id", uid},
             {"path", remote},
             {"size", size},
             {"sha256", sha}},
            [this, profile, peer, local, speed, size, uid,
             accept](QJsonObject o) {
              if (!peer)
                return;
              if (!o["ok"].toBool()) {
                QMessageBox::warning(
                    this, "ECP", o["error"].toObject()["message"].toString());
                return;
              }
              auto r = o["result"].toObject();
              if (r["finished"].toBool()) {
                accept(r["receipt"].toObject());
                return;
              }
              auto offset = r["offset"].toVariant().toULongLong();
              if (offset > quint64(size)) {
                QMessageBox::warning(this, "ECP", "Invalid resume offset");
                return;
              }
              auto prefix = r["prefix_sha256"].toString();
              auto temporary = r["temporary_path"].toString();
              asyncDigest(
                  this, local, offset,
                  [this, profile, peer, local, speed, uid, offset, prefix,
                   temporary, accept](QString got) {
                    if (!peer || !peer->connected)
                      return;
                    if (got != prefix) {
                      QMessageBox::warning(
                          this, "ECP",
                          trText(
                              "Partial upload does not match; refusing to "
                              "resume.",
                              "Kısmi dosya eşleşmiyor; sürdürme reddedildi."));
                      return;
                    }
                    launch(
                        {profile, local, temporary, {}, true, offset, 0, speed},
                        [this, peer, uid, accept](bool ok, QString) {
                          if (!ok || !peer)
                            return;
                          request(peer, "upload_finish", {{"upload_id", uid}},
                                  [this, accept](QJsonObject o) {
                                    if (!o["ok"].toBool()) {
                                      QMessageBox::warning(
                                          this, "ECP",
                                          o["error"]
                                              .toObject()["message"]
                                              .toString());
                                      return;
                                    }
                                    accept(o["result"]
                                               .toObject()["receipt"]
                                               .toObject());
                                  });
                        });
                  });
            });
      });
}

void Transfers::download(Profile profile, RemoteSession *session,
                         QString remote, QString local) {
  if (QFileInfo::exists(local)) {
    QMessageBox::warning(
        this, "SFTP",
        trText("Destination already exists", "Hedef zaten mevcut"));
    return;
  }
  auto speed =
      QSettings("ESCrypter", "ESCrypter").value("bandwidth", 0).toULongLong() *
      1024;
  QPointer<RemoteSession> peer = session;
  auto begin = [this, profile, peer, remote, local,
                speed](QString sha, quint64 size, QString absolute) {
    auto temp =
        local + ".part-" +
        QString(QCryptographicHash::hash(
                    (profile.host + profile.user + remote + sha).toUtf8(),
                    QCryptographicHash::Sha256)
                    .toHex())
            .left(24);
    if (sha.isEmpty())
      temp += "-" + newId();
    quint64 offset = QFileInfo(temp).exists() ? QFileInfo(temp).size() : 0;
    auto start = [this, profile, local, temp, speed, sha, size,
                  absolute](quint64 offset) {
      launch(
          {profile, temp, absolute, {}, false, offset, size, speed},
          [this, temp, local, sha](bool ok, QString e) {
            if (!ok)
              return;
            asyncDigest(
                this, temp, std::numeric_limits<quint64>::max(),
                [this, temp, local, sha](QString got) {
                  if (!sha.isEmpty() && got != sha) {
                    QMessageBox::warning(
                        this, "SFTP",
                        trText(
                            "Downloaded hash mismatch; partial file retained",
                            "İndirilen dosyanın özeti eşleşmiyor; kısmi dosya "
                            "korundu"));
                    return;
                  }
                  if (!QFile::rename(temp, local)) {
                    QMessageBox::warning(
                        this, "SFTP",
                        trText("Cannot publish output without overwriting",
                               "Çıktı üzerine yazmadan sonlandırılamadı"));
                    return;
                  }
                  QMessageBox::information(
                      this, "SFTP",
                      sha.isEmpty()
                          ? trText("Download complete; verify package "
                                   "signature before use.",
                                   "İndirme tamam; kullanmadan önce paket "
                                   "imzasını doğrulayın.")
                          : trText("Download complete; SHA-256 matched.",
                                   "İndirme tamam; SHA-256 eşleşti."));
                });
          });
    };
    if (offset && peer && peer->connected) {
      request(peer, "hash",
              {{"path", remote}, {"prefix_bytes", qint64(offset)}},
              [this, peer, temp, offset, start](QJsonObject o) {
                if (!peer || !o["ok"].toBool())
                  return;
                auto prefix = o["result"].toObject()["sha256"].toString();
                asyncDigest(this, temp, offset,
                            [this, prefix, offset, start](QString got) {
                              if (got != prefix) {
                                QMessageBox::warning(
                                    this, "SFTP", "Partial download mismatch");
                                return;
                              }
                              start(offset);
                            });
              });
    } else
      start(0);
  };
  if (peer && peer->connected) {
    request(peer, "hash", {{"path", remote}},
            [peer, remote, begin, this](QJsonObject o) {
              if (!peer)
                return;
              if (!o["ok"].toBool()) {
                QMessageBox::warning(
                    this, "ECP", o["error"].toObject()["message"].toString());
                return;
              }
              auto r = o["result"].toObject();
              begin(r["sha256"].toString(),
                    r["bytes"].toVariant().toULongLong(),
                    peer->hello["root"].toString() + "/" + remote);
            });
  } else if (remote.startsWith('/'))
    begin({}, 0, remote);
  else
    QMessageBox::warning(this, "SFTP", "Absolute remote path required");
}
