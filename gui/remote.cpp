#include "remote.h"
RemoteSession::RemoteSession(Profile p, QObject *parent)
    : QObject(parent), profile(p) {
  connect(&ssh, &QProcess::readyReadStandardOutput, this, [this] {
    input += ssh.readAllStandardOutput();
    if (input.size() > 524288) {
      emit error("ECP receive limit exceeded");
      close();
      return;
    }
    while (input.size() >= 4) {
      quint32 n = (quint8(input[0]) << 24) | (quint8(input[1]) << 16) |
                  (quint8(input[2]) << 8) | quint8(input[3]);
      if (n == 0 || n > 262144) {
        emit error("Invalid ECP frame");
        close();
        return;
      }
      if (input.size() < qsizetype(n) + 4)
        break;
      auto o = QJsonDocument::fromJson(input.mid(4, n)).object();
      input.remove(0, n + 4);
      if (o["v"].toInt() != 1) {
        emit error("Unsupported ECP version");
        close();
        return;
      }
      auto id = o["id"].toString();
      if (pending.contains(id)) {
        auto cb = pending.take(id);
        deadlines.remove(id);
        cb(o);
      }
    }
  });
  connect(&ssh, &QProcess::readyReadStandardError, this, [this] {
    emit error(QString::fromUtf8(ssh.readAllStandardError()).left(4096));
  });
  connect(&ssh, &QProcess::started, this, [this] {
    request("hello", {}, [this](QJsonObject o) {
      if (!o["ok"].toBool()) {
        emit error(o["error"].toObject()["message"].toString());
        return;
      }
      hello = o["result"].toObject();
      if (hello["protocol"].toString() != "ECP" ||
          hello["version"].toInt() != 1) {
        emit error("Unsupported ECP peer");
        close();
        return;
      }
      connected = true;
      emit ready();
    });
  });
  connect(
      &ssh, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
      [this] {
        connected = false;
        auto callbacks = pending;
        pending.clear();
        deadlines.clear();
        for (auto cb : callbacks)
          cb({{"ok", false},
              {"error",
               QJsonObject{
                   {"message",
                    "Connection lost; refresh job list after reconnecting"}}}});
        emit disconnected();
      });
  connect(&ssh, &QProcess::errorOccurred, this,
          [this](auto) { emit error(ssh.errorString()); });
  timeout.setInterval(1000);
  connect(&timeout, &QTimer::timeout, this, [this] {
    auto now = QDateTime::currentMSecsSinceEpoch();
    for (auto id : deadlines.keys())
      if (deadlines[id] < now) {
        deadlines.remove(id);
        auto cb = pending.take(id);
        if (cb)
          cb({{"ok", false},
              {"error",
               QJsonObject{{"message",
                            "Request timed out; job may still be running"}}}});
      }
  });
  timeout.start();
}
void RemoteSession::open() {
  if (ssh.state() != QProcess::NotRunning)
    return;
  static QRegularExpression host("^[A-Za-z0-9][A-Za-z0-9.:-]*$"),
      user("^[A-Za-z_][A-Za-z0-9_.-]*[$]?$");
  if (!host.match(profile.host).hasMatch() ||
      !user.match(profile.user).hasMatch() ||
      !QFileInfo::exists(profile.knownHosts)) {
    emit error(trText("Invalid profile or missing known_hosts. Import the host "
                      "key through a trusted channel.",
                      "Profil geçersiz veya known_hosts eksik. Sunucu "
                      "anahtarını güvenilir kanaldan ekleyin."));
    return;
  }
  input.clear();
  QStringList args = {"-T",
                      "-F",
                      "/dev/null",
                      "-o",
                      "BatchMode=yes",
                      "-o",
                      "StrictHostKeyChecking=yes",
                      "-o",
                      "UserKnownHostsFile=" + profile.knownHosts,
                      "-o",
                      "GlobalKnownHostsFile=/dev/null",
                      "-o",
                      "ConnectTimeout=15",
                      "-o",
                      "ServerAliveInterval=15",
                      "-o",
                      "ServerAliveCountMax=3",
                      "-p",
                      QString::number(profile.port),
                      "-l",
                      profile.user};
  if (!profile.key.isEmpty())
    args << "-i" << profile.key << "-o" << "IdentitiesOnly=yes";
  args << profile.host << "escrypter-agent --bridge";
  ssh.start("/usr/bin/ssh", args);
}
void RemoteSession::close() {
  ssh.closeWriteChannel();
  ssh.terminate();
  connected = false;
}
QString RemoteSession::request(QString method, QJsonObject fields,
                               std::function<void(QJsonObject)> cb) {
  auto id = newId();
  fields["v"] = 1;
  fields["id"] = id;
  fields["method"] = method;
  auto b = QJsonDocument(fields).toJson(QJsonDocument::Compact);
  if (ssh.state() != QProcess::Running || b.size() > 262144) {
    cb({{"ok", false},
        {"error",
         QJsonObject{{"message", "Not connected or request too large"}}}});
    return id;
  }
  quint32 n = b.size();
  QByteArray prefix;
  prefix.append(char(n >> 24));
  prefix.append(char(n >> 16));
  prefix.append(char(n >> 8));
  prefix.append(char(n));
  pending[id] = cb;
  deadlines[id] = QDateTime::currentMSecsSinceEpoch() + 120000;
  ssh.write(prefix);
  ssh.write(b);
  b.fill(0);
  return id;
}
ServerView::ServerView(Profile p, QWidget *parent) : QWidget(parent) {
  session = new RemoteSession(p, this);
  auto layout = new QVBoxLayout(this);
  auto bar = new QHBoxLayout;
  path = new QLineEdit;
  path->setPlaceholderText(
      trText("Relative remote directory", "Göreli uzak dizin"));
  auto refreshButton = new QToolButton;
  refreshButton->setIcon(lockIcon("verified"));
  refreshButton->setToolTip(trText("Refresh", "Yenile"));
  bar->addWidget(path);
  bar->addWidget(refreshButton);
  layout->addLayout(bar);
  files = new QTreeWidget;
  files->setHeaderLabels(
      {trText("Name", "Ad"), trText("Type", "Tür"), trText("Bytes", "Bayt")});
  files->setSelectionMode(QAbstractItemView::ExtendedSelection);
  layout->addWidget(files, 2);
  jobs = new QTreeWidget;
  jobs->setHeaderLabels({trText("Job", "İş"), trText("Operation", "İşlem"),
                         trText("Status", "Durum"), trText("Output", "Çıktı")});
  layout->addWidget(jobs, 1);
  status = new QLabel(trText("Connecting…", "Bağlanıyor…"));
  layout->addWidget(status);
  events = new QPlainTextEdit;
  events->setReadOnly(true);
  events->setMaximumBlockCount(300);
  events->setMaximumHeight(110);
  layout->addWidget(events);
  connect(refreshButton, &QToolButton::clicked, this, &ServerView::refresh);
  connect(path, &QLineEdit::returnPressed, this, &ServerView::refresh);
  connect(files, &QTreeWidget::itemDoubleClicked, this, [this](auto item, int) {
    if (item->data(0, Qt::UserRole).toBool()) {
      path->setText(selectedPath());
      refresh();
    }
  });
  connect(session, &RemoteSession::ready, this, [this] {
    status->setText(trText("Connected · processing runs on this server",
                           "Bağlı · işlemler bu sunucuda çalışır"));
    refresh();
    poll();
  });
  connect(session, &RemoteSession::error, this,
          [this](auto e) { status->setText(e); });
  connect(session, &RemoteSession::disconnected, this, [this] {
    status->setText(trText("Disconnected · remote jobs may continue",
                           "Bağlantı kesildi · uzak işler sürebilir"));
    polling = false;
  });
  timer.setInterval(2000);
  connect(&timer, &QTimer::timeout, this, &ServerView::poll);
  timer.start();
  if (p.agent)
    session->open();
  else
    status->setText(
        trText("SFTP-only profile · use Connections → Upload / Download",
               "Yalnızca SFTP profili · Bağlantılar → Yükle / İndir"));
}
QString ServerView::selectedPath() const {
  auto items = files->selectedItems();
  if (items.isEmpty())
    return {};
  return path->text().isEmpty() ? items[0]->text(0)
                                : path->text() + "/" + items[0]->text(0);
}
QString ServerView::selectedJob() const {
  auto a = jobs->selectedItems();
  return a.isEmpty() ? QString() : a[0]->text(0);
}
void ServerView::refresh() {
  if (!session->profile.agent)
    return;
  if (!session->connected) {
    session->open();
    return;
  }
  files->clear();
  auto directory = path->text();
  auto page = std::make_shared<std::function<void(int)>>();
  QPointer<ServerView> self = this;
  *page = [self, directory, page](int offset) {
    if (!self)
      return;
    self->session->request(
        "list", {{"path", directory}, {"offset", offset}},
        [self, directory, page](QJsonObject o) {
          if (!self)
            return;
          if (!o["ok"].toBool()) {
            self->status->setText(o["error"].toObject()["message"].toString());
            *page = {};
            return;
          }
          auto result = o["result"].toObject();
          if (self->path->text() != directory) {
            *page = {};
            return;
          }
          for (auto value : result["entries"].toArray()) {
            auto e = value.toObject();
            auto row = new QTreeWidgetItem(
                self->files,
                {e["name"].toString(),
                 e["symlink"].toBool()     ? "link"
                 : e["directory"].toBool() ? "folder"
                                           : "file",
                 QString::number(e["bytes"].toVariant().toLongLong())});
            row->setData(0, Qt::UserRole,
                         e["directory"].toBool() && !e["symlink"].toBool());
            row->setIcon(
                0, lockIcon(e["symlink"].toBool() ? "warning" : "locked"));
          }
          if (!result["next"].isNull())
            (*page)(result["next"].toInt());
          else
            *page = {};
        });
  };
  (*page)(0);
}
void ServerView::poll() {
  if (!session->connected || polling)
    return;
  polling = true;
  QPointer<ServerView> self = this;
  session->request("jobs", {}, [self](QJsonObject o) {
    if (!self)
      return;
    self->polling = false;
    if (!o["ok"].toBool())
      return;
    auto resources = o["result"].toObject()["resources"].toObject();
    self->status->setText(
        trText("Server free space: ", "Sunucu boş alanı: ") +
        QLocale().formattedDataSize(
            resources["free_disk_bytes"].toVariant().toLongLong()) +
        QString(" · %1/%2 jobs")
            .arg(resources["running"].toInt())
            .arg(resources["max_jobs"].toInt()));
    auto selected = self->selectedJob();
    self->jobs->clear();
    for (auto v : o["result"].toObject()["jobs"].toArray()) {
      auto j = v.toObject();
      auto id = j["id"].toString();
      auto row = new QTreeWidgetItem(self->jobs, {id, j["operation"].toString(),
                                                  j["status"].toString(),
                                                  j["output"].toString()});
      if (id == selected)
        row->setSelected(true);
      if (j["seq"].toVariant().toULongLong() > self->cursors.value(id)) {
        self->session->request(
            "events",
            {{"job_id", id}, {"after", qint64(self->cursors.value(id))}},
            [self, id](QJsonObject o) {
              if (!self || !o["ok"].toBool())
                return;
              auto r = o["result"].toObject();
              if (r["gap"].toBool())
                self->events->appendPlainText(
                    trText("Some old events have expired.",
                           "Bazı eski olayların saklama süresi dolmuş."));
              for (auto v : r["events"].toArray()) {
                auto e = v.toObject();
                self->cursors[id] = e["seq"].toVariant().toULongLong();
                auto event = e["event"].toObject();
                self->events->appendPlainText(
                    id.left(8) + " · " + event["event"].toString() + " · " +
                    QString::fromUtf8(QJsonDocument(event["data"].toObject())
                                          .toJson(QJsonDocument::Compact)));
              }
            });
      }
    }
  });
}
void ServerView::submit(QJsonObject spec, QJsonArray secrets) {
  QPointer<ServerView> self = this;
  session->request(
      "submit", {{"job_id", newId()}, {"spec", spec}, {"secrets", secrets}},
      [self](QJsonObject o) {
        if (!self)
          return;
        if (!o["ok"].toBool())
          QMessageBox::warning(self, "ECP",
                               o["error"].toObject()["message"].toString());
        else
          self->poll();
      });
}
void ServerView::cancelSelected() {
  auto id = selectedJob();
  if (id.isEmpty())
    return;
  session->request("cancel", {{"job_id", id}}, [this](QJsonObject o) {
    if (!o["ok"].toBool())
      status->setText(o["error"].toObject()["message"].toString());
  });
}
