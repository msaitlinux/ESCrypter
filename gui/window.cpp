#include "window.h"
#include <QtConcurrent>
#include <unistd.h>
Workspace::Workspace(QWidget *p) : QWidget(p) {
  setAcceptDrops(true);
  auto l = new QVBoxLayout(this);
  auto intro = new QLabel(
      trText("Drop files or folders here. Originals are preserved.",
             "Dosya veya klasörleri buraya bırakın. Kaynaklar korunur."));
  intro->setWordWrap(true);
  l->addWidget(intro);
  files = new QTreeWidget;
  files->setSelectionMode(QAbstractItemView::ExtendedSelection);
  files->setContextMenuPolicy(Qt::CustomContextMenu);
  l->addWidget(files, 1);
  connect(files, &QWidget::customContextMenuRequested, this, [this](QPoint at) {
    QMenu m;
    auto remove = m.addAction(trText("Remove selected", "Seçileni kaldır"));
    if (m.exec(files->viewport()->mapToGlobal(at)) == remove) {
      qDeleteAll(files->selectedItems());
      retranslate();
    }
  });
  auto footer = new QHBoxLayout;
  summary = new QLabel;
  footer->addWidget(summary, 1);
  compression = new QComboBox;
  compression->addItems({trText("Fast", "Hızlı"), trText("Balanced", "Dengeli"),
                         trText("High compression", "Yüksek sıkıştırma")});
  compression->setCurrentIndex(
      QSettings("ESCrypter", "ESCrypter").value("compression", 1).toInt());
  footer->addWidget(compression);
  l->addLayout(footer);
  auto actions = new QHBoxLayout;
  auto enc = new QPushButton(lockIcon(), trText("Encrypt", "Şifrele"));
  auto dec =
      new QPushButton(lockIcon("unlocked"), trText("Open package", "Paket aç"));
  actions->addStretch();
  actions->addWidget(enc);
  actions->addWidget(dec);
  l->addLayout(actions);
  connect(enc, &QPushButton::clicked, this, &Workspace::encryptRequested);
  connect(dec, &QPushButton::clicked, this, &Workspace::openRequested);
  retranslate();
}
void Workspace::retranslate() {
  files->setHeaderLabels({trText("Name", "Ad"), trText("Type", "Tür"),
                          trText("Size", "Boyut"),
                          trText("Location", "Konum")});
  summary->setText(trText("Selected: ", "Seçilen: ") +
                   QString::number(files->topLevelItemCount()) +
                   trText(" · minimum package 4 MB", " · minimum paket 4 MB"));
}
void Workspace::addPaths(QStringList list) {
  auto existing = paths();
  for (auto p : list) {
    QFileInfo f(p);
    auto abs = f.absoluteFilePath();
    if (existing.contains(abs))
      continue;
    auto row = new QTreeWidgetItem(
        files,
        {f.fileName(),
         f.isDir() ? trText("Folder", "Klasör") : trText("File", "Dosya"),
         f.isDir() ? "—" : QLocale().formattedDataSize(f.size()), abs});
    row->setIcon(0, lockIcon(f.isSymLink() ? "warning" : "locked"));
    row->setData(0, Qt::UserRole, abs);
    existing << abs;
  }
  retranslate();
}
QStringList Workspace::paths() const {
  QStringList a;
  for (int i = 0; i < files->topLevelItemCount(); i++) {
    auto path = files->topLevelItem(i)->data(0, Qt::UserRole).toString();
    if (!path.isEmpty())
      a << path;
  }
  return a;
}
void Workspace::dragEnterEvent(QDragEnterEvent *e) {
  if (e->mimeData()->hasUrls())
    e->acceptProposedAction();
}
void Workspace::dropEvent(QDropEvent *e) {
  QStringList a;
  for (auto u : e->mimeData()->urls())
    if (u.isLocalFile())
      a << u.toLocalFile();
  addPaths(a);
}
Workspace *Window::local() const {
  return qobject_cast<Workspace *>(tabs->currentWidget());
}
ServerView *Window::remote() const {
  return qobject_cast<ServerView *>(tabs->currentWidget());
}
Window::Window(QString initial) {
  setWindowTitle("ESCrypter 0.2");
  setWindowIcon(lockIcon());
  resize(1120, 740);
  manager = new JobManager(this);
  tabs = new QTabWidget;
  tabs->setTabsClosable(true);
  tabs->setMovable(true);
  setCentralWidget(tabs);
  connect(tabs, &QTabWidget::tabCloseRequested, this, &Window::closeTab);
  transfers = new Transfers(this);
  jobsDock = new QDockWidget(trText("Jobs", "İşler"), this);
  auto container = new QWidget;
  auto l = new QVBoxLayout(container);
  jobs = new QTreeWidget;
  jobs->setHeaderLabels({trText("Job", "İş"), trText("Status", "Durum"),
                         trText("Progress", "İlerleme"),
                         trText("Signer", "İmzalayan")});
  details = new QPlainTextEdit;
  details->setReadOnly(true);
  details->setMaximumHeight(90);
  details->setVisible(false);
  l->addWidget(jobs);
  l->addWidget(details);
  jobsDock->setWidget(container);
  addDockWidget(Qt::BottomDockWidgetArea, jobsDock);
  jobsDock->setMaximumHeight(260);
  connect(manager, &JobManager::added, this, &Window::track);
  connect(jobs, &QTreeWidget::itemSelectionChanged, this, [this] {
    auto selected = jobs->selectedItems();
    for (auto j : manager->all)
      if (!selected.isEmpty() && jobRows[j] == selected[0])
        details->setPlainText(j->detail + "\n" + j->output + "\n" + j->signer);
  });
  profiles = loadJson(stateHome() + "/profiles.json")["profiles"].toArray();
  signingKey =
      QSettings("ESCrypter", "ESCrypter").value("signingKey").toString();
  menus();
  newLocal();
  theme();
  if (!initial.isEmpty())
    QTimer::singleShot(0, this, [this, initial] { openPackage(initial); });
}
void Window::track(LocalJob *j) {
  owners[j] = tabs->currentWidget();
  auto row = new QTreeWidgetItem(jobs, {j->label, j->status, "", ""});
  row->setIcon(0, lockIcon());
  jobRows[j] = row;
  connect(j, &LocalJob::changed, this, [this, j, row] {
    row->setText(1, j->status + " · " + j->phase);
    if (j->total > 0) {
      auto sec = qMax(0.001, j->clock.elapsed() / 1000.0);
      auto percent = qMin<qint64>(99, 100 * j->bytes / j->total);
      row->setText(2, QString("%1% · %2 MB/s")
                          .arg(percent)
                          .arg(j->bytes / 1e6 / sec, 0, 'f', 1));
    } else
      row->setText(2, "…");
    row->setText(3, j->signer.isEmpty() ? ""
                    : j->trusted
                        ? trText("Trusted", "Güvenilen")
                        : trText("Unknown signer", "Bilinmeyen imzalayan"));
    row->setToolTip(3, j->signer);
    if (j->status == "completed") {
      row->setText(2, "100%");
      row->setIcon(0, lockIcon(j->trusted ? "verified" : "locked"));
    }
    if (j->status == "failed" || j->status == "cancelled")
      row->setIcon(0, lockIcon("warning"));
    if (row->isSelected())
      details->setPlainText(j->detail + "\n" + j->output + "\n" + j->signer);
  });
}
void Window::menus() {
  menuBar()->clear();
  auto add = [this](QMenu *m, QString label, QString icon,
                    std::function<void()> fn, QKeySequence shortcut = {}) {
    auto a = m->addAction(lockIcon(icon), label);
    if (!shortcut.isEmpty())
      a->setShortcut(shortcut);
    connect(a, &QAction::triggered, this, fn);
    return a;
  };
  auto f = menuBar()->addMenu(trText("File", "Dosya"));
  add(
      f, trText("New tab", "Yeni sekme"), "locked", [this] { newLocal(); },
      QKeySequence("Ctrl+T"));
  add(f, trText("Duplicate tab", "Sekmeyi çoğalt"), "locked", [this] {
    if (auto w = local()) {
      auto paths = w->paths();
      newLocal();
      local()->addPaths(paths);
    } else if (auto r = remote()) {
      auto view = new ServerView(r->session->profile);
      tabs->addTab(view, lockIcon("key"), r->session->profile.name);
      tabs->setCurrentWidget(view);
    }
  });
  add(
      f, trText("Add files…", "Dosya ekle…"), "locked",
      [this] {
        if (!local())
          newLocal();
        local()->addPaths(QFileDialog::getOpenFileNames(this));
      },
      QKeySequence("Ctrl+O"));
  add(f, trText("Add folder…", "Klasör ekle…"), "locked", [this] {
    auto p = QFileDialog::getExistingDirectory(this);
    if (p.isEmpty())
      return;
    if (!local())
      newLocal();
    local()->addPaths({p});
  });
  add(f, trText("Open package…", "Paket aç…"), "unlocked",
      [this] { openPackage(); });
  add(f, trText("Clear selection", "Listeyi temizle"), "warning", [this] {
    if (local()) {
      local()->files->clear();
      local()->retranslate();
    }
  });
  f->addSeparator();
  add(
      f, trText("Close tab", "Sekmeyi kapat"), "locked",
      [this] { closeTab(tabs->currentIndex()); }, QKeySequence("Ctrl+W"));
  add(
      f, trText("Exit", "Çıkış"), "locked", [this] { close(); },
      QKeySequence::Quit);
  auto op = menuBar()->addMenu(trText("Operations", "İşlemler"));
  add(
      op, trText("Encrypt", "Şifrele"), "locked",
      [this] {
        if (remote())
          remoteOperation("encrypt");
        else
          encryptLocal();
      },
      QKeySequence("Ctrl+E"));
  add(op, trText("Decrypt", "Şifreyi çöz"), "unlocked", [this] {
    if (remote())
      remoteOperation("decrypt");
    else
      decryptLocal();
  });
  add(op, trText("Verify signature", "İmzayı doğrula"), "verified", [this] {
    if (remote())
      remoteOperation("verify");
    else
      verifyLocal();
  });
  add(op, trText("Package information", "Paket bilgileri"), "locked", [this] {
    if (remote())
      remoteOperation("info");
    else
      verifyLocal(true);
  });
  add(op, trText("Unlock contents list", "İçerik listesini aç"), "unlocked",
      [this] { packageContent(); });
  add(op, trText("Change archive password", "Arşiv parolasını değiştir"), "key",
      [this] {
        if (remote())
          remoteOperation("rekey");
        else
          changePassword();
      });
  add(op, trText("Recover with key", "Anahtarla kurtar"), "key", [this] {
    if (remote())
      remoteOperation("recover");
    else
      decryptLocal(true);
  });
  op->addSeparator();
  add(op, trText("Encrypt → upload", "Şifrele → yükle"), "verified",
      [this] { encryptLocal(true); });
  add(op, trText("Cancel selected job", "Seçili işi iptal et"), "warning",
      [this] {
        if (remote()) {
          remote()->cancelSelected();
          return;
        }
        auto rows = jobs->selectedItems();
        for (auto j : manager->all)
          if (rows.contains(jobRows[j]))
            j->cancel();
      });
  auto keys = menuBar()->addMenu(trText("Keys", "Anahtarlar"));
  for (auto pair : QList<QPair<QString, QString>>{
           {"keygen", trText("Create signing key", "İmza anahtarı oluştur")},
           {"select", trText("Select signing key", "İmza anahtarı seç")},
           {"key-password",
            trText("Change key password", "Anahtar parolasını değiştir")},
           {"public-key",
            trText("Export public key", "Açık anahtarı dışa aktar")}})
    add(keys, pair.second, "key", [this, pair] { keyAction(pair.first); });
  add(keys, trText("Trusted signers", "Güvenilen imzalayanlar"), "verified",
      [this] { trustDialog(); });
  auto net = menuBar()->addMenu(trText("Connections", "Bağlantılar"));
  add(net, trText("New connection…", "Yeni bağlantı…"), "key",
      [this] { connection(); });
  add(net, trText("Saved connections…", "Kayıtlı bağlantılar…"), "key",
      [this] { connection(true); });
  add(
      net, trText("Refresh / reconnect", "Yenile / yeniden bağlan"), "verified",
      [this] {
        if (remote())
          remote()->refresh();
      },
      QKeySequence("F5"));
  add(net, trText("Upload file…", "Dosya yükle…"), "locked",
      [this] { transfer(true); });
  add(net, trText("Download file…", "Dosya indir…"), "unlocked",
      [this] { transfer(false); });
  add(net, trText("HTTPS download (wget)", "HTTPS indir (wget)"), "unlocked",
      [this] { downloadHttps(); });
  add(net, trText("Transfers", "Aktarımlar"), "locked", [this] {
    int i = tabs->indexOf(transfers);
    if (i < 0)
      i = tabs->addTab(transfers, lockIcon(),
                       trText("Transfers", "Aktarımlar"));
    tabs->setCurrentIndex(i);
  });
  auto view = menuBar()->addMenu(trText("View", "Görünüm"));
  view->addAction(jobsDock->toggleViewAction());
  auto d = add(view, trText("Technical details", "Teknik ayrıntılar"), "locked",
               [this] { details->setVisible(!details->isVisible()); });
  d->setCheckable(true);
  d->setChecked(details->isVisible());
  auto lang = view->addMenu(trText("Language", "Dil"));
  for (auto code : QStringList{"tr", "en"}) {
    auto a = lang->addAction(code == "tr" ? "Türkçe" : "English");
    connect(a, &QAction::triggered, this, [this, code] {
      QSettings("ESCrypter", "ESCrypter").setValue("language", code);
      menus();
      for (int i = 0; i < tabs->count(); i++)
        if (auto w = qobject_cast<Workspace *>(tabs->widget(i)))
          w->retranslate();
      QMessageBox::information(this, "ESCrypter",
                               trText("Menus updated. Reopen tabs for all "
                                      "labels to use the new language.",
                                      "Menüler güncellendi. Tüm etiketler için "
                                      "sekmeleri yeniden açın."));
    });
  }
  auto settings = menuBar()->addMenu(trText("Settings", "Ayarlar"));
  add(settings, trText("Preferences…", "Tercihler…"), "key",
      [this] { settingsDialog(); });
  add(settings, trText("Private work folders…", "Özel çalışma klasörleri…"),
      "warning", [this] { cleanup(); });
  add(settings, trText("Job history", "İş geçmişi"), "locked",
      [this] { history(); });
  auto help = menuBar()->addMenu(trText("Help", "Yardım"));
  add(help, trText("User guide", "Kullanım kılavuzu"), "locked", [this] {
    QDialog d(this);
    d.setWindowTitle(trText("User guide", "Kullanım kılavuzu"));
    QVBoxLayout l(&d);
    QTextBrowser text;
    QFile f(turkish() ? ":/docs/README_TR.md" : ":/docs/README.md");
    f.open(QIODevice::ReadOnly);
    text.setMarkdown(QString::fromUtf8(f.readAll()));
    l.addWidget(&text);
    d.resize(800, 600);
    d.exec();
  });
  add(help, trText("Open source licenses", "Açık kaynak lisansları"),
      "verified", [this] { licenses(); });
  add(help, trText("Export diagnostics", "Tanılama raporu dışa aktar"),
      "locked", [this] { diagnostics(); });
  add(help, trText("About ESCrypter", "ESCrypter hakkında"), "locked",
      [this] { about(); });
}
void Window::newLocal() {
  auto w = new Workspace;
  connect(w, &Workspace::encryptRequested, this, [this, w] {
    tabs->setCurrentWidget(w);
    encryptLocal();
  });
  connect(w, &Workspace::openRequested, this, [this] { openPackage(); });
  tabs->addTab(w, lockIcon(), trText("Local workspace", "Yerel çalışma"));
  tabs->setCurrentWidget(w);
}
void Window::openPackage(QString p) {
  if (p.isEmpty())
    p = QFileDialog::getOpenFileName(this, trText("Open package", "Paket aç"),
                                     {}, "ESCrypter (*.esc)");
  if (p.isEmpty())
    return;
  newLocal();
  local()->package = p;
  tabs->setTabText(tabs->currentIndex(), QFileInfo(p).fileName());
  local()->summary->setText(
      trText("Locked package · use Operations to verify or decrypt",
             "Kilitli paket · doğrulamak veya çözmek için İşlemler menüsü"));
  verifyLocal(true);
}
QString Window::chooseKey() {
  if (!signingKey.isEmpty() && QFileInfo::exists(signingKey))
    return signingKey;
  signingKey = QFileDialog::getOpenFileName(
      this, trText("Signing key", "İmza anahtarı"));
  if (!signingKey.isEmpty())
    QSettings("ESCrypter", "ESCrypter").setValue("signingKey", signingKey);
  return signingKey;
}
QString Window::trustedSigner() {
  auto list = loadJson(stateHome() + "/trust.json")["keys"].toArray();
  QStringList labels{trText("Unknown signer (verify signature only)",
                            "Bilinmeyen imzalayan (yalnızca imzayı doğrula)")};
  for (auto v : list) {
    auto k = v.toObject();
    labels << k["label"].toString() + " · " + k["fingerprint"].toString();
  }
  bool ok;
  auto choice = QInputDialog::getItem(
      this, trText("Signer trust", "İmzalayana güven"),
      trText("Expected signer", "Beklenen imzalayan"), labels, 0, false, &ok);
  if (!ok)
    return "CANCEL";
  int i = labels.indexOf(choice);
  return i > 0 ? list[i - 1].toObject()["fingerprint"].toString() : QString();
}
void Window::encryptLocal(bool uploadAfter) {
  auto w = local();
  if (!w || w->paths().isEmpty())
    return;
  auto key = chooseKey();
  if (key.isEmpty())
    return;
  auto output = QFileDialog::getSaveFileName(
      this,
      trText("Encrypted output (minimum 4 MB)", "Şifreli çıktı (en az 4 MB)"),
      "Sifreli-Dosya.esc", "ESCrypter (*.esc)");
  if (output.isEmpty())
    return;
  if (!output.endsWith(".esc"))
    output += ".esc";
  if (QFileInfo::exists(output)) {
    QMessageBox::warning(
        this, "ESCrypter",
        trText("Choose a new output filename.", "Yeni bir çıktı adı seçin."));
    return;
  }
  auto password =
      secretDialog(this, trText("Archive password", "Arşiv parolası"), true);
  if (password.isEmpty())
    return;
  auto signer = secretDialog(
      this, trText("Signing key password", "İmza anahtarı parolası"));
  if (signer.isEmpty())
    return;
  QString recovery = "-";
  if (QMessageBox::question(this, "ESCrypter",
                            trText("Create a separate recovery key? Store it "
                                   "separately and secretly.",
                                   "Ayrı kurtarma anahtarı oluşturulsun mu? "
                                   "Ayrı ve gizli saklayın."),
                            QMessageBox::Yes | QMessageBox::No,
                            QMessageBox::No) == QMessageBox::Yes) {
    recovery = QFileDialog::getSaveFileName(this, {}, "recovery.esckey");
    if (recovery.isEmpty())
      return;
  }
  QStringList args = {
      "encrypt", output, key,
      QStringList{"fast", "balanced", "high"}[w->compression->currentIndex()],
      recovery};
  args += w->paths();
  auto j = manager->add(trText("Encrypt", "Şifrele"), args, {password, signer},
                        output);
  if (uploadAfter)
    connect(j, &LocalJob::ended, this, [this, output](bool ok) {
      if (!ok)
        return;
      QStringList labels;
      for (auto p : profiles)
        labels << p.toObject()["name"].toString();
      bool chosen;
      auto name = QInputDialog::getItem(
          this, "SFTP", trText("Destination profile", "Hedef profil"), labels,
          0, false, &chosen);
      if (!chosen)
        return;
      auto p = Profile::from(profiles[labels.indexOf(name)].toObject());
      auto path = QInputDialog::getText(
          this, "SFTP",
          p.agent ? trText("Destination relative to server root",
                           "Sunucu köküne göre hedef")
                  : trText("Absolute destination path", "Mutlak hedef yolu"));
      if (path.isEmpty())
        return;
      if (p.agent) {
        auto view = new ServerView(p);
        tabs->addTab(view, lockIcon("key"), p.name);
        tabs->setCurrentWidget(view);
        QPointer<ServerView> peer = view;
        connect(
            view->session, &RemoteSession::ready, this,
            [this, peer, p, output, path] {
              if (peer)
                transfers->upload(p, peer->session, output, path);
            },
            Qt::SingleShotConnection);
      } else
        transfers->upload(p, nullptr, output, path);
    });
}
void Window::decryptLocal(bool recovery) {
  auto w = local();
  QString p = w ? w->package : QString();
  if (p.isEmpty())
    p = QFileDialog::getOpenFileName(this, {}, {}, "ESCrypter (*.esc)");
  if (p.isEmpty())
    return;
  auto parent = QFileDialog::getExistingDirectory(
      this, trText("Output parent folder", "Çıktının üst klasörü"));
  if (parent.isEmpty())
    return;
  auto name = QInputDialog::getText(
      this, "ESCrypter",
      trText("New output folder name", "Yeni çıktı klasörü adı"),
      QLineEdit::Normal, "Decrypted");
  if (name.isEmpty() || name.contains('/') || name == "." || name == "..")
    return;
  QString secret;
  if (recovery) {
    auto key = QFileDialog::getOpenFileName(
        this, trText("Recovery key", "Kurtarma anahtarı"));
    QFile f(key);
    if (!f.open(QIODevice::ReadOnly) || f.size() > 1024)
      return;
    secret = QString::fromUtf8(f.readAll()).trimmed();
  } else
    secret = secretDialog(this, trText("Archive password", "Arşiv parolası"));
  if (secret.isEmpty())
    return;
  auto pin = trustedSigner();
  if (pin == "CANCEL")
    return;
  QStringList a = {recovery ? "recover" : "decrypt", p, parent + "/" + name};
  if (!pin.isEmpty())
    a << pin;
  manager->add(trText("Decrypt", "Şifreyi çöz"), a, {secret},
               parent + "/" + name);
}
void Window::verifyLocal(bool info) {
  QString p = local() ? local()->package : QString();
  if (p.isEmpty())
    p = QFileDialog::getOpenFileName(this, {}, {}, "ESCrypter (*.esc)");
  if (p.isEmpty())
    return;
  QStringList a = {info ? "info" : "verify", p};
  if (!info) {
    auto pin = trustedSigner();
    if (pin == "CANCEL")
      return;
    if (!pin.isEmpty())
      a << pin;
  }
  auto j = manager->add(info ? trText("Package information", "Paket bilgileri")
                             : trText("Verify signature", "İmzayı doğrula"),
                        a);
  if (info)
    connect(j, &LocalJob::ended, this, [this, j](bool ok) {
      if (ok) {
        auto d = j->result;
        QMessageBox::information(
            this, "ESCrypter",
            trText("Signed package; identity not yet trusted.\n",
                   "İmzalı paket; kimliğe henüz güvenilmiyor.\n") +
                QString("%1 · %2 parts\nSHA-256: %3\nRecovery: %4")
                    .arg(QLocale().formattedDataSize(
                        d["bytes"].toVariant().toLongLong()))
                    .arg(d["parts"].toInt())
                    .arg(d["fingerprint"].toString())
                    .arg(d["recovery"].toBool() ? "yes" : "no"));
      }
    });
}
void Window::changePassword() {
  QString p = local() ? local()->package : QString();
  if (p.isEmpty())
    p = QFileDialog::getOpenFileName(this, {}, {}, "ESCrypter (*.esc)");
  if (p.isEmpty() || chooseKey().isEmpty())
    return;
  auto out = QFileDialog::getSaveFileName(
      this,
      trText("New package — old copies keep the old password",
             "Yeni paket — eski kopyaların parolası değişmez"),
      "New.esc");
  if (out.isEmpty())
    return;
  auto old =
      secretDialog(this, trText("Old archive password", "Eski arşiv parolası"));
  if (old.isEmpty())
    return;
  auto next = secretDialog(
      this, trText("New archive password", "Yeni arşiv parolası"), true);
  if (next.isEmpty())
    return;
  auto signing =
      secretDialog(this, trText("Signing password", "İmza parolası"));
  if (signing.isEmpty())
    return;
  manager->add(trText("Change password", "Parola değiştir"),
               {"rekey", p, out, signingKey}, {old, next, signing}, out);
}
void Window::keyAction(QString action) {
  if (action == "select") {
    signingKey.clear();
    chooseKey();
    return;
  }
  QString input;
  if (action != "keygen") {
    input = chooseKey();
    if (input.isEmpty())
      return;
  }
  auto out = QFileDialog::getSaveFileName(
      this, {}, action == "public-key" ? "signer.pub" : "signing-key.esckey");
  if (out.isEmpty())
    return;
  QStringList secrets;
  auto old = secretDialog(
      this,
      action == "keygen"
          ? trText("Protect new signing key", "Yeni imza anahtarını koru")
          : trText("Signing key password", "İmza anahtarı parolası"),
      action == "keygen");
  if (old.isEmpty())
    return;
  secrets << old;
  if (action == "key-password") {
    auto next = secretDialog(
        this, trText("New key password", "Yeni anahtar parolası"), true);
    if (next.isEmpty())
      return;
    secrets << next;
  }
  QStringList args = {action};
  if (action != "keygen")
    args << input;
  args << out;
  auto job = manager->add(trText("Key management", "Anahtar yönetimi"), args,
                          secrets, out);
  if (action == "keygen" || action == "key-password")
    connect(job, &LocalJob::ended, this, [this, out](bool ok) {
      if (ok) {
        signingKey = out;
        QSettings("ESCrypter", "ESCrypter").setValue("signingKey", out);
      }
    });
}
void Window::packageContent() {
  auto w = local();
  if (!w || w->package.isEmpty())
    return;
  auto pw = secretDialog(this, trText("Unlock contents", "İçeriği aç"));
  if (pw.isEmpty())
    return;
  auto j = manager->add(trText("Read contents", "İçeriği oku"),
                        {"list-content", w->package}, {pw});
  QPointer<Workspace> target = w;
  connect(j, &LocalJob::ended, this, [j, target](bool ok) {
    if (!ok || !target)
      return;
    target->files->clear();
    for (auto v : j->result["entries"].toArray()) {
      auto e = v.toObject();
      auto row = new QTreeWidgetItem(
          target->files,
          {e["name"].toString(), e["directory"].toBool() ? "folder" : "file",
           QString::number(e["bytes"].toVariant().toLongLong()), ""});
      row->setIcon(0, lockIcon("unlocked"));
    }
    j->result = {};
    target->summary->setText(
        trText("Contents authenticated · names visible until this tab closes",
               "İçerik doğrulandı · sekme kapanana kadar adlar görünür"));
  });
}
void Window::connection(bool saved) {
  Profile p;
  if (saved) {
    QStringList names;
    for (auto v : profiles)
      names << v.toObject()["name"].toString();
    if (names.isEmpty()) {
      connection(false);
      return;
    }
    bool ok;
    auto name = QInputDialog::getItem(
        this, trText("Connections", "Bağlantılar"),
        trText("Select profile", "Profil seç"), names, 0, false, &ok);
    if (!ok)
      return;
    p = Profile::from(profiles[names.indexOf(name)].toObject());
  } else {
    QDialog d(this);
    d.setWindowTitle(trText("Connection profile", "Bağlantı profili"));
    d.setWindowIcon(lockIcon("key"));
    QFormLayout l(&d);
    QLineEdit name, host, user, key, known;
    QSpinBox port;
    port.setRange(1, 65535);
    port.setValue(22);
    QCheckBox agent(trText("ESCrypter Agent installed (ECP)",
                           "ESCrypter Agent kurulu (ECP)"));
    agent.setChecked(true);
    known.setText(QDir::homePath() + "/.ssh/known_hosts");
    l.addRow(trText("Name", "Ad"), &name);
    l.addRow(trText("Host", "Sunucu"), &host);
    l.addRow(trText("User", "Kullanıcı"), &user);
    l.addRow(trText("Port", "Port"), &port);
    l.addRow(trText("Private key path (empty: SSH agent)",
                    "Özel anahtar yolu (boş: SSH agent)"),
             &key);
    l.addRow("known_hosts", &known);
    l.addRow(&agent);
    QLabel hint(
        trText("Host verification is mandatory. Add the verified server key to "
               "known_hosts first. Load encrypted SSH keys into ssh-agent.",
               "Sunucu doğrulaması zorunlu. Doğrulanmış sunucu anahtarını önce "
               "known_hosts dosyasına ekleyin. Şifreli SSH anahtarlarını "
               "ssh-agent'a yükleyin."));
    hint.setWordWrap(true);
    l.addRow(&hint);
    QDialogButtonBox buttons(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    l.addRow(&buttons);
    connect(&buttons, &QDialogButtonBox::accepted, &d, [&] {
      if (name.text().isEmpty() || host.text().isEmpty() ||
          user.text().isEmpty() || !QFileInfo::exists(known.text()))
        return;
      d.accept();
    });
    connect(&buttons, &QDialogButtonBox::rejected, &d, &QDialog::reject);
    if (d.exec() != QDialog::Accepted)
      return;
    p = {name.text(),  host.text(),  user.text(),      key.text(),
         known.text(), port.value(), agent.isChecked()};
    profiles.append(p.json());
    saveJson(stateHome() + "/profiles.json", {{"profiles", profiles}});
  }
  auto server = new ServerView(p);
  tabs->addTab(server, lockIcon("key"), p.name);
  tabs->setCurrentWidget(server);
}
void Window::remoteOperation(QString operation) {
  auto r = remote();
  if (!r || !r->session->connected) {
    QMessageBox::warning(this, "ECP",
                         trText("Connect to an ESCrypter Agent first.",
                                "Önce ESCrypter Agent'a bağlanın."));
    return;
  }
  if (!r->session->hello["capabilities"].toArray().contains("submit"))
    return;
  QJsonObject spec{{"operation", operation}};
  QJsonArray secrets;
  auto input = r->selectedPath();
  if (input.isEmpty())
    return;
  if (operation == "encrypt") {
    QJsonArray a;
    for (auto item : r->files->selectedItems())
      a.append(r->path->text().isEmpty()
                   ? item->text(0)
                   : r->path->text() + "/" + item->text(0));
    spec["inputs"] = a;
    bool ok;
    auto profile =
        QInputDialog::getItem(this, "ECP", trText("Compression", "Sıkıştırma"),
                              {"fast", "balanced", "high"}, 1, false, &ok);
    if (!ok)
      return;
    spec["profile"] = profile;
  } else
    spec["input"] = input;
  if (operation == "encrypt" || operation == "decrypt" ||
      operation == "recover" || operation == "rekey") {
    if (QMessageBox::warning(
            this, "ECP",
            trText("This operation runs on the server. The server can access "
                   "plaintext and the secrets required for the operation. "
                   "Continue?",
                   "İşlem sunucuda yapılacak. Sunucu açık veriye ve işlem için "
                   "gereken sırlara erişebilir. Devam edilsin mi?"),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No) != QMessageBox::Yes)
      return;
    auto out =
        QInputDialog::getText(this, "ECP",
                              trText("New output path relative to server root",
                                     "Sunucu köküne göre yeni çıktı yolu"));
    if (out.isEmpty())
      return;
    spec["output"] = out;
  }
  if (operation == "encrypt" || operation == "rekey") {
    auto key = QInputDialog::getText(
        this, "ECP",
        trText("Signing key path relative to server key root",
               "Sunucudaki anahtar köküne göre imza anahtarı yolu"));
    if (key.isEmpty())
      return;
    spec["key"] = key;
  }
  if (operation == "encrypt") {
    auto pw = secretDialog(
        this, trText("Remote archive password", "Uzak arşiv parolası"), true);
    if (pw.isEmpty())
      return;
    secrets.append(pw);
  } else if (operation == "decrypt" || operation == "rekey" ||
             operation == "recover") {
    auto pw = secretDialog(
        this, operation == "recover"
                  ? trText("Recovery key (hex)", "Kurtarma anahtarı (hex)")
                  : trText("Remote archive password", "Uzak arşiv parolası"));
    if (pw.isEmpty())
      return;
    secrets.append(pw);
    if (operation == "rekey") {
      auto next = secretDialog(
          this, trText("New remote password", "Yeni uzak parola"), true);
      if (next.isEmpty())
        return;
      secrets.append(next);
    }
  }
  if (operation == "encrypt" || operation == "rekey") {
    auto pw = secretDialog(this, trText("Remote signing key password",
                                        "Uzak imza anahtarı parolası"));
    if (pw.isEmpty())
      return;
    secrets.append(pw);
  }
  if (operation == "verify" || operation == "decrypt" ||
      operation == "recover") {
    auto pin = trustedSigner();
    if (pin == "CANCEL")
      return;
    if (!pin.isEmpty())
      spec["trusted_signer"] = pin;
  }
  r->submit(spec, secrets);
}
void Window::transfer(bool upload) {
  auto r = remote();
  if (!r) {
    QMessageBox::information(
        this, "SFTP",
        trText("Select a server tab first.", "Önce bir sunucu sekmesi seçin."));
    return;
  }
  if (upload) {
    auto local = QFileDialog::getOpenFileName(
        this, trText("Upload file", "Dosya yükle"));
    if (local.isEmpty())
      return;
    auto path = QInputDialog::getText(
        this, "SFTP",
        r->session->connected
            ? trText("Destination relative to server root",
                     "Sunucu köküne göre hedef")
            : trText("Absolute SFTP destination", "Mutlak SFTP hedefi"),
        QLineEdit::Normal,
        r->path->text().isEmpty()
            ? QFileInfo(local).fileName()
            : r->path->text() + "/" + QFileInfo(local).fileName());
    if (!path.isEmpty())
      transfers->upload(r->session->profile, r->session, local, path);
  } else {
    auto path = r->selectedPath();
    if (path.isEmpty())
      path = QInputDialog::getText(this, "SFTP",
                                   trText("Remote path", "Uzak yol"));
    if (path.isEmpty())
      return;
    auto output =
        QFileDialog::getSaveFileName(this, {}, QFileInfo(path).fileName());
    if (output.isEmpty())
      return;
    transfers->download(r->session->profile, r->session, path, output);
  }
  if (tabs->indexOf(transfers) < 0)
    tabs->addTab(transfers, lockIcon(), trText("Transfers", "Aktarımlar"));
  tabs->setCurrentWidget(transfers);
}
void Window::settingsDialog() {
  QSettings settings("ESCrypter", "ESCrypter");
  QDialog d(this);
  d.setWindowTitle(trText("Preferences", "Tercihler"));
  QFormLayout l(&d);
  QSpinBox parallel, network, bandwidth, memory;
  parallel.setRange(1, 4);
  parallel.setValue(settings.value("parallel", 1).toInt());
  network.setRange(1, 4);
  network.setValue(settings.value("transfers", 2).toInt());
  bandwidth.setRange(0, 1000000);
  bandwidth.setValue(settings.value("bandwidth", 0).toInt());
  memory.setRange(256, 4096);
  memory.setValue(settings.value("memory", 1024).toInt());
  QComboBox themeBox;
  themeBox.addItems({"system", "light", "dark"});
  themeBox.setCurrentText(settings.value("theme", "system").toString());
  QLineEdit temporary;
  temporary.setText(settings.value("temporary").toString());
  QCheckBox history(trText("Keep job history (no paths or secrets)",
                           "İş geçmişini sakla (yol veya sır içermez)"));
  history.setChecked(settings.value("history", false).toBool());
  l.addRow(trText("Concurrent local jobs", "Eşzamanlı yerel iş"), &parallel);
  l.addRow(trText("Concurrent transfers", "Eşzamanlı aktarım"), &network);
  l.addRow(trText("KiB/s per transfer (0: unlimited)",
                  "Aktarım başına KiB/sn (0: sınırsız)"),
           &bandwidth);
  l.addRow(trText("Memory limit per worker (MiB)",
                  "İşlem başına bellek sınırı (MiB)"),
           &memory);
  l.addRow(
      trText("Temporary folder (empty: system)", "Geçici dizin (boş: sistem)"),
      &temporary);
  l.addRow(trText("Theme", "Tema"), &themeBox);
  l.addRow(&history);
  QDialogButtonBox buttons(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
  l.addRow(&buttons);
  connect(&buttons, &QDialogButtonBox::accepted, &d, [&] {
    if (!temporary.text().isEmpty() && !QFileInfo(temporary.text()).isDir()) {
      QMessageBox::warning(&d, "ESCrypter", "Temporary directory must exist");
      return;
    }
    d.accept();
  });
  connect(&buttons, &QDialogButtonBox::rejected, &d, &QDialog::reject);
  if (d.exec() != QDialog::Accepted)
    return;
  settings.setValue("parallel", parallel.value());
  settings.setValue("transfers", network.value());
  settings.setValue("bandwidth", bandwidth.value());
  settings.setValue("memory", memory.value());
  settings.setValue("temporary", temporary.text());
  settings.setValue("theme", themeBox.currentText());
  settings.setValue("history", history.isChecked());
  theme();
}
void Window::theme() {
  static const QPalette desktop = QApplication::palette();
  auto t =
      QSettings("ESCrypter", "ESCrypter").value("theme", "system").toString();
  if (t == "dark") {
    QApplication::setStyle("Fusion");
    QPalette p;
    p.setColor(QPalette::Window, QColor("#17252e"));
    p.setColor(QPalette::WindowText, Qt::white);
    p.setColor(QPalette::Base, QColor("#0e1b23"));
    p.setColor(QPalette::AlternateBase, QColor("#233541"));
    p.setColor(QPalette::Text, Qt::white);
    p.setColor(QPalette::Button, QColor("#233541"));
    p.setColor(QPalette::ButtonText, Qt::white);
    p.setColor(QPalette::Highlight, QColor("#1f7d85"));
    p.setColor(QPalette::HighlightedText, Qt::white);
    QApplication::setPalette(p);
  } else if (t == "light") {
    QPalette p;
    p.setColor(QPalette::Window, QColor("#f3f6f8"));
    p.setColor(QPalette::WindowText, QColor("#143b58"));
    p.setColor(QPalette::Base, Qt::white);
    p.setColor(QPalette::Text, QColor("#162a35"));
    p.setColor(QPalette::Button, QColor("#e7eff2"));
    p.setColor(QPalette::ButtonText, QColor("#143b58"));
    p.setColor(QPalette::Highlight, QColor("#1f7d85"));
    p.setColor(QPalette::HighlightedText, Qt::white);
    QApplication::setPalette(p);
  } else {
    QApplication::setPalette(desktop);
  }
  setStyleSheet("QMenuBar{padding:5px;} QTabBar::tab{padding:9px 17px;} "
                "QTreeWidget{border-radius:5px;} QPushButton{padding:8px "
                "17px;} QLineEdit,QComboBox{padding:5px;}");
}
void Window::trustDialog() {
  auto data = loadJson(stateHome() + "/trust.json");
  auto keys = data["keys"].toArray();
  QDialog d(this);
  d.setWindowTitle(trText("Trusted signers", "Güvenilen imzalayanlar"));
  QVBoxLayout l(&d);
  QListWidget list;
  auto refresh = [&] {
    list.clear();
    for (auto v : keys) {
      auto k = v.toObject();
      list.addItem(k["label"].toString() + " · " + k["fingerprint"].toString());
    }
  };
  refresh();
  l.addWidget(&list);
  QHBoxLayout row;
  QPushButton add(trText("Import public key", "Açık anahtar al")),
      remove(trText("Remove trust", "Güveni kaldır"));
  row.addWidget(&add);
  row.addWidget(&remove);
  l.addLayout(&row);
  connect(&add, &QPushButton::clicked, &d, [&] {
    auto path = QFileDialog::getOpenFileName(&d);
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly) || f.size() != 32)
      return;
    auto bytes = f.readAll();
    auto fp = QString(
        QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex());
    auto label = QInputDialog::getText(
        &d, "ESCrypter", trText("Signer label", "İmzalayan etiketi"));
    if (label.isEmpty())
      return;
    if (QMessageBox::question(
            &d, "ESCrypter",
            trText("Verify this fingerprint through an independent trusted "
                   "channel before trusting it:\n",
                   "Güvenmeden önce bu parmak izini bağımsız güvenilir "
                   "kanaldan doğrulayın:\n") +
                fp) != QMessageBox::Yes)
      return;
    keys.append(QJsonObject{
        {"label", label},
        {"fingerprint", fp},
        {"public_key", QString(bytes.toHex())},
        {"added", QDateTime::currentDateTimeUtc().toString(Qt::ISODate)}});
    refresh();
  });
  connect(&remove, &QPushButton::clicked, &d, [&] {
    int i = list.currentRow();
    if (i >= 0) {
      keys.removeAt(i);
      refresh();
    }
  });
  QDialogButtonBox buttons(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
  l.addWidget(&buttons);
  connect(&buttons, &QDialogButtonBox::accepted, &d, &QDialog::accept);
  connect(&buttons, &QDialogButtonBox::rejected, &d, &QDialog::reject);
  d.resize(850, 350);
  if (d.exec() == QDialog::Accepted)
    saveJson(stateHome() + "/trust.json", {{"keys", keys}});
}
void Window::licenses() {
  QFile f(":/licenses/catalog.json");
  f.open(QIODevice::ReadOnly);
  auto catalog = QJsonDocument::fromJson(f.readAll()).object();
  QDialog d(this);
  d.setWindowTitle(trText("Open source licenses", "Açık kaynak lisansları"));
  d.setWindowIcon(lockIcon("verified"));
  QVBoxLayout l(&d);
  QLineEdit search;
  search.setPlaceholderText(trText("Search component, version or license",
                                   "Bileşen, sürüm veya lisans ara"));
  l.addWidget(&search);
  QSplitter split;
  QListWidget list;
  QTextBrowser text;
  text.setOpenExternalLinks(false);
  split.addWidget(&list);
  split.addWidget(&text);
  split.setStretchFactor(1, 3);
  l.addWidget(&split);
  auto entries = catalog["components"].toArray();
  auto fill = [&] {
    list.clear();
    for (int i = 0; i < entries.size(); i++) {
      auto e = entries[i].toObject();
      QString name = e["name"].toString() + " " + e["version"].toString() +
                     " · " + e["license"].toString();
      if (!name.contains(search.text(), Qt::CaseInsensitive))
        continue;
      auto item = new QListWidgetItem(name, &list);
      item->setData(Qt::UserRole, i);
    }
  };
  fill();
  connect(&search, &QLineEdit::textChanged, &d, [&] { fill(); });
  connect(&list, &QListWidget::currentItemChanged, &d, [&](auto item, auto) {
    if (!item)
      return;
    auto e = entries[item->data(Qt::UserRole).toInt()].toObject();
    text.setPlainText(e["name"].toString() + " " + e["version"].toString() +
                      "\n" + e["category"].toString() + "\n" +
                      e["url"].toString() + "\n\n" + e["text"].toString());
  });
  if (list.count())
    list.setCurrentRow(0);
  d.resize(1000, 650);
  d.exec();
}
void Window::cleanup() {
  if (manager->active()) {
    QMessageBox::information(this, "ESCrypter",
                             trText("Wait for local jobs to finish.",
                                    "Yerel işlerin bitmesini bekleyin."));
    return;
  }
  auto parent = QFileDialog::getExistingDirectory(
      this, trText("Select parent of abandoned work folders",
                   "Yarım kalmış çalışma klasörlerinin üst dizinini seç"));
  if (parent.isEmpty())
    return;
  QDialog d(this);
  d.setWindowTitle(trText("Abandoned private work folders",
                          "Yarım kalmış özel çalışma klasörleri"));
  QVBoxLayout l(&d);
  QLabel hint(trText(
      "Only marked ESCrypter folders whose owning process has ended are "
      "listed. They may contain plaintext. Choose explicitly before deletion.",
      "Yalnızca işaretli ve sahibi olan süreci bitmiş ESCrypter klasörleri "
      "listelenir. Açık veri içerebilirler. Silinecekleri açıkça seçin."));
  hint.setWordWrap(true);
  l.addWidget(&hint);
  QListWidget list;
  for (auto info : QDir(parent).entryInfoList({".escrypter-work-*"},
                                              QDir::Dirs | QDir::Hidden |
                                                  QDir::NoDotAndDotDot)) {
    if (info.isSymLink() || info.ownerId() != getuid() ||
        QFileInfo(info.filePath() + "/owner.json").isSymLink())
      continue;
    auto marker = loadJson(info.filePath() + "/owner.json");
    auto pid = marker["pid"].toInt();
    if (marker["app"] != "ESCrypter" ||
        marker["uid"].toInt(-1) != int(getuid()) || pid <= 0 ||
        QFileInfo::exists("/proc/" + QString::number(pid)))
      continue;
    auto item = new QListWidgetItem(info.filePath(), &list);
    item->setCheckState(Qt::Unchecked);
  }
  l.addWidget(&list);
  QDialogButtonBox buttons(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
  l.addWidget(&buttons);
  connect(&buttons, &QDialogButtonBox::accepted, &d, &QDialog::accept);
  connect(&buttons, &QDialogButtonBox::rejected, &d, &QDialog::reject);
  d.resize(700, 350);
  if (d.exec() != QDialog::Accepted)
    return;
  for (int i = 0; i < list.count(); i++) {
    auto item = list.item(i);
    if (item->checkState() == Qt::Checked) {
      auto marker = loadJson(item->text() + "/owner.json");
      if (marker["app"] == "ESCrypter" &&
          marker["uid"].toInt(-1) == int(getuid()) &&
          marker["pid"].toInt() > 0 && !QFileInfo(item->text()).isSymLink() &&
          QFileInfo(item->text()).ownerId() == getuid() &&
          !QFileInfo(item->text() + "/owner.json").isSymLink() &&
          !QFileInfo::exists("/proc/" + QString::number(marker["pid"].toInt())))
        QDir(item->text()).removeRecursively();
    }
  }
}
void Window::history() {
  QDialog d(this);
  d.setWindowTitle(trText("Job history", "İş geçmişi"));
  QVBoxLayout l(&d);
  QTextBrowser text;
  text.setPlainText(QString::fromUtf8(
      QJsonDocument(loadJson(stateHome() + "/history.json")).toJson()));
  l.addWidget(&text);
  QPushButton clear(trText("Clear history", "Geçmişi temizle"));
  l.addWidget(&clear);
  connect(&clear, &QPushButton::clicked, &d, [&] {
    QFile::remove(stateHome() + "/history.json");
    text.clear();
  });
  d.resize(650, 400);
  d.exec();
}
void Window::diagnostics() {
  auto p = QFileDialog::getSaveFileName(this, {}, "ESCrypter-diagnostics.json");
  if (p.isEmpty())
    return;
  QJsonArray status;
  for (auto j : manager->all)
    status.append(QJsonObject{{"status", j->status}, {"phase", j->phase}});
  saveJson(p, {{"app", "0.2.0"},
               {"qt", qVersion()},
               {"platform", QSysInfo::productType()},
               {"platform_version", QSysInfo::productVersion()},
               {"architecture", QSysInfo::currentCpuArchitecture()},
               {"jobs", status},
               {"contains_paths_or_secrets", false}});
}
void Window::downloadHttps() {
  auto input =
      QInputDialog::getText(this, "HTTPS",
                            trText("HTTPS URL (no credentials)",
                                   "HTTPS adresi (kimlik bilgisi içermemeli)"));
  QUrl url(input);
  if (url.scheme() != "https" || url.host().isEmpty() ||
      !url.userInfo().isEmpty())
    return;
  auto out =
      QFileDialog::getSaveFileName(this, {}, QFileInfo(url.path()).fileName());
  if (out.isEmpty() || QFileInfo::exists(out))
    return;
  auto p = new QProcess(this);
  httpsJobs.insert(p);
  auto temp = out + ".part-" + newId();
  QPointer<QProgressDialog> progress = new QProgressDialog(
      trText("Downloading over HTTPS…", "HTTPS üzerinden indiriliyor…"),
      trText("Cancel", "İptal"), 0, 0, this);
  progress->setAttribute(Qt::WA_DeleteOnClose);
  connect(progress.data(), &QProgressDialog::canceled, p, &QProcess::terminate);
  connect(p, &QProcess::readyReadStandardError, p,
          [p] { p->readAllStandardError(); });
  connect(p, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
          [this, p, progress, temp, out](int code, QProcess::ExitStatus state) {
            httpsJobs.remove(p);
            if (progress)
              progress->close();
            if (code == 0 && state == QProcess::NormalExit) {
              QFile::setPermissions(temp, QFile::ReadOwner | QFile::WriteOwner);
              if (!QFile::rename(temp, out))
                QMessageBox::warning(this, "HTTPS",
                                     "Cannot publish downloaded file");
            } else {
              QFile::remove(temp);
              QMessageBox::warning(
                  this, "HTTPS",
                  trText("Download failed or cancelled.",
                         "İndirme başarısız veya iptal edildi."));
            }
            p->deleteLater();
          });
  connect(p, &QProcess::errorOccurred, this,
          [this, p, progress, temp](auto error) {
            if (error != QProcess::FailedToStart)
              return;
            httpsJobs.remove(p);
            if (progress)
              progress->close();
            QFile::remove(temp);
            p->deleteLater();
            QMessageBox::warning(this, "HTTPS", "wget could not start");
          });
  p->start("/usr/bin/wget",
           {"--no-config", "--https-only", "--max-redirect=0", "--timeout=30",
            "--tries=2", "--output-document=" + temp, "--",
            url.toString(QUrl::FullyEncoded)});
  progress->show();
}
void Window::about() {
  QMessageBox box(this);
  box.setWindowTitle("ESCrypter");
  box.setIconPixmap(lockIcon().pixmap(64));
  box.setText(
      trText("ESCrypter 0.2.0 — development candidate\nGPLv3 · no "
             "warranty\nAutomated checks completed; target-platform and network validation remain pending.",
             "ESCrypter 0.2.0 — geliştirme adayı\nGPLv3 · garanti "
             "verilmez\nOtomatik kontroller tamamlandı; hedef platform ve ağ doğrulaması bekliyor."));
  box.setInformativeText(trText(
      "Source code, license texts and build scripts accompany the "
      "distribution. See Help → Open source licenses.",
      "Kaynak kodu, lisans metinleri ve derleme betikleri dağıtımla birlikte "
      "sunulur. Yardım → Açık kaynak lisansları bölümüne bakın."));
  box.exec();
}
void Window::closeTab(int index) {
  auto w = tabs->widget(index);
  if (!w)
    return;
  if (auto server = qobject_cast<ServerView *>(w)) {
    auto answer = QMessageBox::question(
        this, "ECP",
        trText(
            "Close connection tab? Remote jobs continue on the server.",
            "Bağlantı sekmesi kapatılsın mı? Uzak işler sunucuda devam eder."));
    if (answer != QMessageBox::Yes)
      return;
    server->session->close();
  } else if (w != transfers) {
    QList<LocalJob *> active;
    for (auto job : manager->all)
      if (owners.value(job) == w &&
          (job->status == "queued" || job->status == "running" ||
           job->status == "cancelling"))
        active << job;
    if (!active.isEmpty()) {
      QMessageBox box(this);
      box.setText(
          trText("This tab has active jobs.", "Bu sekmede etkin işler var."));
      auto background =
          box.addButton(trText("Continue in background", "Arka planda sürdür"),
                        QMessageBox::AcceptRole);
      auto cancel =
          box.addButton(trText("Cancel these jobs", "Bu işleri iptal et"),
                        QMessageBox::DestructiveRole);
      box.addButton(QMessageBox::Cancel);
      box.exec();
      if (box.clickedButton() == cancel) {
        for (auto job : active)
          job->cancel();
      } else if (box.clickedButton() != background)
        return;
    }
  }
  for (auto j : manager->all)
    if (owners.value(j) == w)
      j->result = {};
  tabs->removeTab(index);
  if (w != transfers)
    w->deleteLater();
  if (!tabs->count())
    newLocal();
}
void Window::closeEvent(QCloseEvent *e) {
  if (manager->active() || transfers->active() || !httpsJobs.isEmpty()) {
    QMessageBox box(this);
    box.setText(
        trText("Operations are active. Cancel safely before closing?",
               "İşlemler sürüyor. Kapatmadan önce güvenle iptal edilsin mi?"));
    box.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    if (box.exec() == QMessageBox::Yes) {
      manager->cancelAll();
      transfers->cancelAll();
      for (auto p : httpsJobs)
        p->terminate();
    }
    e->ignore();
    return;
  }
  for (int i = 0; i < tabs->count(); i++)
    if (auto r = qobject_cast<ServerView *>(tabs->widget(i)))
      r->session->close();
  e->accept();
}
