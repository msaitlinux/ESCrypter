#include "jobs.h"
void LocalJob::start() {
  status = "running";
  clock.start();
  emit changed();
  connect(&process, &QProcess::started, this, [this] {
    QByteArray b;
    for (auto &s : secrets) {
      b += s.toUtf8();
      b += '\n';
      s.fill(QChar(0));
    }
    secrets.clear();
    process.write(b);
    b.fill(0);
    process.closeWriteChannel();
  });
  connect(&process, &QProcess::readyReadStandardError, this, [this] {
    buffer += process.readAllStandardError();
    if (buffer.size() > 1024 * 1024) {
      detail = "Worker event stream too large";
      cancel();
      buffer.clear();
      return;
    }
    int end;
    while ((end = buffer.indexOf('\n')) >= 0) {
      auto line = buffer.left(end);
      buffer.remove(0, end + 1);
      auto o = QJsonDocument::fromJson(line).object();
      if (o["v"].toInt() != 1)
        continue;
      auto e = o["event"].toString();
      auto d = o["data"].toObject();
      if (e == "total")
        total = d["bytes"].toVariant().toLongLong();
      if (e == "progress")
        bytes = d["bytes"].toVariant().toLongLong();
      if (e == "phase" || e == "progress" || e == "total")
        phase = d["phase"].toString();
      if (e == "failed")
        detail = d["message"].toString();
      if (e == "signer") {
        signer = d["fingerprint"].toString();
        trusted = d["trusted"].toBool();
      }
      if (e == "package" || e == "content")
        result = d;
      emit changed();
    }
  });
  connect(&process, &QProcess::readyReadStandardOutput, this,
          [this] { process.readAllStandardOutput(); });
  connect(&process, &QProcess::errorOccurred, this,
          [this](QProcess::ProcessError e) {
            if (e == QProcess::FailedToStart) {
              for (auto &secret : secrets)
                secret.fill(QChar(0));
              secrets.clear();
              status = "failed";
              detail = process.errorString();
              emit changed();
              emit ended(false);
            }
          });
  connect(&process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
          this, [this](int c, QProcess::ExitStatus s) {
            bool ok = c == 0 && s == QProcess::NormalExit;
            status = ok                       ? "completed"
                     : status == "cancelling" ? "cancelled"
                                              : "failed";
            emit changed();
            emit ended(ok);
          });
  auto env = QProcessEnvironment::systemEnvironment();
  env.insert(
      "ESCRYPTER_MEMORY_MIB",
      QSettings("ESCrypter", "ESCrypter").value("memory", 1024).toString());
  auto tmp = QSettings("ESCrypter", "ESCrypter").value("temporary").toString();
  if (!tmp.isEmpty())
    env.insert("TMPDIR", tmp);
  process.setProcessEnvironment(env);
  process.start(coreBinary(), QStringList{"--events"} + args);
}
void LocalJob::cancel() {
  if (status == "queued") {
    status = "cancelled";
    for (auto &s : secrets)
      s.fill(QChar(0));
    secrets.clear();
    emit changed();
    return;
  }
  if (status == "running") {
    status = "cancelling";
    process.terminate();
    emit changed();
  }
}
LocalJob *JobManager::add(QString label, QStringList args, QStringList secrets,
                          QString output) {
  auto j = new LocalJob(this);
  j->label = label;
  j->args = args;
  j->secrets = secrets;
  j->output = output;
  all << j;
  queue << j;
  connect(j, &LocalJob::ended, this, [this, j](bool ok) {
    running = qMax(0, running - 1);
    if (QSettings("ESCrypter", "ESCrypter").value("history", false).toBool()) {
      auto data = loadJson(stateHome() + "/history.json");
      auto list = data["jobs"].toArray();
      list.append(QJsonObject{
          {"id", j->id},
          {"label", j->label},
          {"status", j->status},
          {"time", QDateTime::currentDateTimeUtc().toString(Qt::ISODate)}});
      while (list.size() > 200)
        list.removeFirst();
      saveJson(stateHome() + "/history.json", {{"jobs", list}});
    }
    pump();
  });
  emit added(j);
  QTimer::singleShot(0, this, [this] { pump(); });
  return j;
}
void JobManager::pump() {
  int max = QSettings("ESCrypter", "ESCrypter").value("parallel", 1).toInt();
  max = qBound(1, max, 4);
  while (running < max && !queue.isEmpty()) {
    auto j = queue.takeFirst();
    if (j->status != "queued")
      continue;
    running++;
    j->start();
  }
}
bool JobManager::active() const {
  for (auto j : all)
    if (j->status == "queued" || j->status == "running" ||
        j->status == "cancelling")
      return true;
  return false;
}
void JobManager::cancelAll() {
  for (auto j : all)
    j->cancel();
}
