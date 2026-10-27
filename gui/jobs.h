#pragma once
#include "common.h"
class LocalJob : public QObject {
  Q_OBJECT
public:
  QString id = newId(), label, status = "queued", phase, output, detail, signer;
  bool trusted = false;
  qint64 bytes = 0, total = 0;
  QElapsedTimer clock;
  QJsonObject result;
  QProcess process;
  QStringList args, secrets;
  QByteArray buffer;
  explicit LocalJob(QObject *parent = nullptr) : QObject(parent) {}
  ~LocalJob() {
    for (auto &s : secrets)
      s.fill(QChar(0));
  }
  void start();
  void cancel();
signals:
  void changed();
  void ended(bool ok);
};
class JobManager : public QObject {
  Q_OBJECT
  QList<LocalJob *> queue;
  int running = 0;
  void pump();

public:
  QList<LocalJob *> all;
  explicit JobManager(QObject *p = nullptr) : QObject(p) {}
  LocalJob *add(QString label, QStringList args, QStringList secrets = {},
                QString output = {});
  bool active() const;
  void cancelAll();
signals:
  void added(LocalJob *);
};
