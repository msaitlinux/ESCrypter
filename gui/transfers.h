#pragma once
#include "remote.h"
#include <atomic>
struct TransferSpec {
  Profile profile;
  QString local, remote, renameTo;
  bool upload = true;
  quint64 offset = 0;
  quint64 limit = 0;
  quint64 speed = 0;
};
class TransferWorker : public QThread {
  Q_OBJECT
  TransferSpec spec;
  std::atomic_bool stop{false};

public:
  explicit TransferWorker(TransferSpec s, QObject *p = nullptr)
      : QThread(p), spec(s) {}
  void cancel() { stop.store(true); }
  void run() override;
signals:
  void progress(qint64 bytes, qint64 total);
  void outcome(bool ok, QString detail);
};
class Transfers : public QWidget {
  Q_OBJECT
  QTreeWidget *rows;
  QList<TransferWorker *> workers;
  QHash<TransferWorker *, QTreeWidgetItem *> items;
  QList<std::function<void()>> waiting;
  int running = 0;
  int pendingOperations = 0;
  quint64 generation = 0;
  QList<QTreeWidgetItem *> queuedRows;
  void asyncDigest(QObject *, QString, quint64, std::function<void(QString)>);
  void request(RemoteSession *, QString, QJsonObject,
               std::function<void(QJsonObject)>);
  void pump();
  void launch(TransferSpec spec, std::function<void(bool, QString)> done);

public:
  explicit Transfers(QWidget *p = nullptr);
  bool active() const;
  void cancelAll();
  void upload(Profile p, RemoteSession *session, QString local, QString remote);
  void download(Profile p, RemoteSession *session, QString remote,
                QString local);
};
