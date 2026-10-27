#pragma once
#include "common.h"
struct Profile {
  QString name, host, user, key, knownHosts;
  int port = 22;
  bool agent = true;
  QJsonObject json() const {
    return {{"name", name},
            {"host", host},
            {"user", user},
            {"key", key},
            {"knownHosts", knownHosts},
            {"port", port},
            {"agent", agent}};
  }
  static Profile from(const QJsonObject &o) {
    return {o["name"].toString(),       o["host"].toString(),
            o["user"].toString(),       o["key"].toString(),
            o["knownHosts"].toString(), o["port"].toInt(22),
            o["agent"].toBool(true)};
  }
};
class RemoteSession : public QObject {
  Q_OBJECT
  QProcess ssh;
  QByteArray input;
  QHash<QString, std::function<void(QJsonObject)>> pending;
  QHash<QString, qint64> deadlines;
  QTimer timeout;

public:
  Profile profile;
  bool connected = false;
  QJsonObject hello;
  explicit RemoteSession(Profile p, QObject *parent = nullptr);
  void open();
  void close();
  QString request(QString method, QJsonObject fields,
                  std::function<void(QJsonObject)> callback);
signals:
  void ready();
  void disconnected();
  void error(QString);
};
class ServerView : public QWidget {
  Q_OBJECT
  QTimer timer;
  QHash<QString, quint64> cursors;
  bool polling = false;

public:
  RemoteSession *session;
  QLineEdit *path;
  QTreeWidget *files, *jobs;
  QLabel *status;
  QPlainTextEdit *events;
  explicit ServerView(Profile p, QWidget *parent = nullptr);
  void refresh();
  void poll();
  QString selectedPath() const;
  QString selectedJob() const;
  void submit(QJsonObject spec, QJsonArray secrets);
  void cancelSelected();
};
