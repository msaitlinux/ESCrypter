#pragma once
#include "jobs.h"
#include "transfers.h"
class Workspace : public QWidget {
  Q_OBJECT
public:
  QTreeWidget *files;
  QComboBox *compression;
  QLabel *summary;
  QString package;
  explicit Workspace(QWidget *p = nullptr);
  void addPaths(QStringList paths);
  QStringList paths() const;
  void retranslate();

protected:
  void dragEnterEvent(QDragEnterEvent *) override;
  void dropEvent(QDropEvent *) override;
signals:
  void encryptRequested();
  void openRequested();
};
class Window : public QMainWindow {
  Q_OBJECT
  QTabWidget *tabs;
  JobManager *manager;
  Transfers *transfers;
  QDockWidget *jobsDock;
  QTreeWidget *jobs;
  QPlainTextEdit *details;
  QHash<LocalJob *, QTreeWidgetItem *> jobRows;
  QHash<LocalJob *, QPointer<QWidget>> owners;
  QJsonArray profiles;
  QString signingKey;
  QSet<QProcess *> httpsJobs;
  Workspace *local() const;
  ServerView *remote() const;
  void menus();
  void newLocal();
  void openPackage(QString path = {});
  void encryptLocal(bool uploadAfter = false);
  void decryptLocal(bool recovery = false);
  void keyAction(QString action);
  void verifyLocal(bool info = false);
  void changePassword();
  void packageContent();
  void connection(bool saved = false);
  void remoteOperation(QString operation);
  void transfer(bool upload);
  void settingsDialog();
  void trustDialog();
  void licenses();
  void cleanup();
  void history();
  void diagnostics();
  void downloadHttps();
  void theme();
  void closeTab(int);
  QString trustedSigner();
  QString chooseKey();
  void track(LocalJob *);
  void about();

protected:
  void closeEvent(QCloseEvent *) override;

public:
  explicit Window(QString initial = {});
};
