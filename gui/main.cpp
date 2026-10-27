// SPDX-License-Identifier: GPL-3.0-only
#include "window.h"
#include <sys/stat.h>
int main(int argc, char **argv) {
  umask(0077);
  QApplication app(argc, argv);
  QCoreApplication::setOrganizationName("ESCrypter");
  QCoreApplication::setApplicationName("ESCrypter");
  app.setWindowIcon(lockIcon());
  QString initial;
  auto a = app.arguments();
  int at = a.indexOf("--open");
  if (at >= 0 && at + 1 < a.size())
    initial = a[at + 1];
  Window window(initial);
  window.show();
  return app.exec();
}
