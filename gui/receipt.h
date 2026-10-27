#pragma once
#include "common.h"
#include <sodium.h>
inline bool validReceipt(const QJsonObject &receipt, const QString &pinnedKey,
                         const QString &id, const QString &sha, qint64 size) {
  auto pk = QByteArray::fromHex(receipt["public_key"].toString().toLatin1());
  auto sig = QByteArray::fromHex(receipt["signature"].toString().toLatin1());
  auto payload =
      QByteArray::fromHex(receipt["payload_hex"].toString().toLatin1());
  QByteArray message("ESCrypter receipt v1\0",
                     sizeof("ESCrypter receipt v1\0") - 1);
  message += payload;
  auto fields = QJsonDocument::fromJson(payload).object();
  return receipt["public_key"].toString() == pinnedKey && pk.size() == 32 &&
         sig.size() == 64 && fields["v"].toInt() == 1 &&
         fields["upload_id"].toString() == id &&
         fields["sha256"].toString() == sha &&
         fields["bytes"].toVariant().toLongLong() == size &&
         sodium_init() >= 0 &&
         crypto_sign_verify_detached(
             reinterpret_cast<const unsigned char *>(sig.constData()),
             reinterpret_cast<const unsigned char *>(message.constData()),
             message.size(),
             reinterpret_cast<const unsigned char *>(pk.constData())) == 0;
}
