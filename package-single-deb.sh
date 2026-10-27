#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ ${1:-} != --no-build ]]; then bash ./build.sh; fi
bash ./package-deb.sh --no-build
arch=$(dpkg --print-architecture)
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
dpkg-deb -x "dist/escrypter-core_0.2.0_${arch}.deb" "$stage"
dpkg-deb -x "dist/escrypter_0.2.0_${arch}.deb" "$stage"
mkdir -p "$stage/DEBIAN"
cat > "$stage/DEBIAN/control" <<CONTROL
Package: escrypter
Version: 0.2.0-1
Section: utils
Priority: optional
Architecture: $arch
Maintainer: ESCrypter contributors <maintainer@localhost>
Depends: libc6 (>= 2.39), libgcc-s1, libstdc++6, libsodium23, liblzma5, libcurl4t64, libqt6core6t64, libqt6gui6 | libqt6gui6t64, libqt6widgets6 | libqt6widgets6t64, libqt6svg6, libqt6concurrent6 | libqt6concurrent6t64, qt6-qpa-plugins, openssh-client
Recommends: qt6-wayland, wget
Provides: escrypter-core (= 0.2.0)
Breaks: escrypter-core (<< 0.2.0-1)
Replaces: escrypter-core (<< 0.2.0-1)
Description: ESCrypter complete desktop encryption application
 Includes the Qt6 graphical interface, cryptographic command-line core,
 SFTP client and per-user ECP agent in one package.
CONTROL
dpkg-deb --root-owner-group --build "$stage" "dist/ESCrypter_0.2.0-1_${arch}.deb"
