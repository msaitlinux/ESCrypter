#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
[[ ${1:-} == --no-build ]] || ./build.sh
arch=$(dpkg --print-architecture)
target_dir=${CARGO_TARGET_DIR:-target}
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
mkdir -p dist
core="$stage/core"; gui="$stage/gui"
install -Dm755 "$target_dir/release/escrypter" "$core/usr/bin/escrypter"
install -Dm755 "$target_dir/release/escrypter-agent" "$core/usr/bin/escrypter-agent"
install -Dm644 packaging/escrypter-agent.service "$core/usr/lib/systemd/user/escrypter-agent.service"
install -Dm755 build-gui/escrypter-gui "$gui/usr/bin/escrypter-gui"
install -Dm644 packaging/escrypter.desktop "$gui/usr/share/applications/escrypter.desktop"
install -Dm644 packaging/escrypter.xml "$gui/usr/share/mime/packages/escrypter.xml"
install -Dm644 packaging/escrypter.svg "$gui/usr/share/icons/hicolor/scalable/apps/escrypter.svg"
for pkg in "$core" "$gui"; do
    docname=escrypter
    [[ "$pkg" != "$core" ]] || docname=escrypter-core
    mkdir -p "$pkg/DEBIAN"
    for doc in docs/DEBUG_REPORT_TR.md docs/ECP.md docs/IMPLEMENTATION_STATUS.md FORMAT.md BUILD_STATUS.json; do
        install -Dm644 "$doc" "$pkg/usr/share/doc/$docname/$doc"
    done
    install -Dm644 LICENSE "$pkg/usr/share/doc/$docname/COPYING"
    install -Dm644 README_TR.md "$pkg/usr/share/doc/$docname/README_TR.md"
    install -Dm644 THIRD_PARTY_NOTICES.txt "$pkg/usr/share/doc/$docname/THIRD_PARTY_NOTICES.txt"
    install -Dm644 licenses/catalog.json "$pkg/usr/share/doc/$docname/licenses.json"
done
cat > "$core/DEBIAN/control" <<CONTROL
Package: escrypter-core
Version: 0.2.0
Section: utils
Priority: optional
Architecture: $arch
Maintainer: ESCrypter contributors <maintainer@localhost>
Depends: libc6 (>= 2.39), libgcc-s1, libsodium23, liblzma5
Description: ESCrypter cryptographic core and per-user ECP agent
 GPLv3 file encryption, signed archives and SSH-bridged remote jobs.
CONTROL
cat > "$gui/DEBIAN/control" <<CONTROL
Package: escrypter
Version: 0.2.0
Section: utils
Priority: optional
Architecture: $arch
Maintainer: ESCrypter contributors <maintainer@localhost>
Depends: escrypter-core (= 0.2.0), libc6 (>= 2.39), libgcc-s1, libstdc++6, libsodium23, libcurl4t64, libqt6core6t64, libqt6gui6 | libqt6gui6t64, libqt6widgets6 | libqt6widgets6t64, libqt6svg6, libqt6concurrent6 | libqt6concurrent6t64, qt6-qpa-plugins, openssh-client
Recommends: qt6-wayland, wget
Description: ESCrypter tabbed desktop and SFTP client
 Bilingual Qt6 workspace, cryptographic jobs and ECP remote management.
CONTROL
dpkg-deb --root-owner-group --build "$core" "dist/escrypter-core_0.2.0_${arch}.deb"
dpkg-deb --root-owner-group --build "$gui" "dist/escrypter_0.2.0_${arch}.deb"
