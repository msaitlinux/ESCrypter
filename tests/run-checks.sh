#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
mkdir -p test-results
target_dir=${CARGO_TARGET_DIR:-target}
cargo fmt --check
cargo build --release --locked --offline 2>&1 | tee test-results/build-rust.log
cargo test --locked --offline 2>&1 | tee test-results/rust-tests.log
python3 tools/license_catalog.py
cmake -S gui -B build-gui -DCMAKE_BUILD_TYPE=Release -DESCRYPTER_TESTS=ON
cmake --build build-gui --parallel 2 2>&1 | tee test-results/build-gui.log
python3 tests/integration.py "$target_dir/release/escrypter" 2>&1 | tee test-results/integration.log
QT_QPA_PLATFORM=offscreen build-gui/escrypter-gui-tests test-results/gui.png 2>&1 | tee test-results/gui-tests.log
# Run separately on a host that permits Unix sockets and real SSH/SFTP fixtures:
# python3 tests/ecp_integration.py target/release
