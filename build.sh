#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
cargo build --release --locked --offline
python3 tools/license_catalog.py
cmake -S gui -B build-gui -DCMAKE_BUILD_TYPE=Release
cmake --build build-gui --parallel 2
