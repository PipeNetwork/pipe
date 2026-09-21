#!/usr/bin/env bash
set -euo pipefail

# Build this checkout. Installation never deletes an existing checkout or config.
pipe_source=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ ! -f "$pipe_source/Cargo.toml" ]]; then
    echo 'Clone https://github.com/PipeNetwork/pipe and run ./setup.sh inside it.' >&2
    exit 1
fi
if ! command -v cargo >/dev/null 2>&1; then
    echo 'Install the stable Rust toolchain, then rerun ./setup.sh.' >&2
    exit 1
fi
pipe_install_args=(--locked --path "$pipe_source")
if [[ ${1:-} == --force ]]; then
    pipe_install_args+=(--force)
    shift
fi
if [[ $# != 0 ]]; then
    echo 'Usage: ./setup.sh [--force]' >&2
    exit 2
fi
cargo install "${pipe_install_args[@]}"
echo 'Installed Pipe CLI. Run pipe --help to get started.'
