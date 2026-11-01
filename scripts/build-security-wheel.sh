#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 || ${1:-} == --help ]]; then
    echo 'Usage: bash scripts/build-security-wheel.sh NEW_WHEEL_DIRECTORY'
    echo 'Build the managed wheel with four jobs and a persistent Cargo cache.'
    [[ ${1:-} == --help ]] && exit 0
    exit 2
fi
repo=$(cd "$(dirname "$0")/.." && pwd)
if [[ $(uname -s) == Darwin ]]; then
    cache_root=${XDG_CACHE_HOME:-$HOME/Library/Caches}
else
    cache_root=${XDG_CACHE_HOME:-$HOME/.cache}
fi
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$cache_root/sparkles-builds/litellm}
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}
cd "$repo"
exec nice -n 10 uv build --wheel --python "${SPARKLES_BUILD_PYTHON:-3.12}" --out-dir "$1"
