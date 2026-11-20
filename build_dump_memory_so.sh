#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == -h || ${1:-} == --help ]]; then
    echo "Usage: ANDROID_NDK_HOME=/path/to/ndk $0 [abi] [api]"
    echo "ABIs: arm64-v8a (default), armeabi-v7a, x86_64, x86"
    echo "API: 24 or newer (default: 24)"
    exit 0
fi

ndk=${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}
abi=${1:-arm64-v8a}
api=${2:-24}

if (( $# > 2 )) || [[ ! $api =~ ^[1-9][0-9]*$ ]] || (( api < 24 )); then
    echo "Expected [abi] [api], with API 24 or newer." >&2
    exit 1
fi

case "$abi" in
    arm64-v8a) triple=aarch64-linux-android ;;
    armeabi-v7a) triple=armv7a-linux-androideabi ;;
    x86_64) triple=x86_64-linux-android ;;
    x86) triple=i686-linux-android ;;
    *) echo "Unsupported ABI: $abi" >&2; exit 1 ;;
esac

case "$(uname -s)" in
    Linux) host=linux-x86_64 ;;
    Darwin) host=darwin-x86_64 ;;
    *) echo "This script supports Linux and macOS hosts." >&2; exit 1 ;;
esac

if [[ -z $ndk ]]; then
    echo "Set ANDROID_NDK_HOME to the Android NDK installation directory." >&2
    exit 1
fi

compiler="$ndk/toolchains/llvm/prebuilt/$host/bin/${triple}${api}-clang++"
if [[ ! -x $compiler ]]; then
    echo "NDK compiler not found: $compiler" >&2
    exit 1
fi

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
output_dir="$project_dir/build/android/$abi/api-$api"
mkdir -p -- "$output_dir"
"$compiler" -std=c++11 -O2 -static-libstdc++ \
    "$project_dir/dump_memory_so.cpp" -o "$output_dir/dump_memory_so"
echo "$output_dir/dump_memory_so"
