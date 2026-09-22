#!/usr/bin/env bash
set -euo pipefail

workspace="${WORKSPACE:-/workspace}"
ida_sdk_repo="${IDA_SDK_REPO:-https://github.com/HexRaysSA/ida-sdk.git}"
ida_sdk_ref="${IDA_SDK_REF:-v9.3.0-sdk.2}"
ida_sdk_dir="${IDASDK:-${workspace}/ida-sdk}"
xwin_root="${XWIN_ROOT:-${workspace}/xwin}"
llvm_shim_dir="${LLVM_SHIM_DIR:-${workspace}/.ci-bin}"
cmake_preset="${CMAKE_PRESET:-windows-clang-release}"
plugin_name="${PLUGIN_NAME:-chernobog}"
jobs="${JOBS:-$(nproc)}"

if [[ ! -f "${workspace}/CMakeLists.txt" ]]; then
    echo "Expected repository root at ${workspace}" >&2
    exit 1
fi

mkdir -p "${llvm_shim_dir}"
python3 /usr/local/bin/prepare-llvm-shims.py "${llvm_shim_dir}"
export PATH="${llvm_shim_dir}:${PATH}"

if [[ ! -d "${ida_sdk_dir}" ]]; then
    git clone --branch "${ida_sdk_ref}" --depth 1 --recurse-submodules "${ida_sdk_repo}" "${ida_sdk_dir}"
elif [[ -d "${ida_sdk_dir}/.git" ]]; then
    git -C "${ida_sdk_dir}" submodule update --init --recursive
fi

if [[ ! -d "${xwin_root}/crt" || ! -d "${xwin_root}/sdk" ]]; then
    xwin --accept-license --arch x86_64 splat --output "${xwin_root}"
fi

export IDASDK="${ida_sdk_dir}"
export XWIN_ROOT="${xwin_root}"

cd "${workspace}"
cmake --preset "${cmake_preset}"
cmake --build --preset "${cmake_preset}" --parallel "${jobs}"

plugin_path=""
if [[ -f "${ida_sdk_dir}/src/bin/plugins/${plugin_name}.dll" ]]; then
    plugin_path="${ida_sdk_dir}/src/bin/plugins/${plugin_name}.dll"
elif [[ -f "${ida_sdk_dir}/bin/plugins/${plugin_name}.dll" ]]; then
    plugin_path="${ida_sdk_dir}/bin/plugins/${plugin_name}.dll"
fi

if [[ -z "${plugin_path}" ]]; then
    echo "Build finished but ${plugin_name}.dll was not found under ${ida_sdk_dir}" >&2
    exit 1
fi

echo "Built ${plugin_path}"
