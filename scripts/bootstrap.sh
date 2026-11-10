#!/usr/bin/env bash
# 首次初始化仓库：git init、添加 blst 子模块（固定到最新的发布 tag）、首次提交。
# 可以重复执行：已完成的步骤会自动跳过。
#
# 用法：在仓库根目录执行  ./scripts/bootstrap.sh
set -euo pipefail

cd "$(dirname "$0")/.."

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

command -v git   >/dev/null || die "未找到 git"
command -v cmake >/dev/null || warn "未找到 cmake（macOS: brew install cmake ninja）"
command -v ninja >/dev/null || warn "未找到 ninja（macOS: brew install ninja），CMakePresets 默认使用 Ninja"

# 1. git 仓库
if [ ! -d .git ]; then
    say "初始化 git 仓库（默认分支 main）"
    git init -q -b main
fi

# 2. blst 子模块
BLST_URL="https://github.com/supranational/blst.git"
if [ ! -f third_party/blst/src/server.c ]; then
    if git config --file .gitmodules --get submodule.third_party/blst.url >/dev/null 2>&1; then
        say "拉取已登记的 blst 子模块"
        git submodule update --init --recursive
    else
        say "添加 blst 子模块"
        git submodule add -q "$BLST_URL" third_party/blst
        latest_tag=$(git -C third_party/blst tag --list 'v*' --sort=-v:refname | head -n 1)
        [ -n "$latest_tag" ] || die "无法获取 blst 的发布 tag"
        say "将 blst 固定到 $latest_tag"
        git -C third_party/blst checkout -q "$latest_tag"
        git add .gitmodules third_party/blst
    fi
fi

# 3. 平台相关提示
case "$(uname -s)" in
    Darwin)
        if command -v brew >/dev/null; then
            missing=()
            for f in openssl@3 cmocka ninja; do
                brew list --versions "$f" >/dev/null 2>&1 || missing+=("$f")
            done
            if [ ${#missing[@]} -gt 0 ]; then
                warn "使用 debug / release 预设前需安装：brew install ${missing[*]}"
                warn "（或者设置 VCPKG_ROOT 后使用 vcpkg-debug 预设）"
            fi
        else
            warn "未找到 Homebrew，请安装 Homebrew，或使用 vcpkg 预设"
        fi
        ;;
    Linux)
        warn "Ubuntu/Debian 依赖：sudo apt install build-essential cmake ninja-build libssl-dev libcmocka-dev"
        ;;
esac

# 4. 首次提交
if ! git rev-parse --verify -q HEAD >/dev/null; then
    say "创建首次提交"
    git add -A
    git commit -q -m "chore: project skeleton (SPEC v0.4)"
fi

say "完成。下一步："
echo "    cmake --preset debug && cmake --build --preset debug && ctest --preset debug"
echo "    ./build/debug/apps/porctl doctor"
