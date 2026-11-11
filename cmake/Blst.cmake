# 从 third_party/blst（git submodule）构建 blst 静态库，导出目标 swpor::blst。
#
# - macOS / Linux：编译 src/server.c + build/assembly.S（汇编按平台自动选择，含 Apple arm64）。
# - Windows（MSVC，x64）：与 blst 自带的 build.bat 一致，编译 src/server.c 并用 ml64（MASM）汇编
#   build/win64/*-x86_64.asm。注意不能用 __BLST_NO_ASM__ 的纯 C 实现：它依赖变长数组（VLA），
#   MSVC 不支持（blst/src/no_asm.h 会报 "unsupported compiler"）。

set(BLST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/blst")

if(NOT EXISTS "${BLST_DIR}/src/server.c")
    message(FATAL_ERROR
        "third_party/blst 不存在。请先运行 scripts/bootstrap.sh "
        "（或 git submodule update --init --recursive）。")
endif()

if(MSVC)
    enable_language(ASM_MASM)
    file(GLOB _blst_win64_asm "${BLST_DIR}/build/win64/*-x86_64.asm")
    add_library(blst STATIC "${BLST_DIR}/src/server.c" ${_blst_win64_asm})
    # 与 build.bat 相同的 ml64 选项：/Cp /Cx 保留符号大小写
    set_source_files_properties(${_blst_win64_asm} PROPERTIES COMPILE_OPTIONS "/Cp;/Cx")
else()
    enable_language(ASM)
    add_library(blst STATIC
        "${BLST_DIR}/src/server.c"
        "${BLST_DIR}/build/assembly.S")
    target_compile_options(blst PRIVATE -O2 -fno-builtin -fPIC)
endif()

target_include_directories(blst SYSTEM PUBLIC "${BLST_DIR}/bindings")
set_target_properties(blst PROPERTIES POSITION_INDEPENDENT_CODE ON)
add_library(swpor::blst ALIAS blst)
