# 从 third_party/blst（git submodule）构建 blst 静态库，导出目标 swpor::blst。
#
# - macOS / Linux：编译 src/server.c + build/assembly.S（汇编按平台自动选择，含 Apple arm64）。
# - Windows（MSVC）：使用 blst 的纯 C 实现（__BLST_NO_ASM__），性能较低；Windows 为 Tier 2，
#   且不跑正式基准测试（SPEC 2.1），可以接受。

set(BLST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/blst")

if(NOT EXISTS "${BLST_DIR}/src/server.c")
    message(FATAL_ERROR
        "third_party/blst 不存在。请先运行 scripts/bootstrap.sh "
        "（或 git submodule update --init --recursive）。")
endif()

if(MSVC)
    add_library(blst STATIC "${BLST_DIR}/src/server.c")
    target_compile_definitions(blst PRIVATE __BLST_NO_ASM__)
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
