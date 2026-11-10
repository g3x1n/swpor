cmake_minimum_required(VERSION 3.21)

project(swpor
    VERSION 0.0.1
    DESCRIPTION "Shacham-Waters Compact Proofs of Retrievability: data audit system"
    LANGUAGES C)

# ---------------------------------------------------------------------------
# 选项（见 SPEC 2.1）
# ---------------------------------------------------------------------------
if(WIN32)
    set(_swpor_server_default OFF)   # Windows 只做客户端，不构建 pord
else()
    set(_swpor_server_default ON)
endif()

option(SWPOR_BUILD_SERVER "Build the storage server (pord)" ${_swpor_server_default})
option(SWPOR_BUILD_TESTS  "Build unit tests"                ON)
option(SWPOR_WERROR       "Treat warnings as errors"        ON)
option(SWPOR_SANITIZE     "Enable ASan/UBSan in Debug builds" ON)
option(SWPOR_TESTING      "Compile deterministic RNG hooks for tests (never in releases)" OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(SwporWarnings)
include(SwporSanitizers)

# ---------------------------------------------------------------------------
# 依赖
# ---------------------------------------------------------------------------
# macOS + Homebrew：OpenSSL 是 keg-only，未使用 vcpkg 且未指定路径时自动查找。
if(APPLE AND NOT DEFINED VCPKG_TOOLCHAIN AND NOT DEFINED OPENSSL_ROOT_DIR
   AND NOT DEFINED ENV{OPENSSL_ROOT_DIR})
    find_program(_swpor_brew brew)
    if(_swpor_brew)
        execute_process(COMMAND ${_swpor_brew} --prefix openssl@3
            OUTPUT_VARIABLE _swpor_brew_openssl
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
            RESULT_VARIABLE _swpor_brew_rc)
        if(_swpor_brew_rc EQUAL 0 AND EXISTS "${_swpor_brew_openssl}")
            set(OPENSSL_ROOT_DIR "${_swpor_brew_openssl}")
            message(STATUS "swpor: using Homebrew OpenSSL at ${OPENSSL_ROOT_DIR}")
        endif()
    endif()
endif()

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)

include(Blst)   # 定义 swpor::blst（third_party/blst 子模块）

# ---------------------------------------------------------------------------
# 版本头文件
# ---------------------------------------------------------------------------
string(TOUPPER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_UPPER)
set(SWPOR_COMPILER_INFO "${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
set(SWPOR_BUILD_TYPE_INFO "${CMAKE_BUILD_TYPE}")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/include/swpor/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/swpor/version.h"
    @ONLY)

# 构建信息（git commit，供 porbench 记录，SPEC 10.3）：每次构建时刷新
add_custom_target(swpor_buildinfo
    COMMAND ${CMAKE_COMMAND} -DSRC_DIR=${CMAKE_CURRENT_SOURCE_DIR}
            -DOUT_FILE=${CMAKE_CURRENT_BINARY_DIR}/generated/swpor/buildinfo.h
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/BuildInfo.cmake
    BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/generated/swpor/buildinfo.h
    COMMENT "Refreshing build info")
set(SWPOR_C_FLAGS_INFO "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")

# ---------------------------------------------------------------------------
# 子目录
# ---------------------------------------------------------------------------
add_subdirectory(src)
add_subdirectory(apps)

if(SWPOR_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# 打包（SPEC 2.1 发布流程）
# ---------------------------------------------------------------------------
set(CPACK_PACKAGE_NAME "swpor")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
if(WIN32)
    set(CPACK_GENERATOR "ZIP")
else()
    set(CPACK_GENERATOR "TGZ")
endif()
include(CPack)

message(STATUS "swpor ${PROJECT_VERSION}: build type=${CMAKE_BUILD_TYPE} "
               "server=${SWPOR_BUILD_SERVER} tests=${SWPOR_BUILD_TESTS} "
               "sanitize=${SWPOR_SANITIZE}")
