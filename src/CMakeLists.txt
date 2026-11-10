# libswpor：核心库（SPEC 9.1）。不含任何 CLI 或应用层代码。

add_library(swpor STATIC
    core/challenge.c
    core/ctx.c
    core/error.c
    core/fr.c
    core/prf.c
    core/prove.c
    core/selftest.c
    core/tag_header.c
    ec/ec.c
    ec/pipeline.c
    priv/priv.c
    pub/pub.c
    store/keyfile.c
    store/store.c
    platform/platform_posix.c
    platform/platform_win32.c
)
add_library(swpor::swpor ALIAS swpor)

target_include_directories(swpor
    PUBLIC
        "${PROJECT_SOURCE_DIR}/include"
        "${PROJECT_BINARY_DIR}/generated"
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/core"
        "${CMAKE_CURRENT_SOURCE_DIR}/platform")

# ---- Intel ISA-L（纠删码，SPEC 2）：Homebrew / apt / vcpkg 的头文件布局不同，按文件名查找 ----
find_path(SWPOR_ISAL_INCLUDE_DIR erasure_code.h PATH_SUFFIXES isa-l include/isa-l)
find_library(SWPOR_ISAL_LIBRARY NAMES isal libisal isa-l)
if(NOT SWPOR_ISAL_INCLUDE_DIR OR NOT SWPOR_ISAL_LIBRARY)
    message(FATAL_ERROR "swpor: 未找到 ISA-L（brew install isa-l / apt install libisal-dev / vcpkg isal）")
endif()
message(STATUS "swpor: ISA-L ${SWPOR_ISAL_LIBRARY}")
target_include_directories(swpor SYSTEM PRIVATE "${SWPOR_ISAL_INCLUDE_DIR}")

target_link_libraries(swpor
    PRIVATE
        "${SWPOR_ISAL_LIBRARY}"
    PUBLIC
        OpenSSL::Crypto
        swpor::blst
        Threads::Threads)

if(WIN32)
    target_link_libraries(swpor PUBLIC ws2_32 advapi32)
endif()

if(SWPOR_TESTING)
    target_compile_definitions(swpor PUBLIC SWPOR_TESTING=1)
endif()

swpor_set_warnings(swpor)
swpor_enable_sanitizers(swpor)

# ---------------------------------------------------------------------------
# swpor_net：网络协议、客户端与服务端（SPEC 8）。libswpor 本身不含网络代码（SPEC 9.1）。
# ---------------------------------------------------------------------------
add_library(swpor_net STATIC
    net/client.c
    net/frame.c
    net/remote.c
    net/server.c
    platform/sock_posix.c
    platform/sock_win32.c
)
add_library(swpor::net ALIAS swpor_net)
target_include_directories(swpor_net PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/core"
    "${CMAKE_CURRENT_SOURCE_DIR}/platform")
target_link_libraries(swpor_net PUBLIC swpor::swpor)
swpor_set_warnings(swpor_net)
swpor_enable_sanitizers(swpor_net)
