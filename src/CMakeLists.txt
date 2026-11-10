# libswpor：核心库（SPEC 9.1）。不含任何 CLI 或应用层代码。

add_library(swpor STATIC
    core/ctx.c
    core/error.c
    core/selftest.c
    platform/platform_posix.c
    platform/platform_win32.c
    # 以下模块随里程碑逐步加入：
    # priv/  (M1)  pub/  (M4)  ec/  (M2)  store/  (M2)  net/  (M3)
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

target_link_libraries(swpor
    PUBLIC
        OpenSSL::Crypto
        swpor::blst
        Threads::Threads)

if(WIN32)
    target_link_libraries(swpor PUBLIC ws2_32)
endif()

if(SWPOR_TESTING)
    target_compile_definitions(swpor PUBLIC SWPOR_TESTING=1)
endif()

swpor_set_warnings(swpor)
swpor_enable_sanitizers(swpor)
