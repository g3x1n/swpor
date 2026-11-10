# 测试（SPEC 10）。
# cmocka 查找顺序：CMake 配置包（vcpkg / Homebrew）→ pkg-config（apt）。找不到时跳过单元测试。

# ---- 差分测试 T-03（不依赖 cmocka）：C 端 ref_dump + Python 参考实现 ----
add_executable(ref_dump ref/ref_dump.c)
target_link_libraries(ref_dump PRIVATE swpor::swpor)
target_include_directories(ref_dump PRIVATE "${PROJECT_SOURCE_DIR}/src/platform")
swpor_set_warnings(ref_dump)
swpor_enable_sanitizers(ref_dump)

find_package(Python3 3.9 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_test(NAME T03_diff_python_ref
             COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/ref/run_diff.py"
                     "${PROJECT_BINARY_DIR}")
    add_test(NAME T14_T21_cli_integration
             COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_cli.py"
                     "${PROJECT_BINARY_DIR}")
endif()

find_package(cmocka CONFIG QUIET)
if(TARGET cmocka::cmocka)
    set(SWPOR_CMOCKA cmocka::cmocka)
else()
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(CMOCKA QUIET IMPORTED_TARGET cmocka)
        if(CMOCKA_FOUND)
            set(SWPOR_CMOCKA PkgConfig::CMOCKA)
        endif()
    endif()
endif()

if(NOT SWPOR_CMOCKA)
    message(WARNING "swpor: cmocka not found, unit tests are disabled. "
                    "Install it (brew install cmocka / apt install libcmocka-dev) or use a vcpkg preset.")
    return()
endif()

function(swpor_add_test name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE swpor::swpor ${SWPOR_CMOCKA})
    # 单元测试可以访问库的内部头文件
    target_include_directories(${name} PRIVATE
        "${PROJECT_SOURCE_DIR}/src"
        "${PROJECT_SOURCE_DIR}/src/core"
        "${PROJECT_SOURCE_DIR}/src/platform")
    swpor_set_warnings(${name})
    swpor_enable_sanitizers(${name})
    add_test(NAME ${name} COMMAND ${name})
endfunction()

swpor_add_test(test_infra unit/test_infra.c)
swpor_add_test(test_core unit/test_core.c)
swpor_add_test(test_priv unit/test_priv.c)
swpor_add_test(test_ec unit/test_ec.c)
swpor_add_test(test_pub unit/test_pub.c)

# 网络测试（T-15～T-18）需要服务端，Windows 上不构建 pord 相关功能
if(SWPOR_BUILD_SERVER)
    swpor_add_test(test_net unit/test_net.c)
    target_link_libraries(test_net PRIVATE swpor::net)
endif()
