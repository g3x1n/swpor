# 测试（SPEC 10）。
# cmocka 查找顺序：CMake 配置包（vcpkg / Homebrew）→ pkg-config（apt）。找不到时跳过单元测试。

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
