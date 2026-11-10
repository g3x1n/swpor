# 应用程序（SPEC 9.1）。pord 只在 SWPOR_BUILD_SERVER=ON 时构建（Windows 默认关闭）。

# 公共 CLI 工具（选项解析、退出码、JSON、trace、文件适配）
add_library(swpor_cli STATIC common/cli.c)
target_include_directories(swpor_cli PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/common"
    "${PROJECT_SOURCE_DIR}/src/platform")
target_link_libraries(swpor_cli PUBLIC swpor::swpor)
swpor_set_warnings(swpor_cli)
swpor_enable_sanitizers(swpor_cli)

function(swpor_add_app name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE swpor_cli swpor::net)
    # 应用可以使用平台抽象层（如计时、文件），但不能直接包含系统头文件
    target_include_directories(${name} PRIVATE "${PROJECT_SOURCE_DIR}/src/platform")
    swpor_set_warnings(${name})
    swpor_enable_sanitizers(${name})
    install(TARGETS ${name} RUNTIME DESTINATION bin)
endfunction()

swpor_add_app(porctl   porctl/main.c)
swpor_add_app(porta    porta/main.c)
swpor_add_app(porbench porbench/main.c)

# porbench 记录编译器、构建类型与 git commit（SPEC 10.3）
add_dependencies(porbench swpor_buildinfo)
target_compile_definitions(porbench PRIVATE
    "SWPOR_COMPILER_INFO=\"${SWPOR_COMPILER_INFO}\""
    "SWPOR_BUILD_TYPE_INFO=\"${SWPOR_BUILD_TYPE_INFO}\"")
if(NOT MSVC)
    target_link_libraries(porbench PRIVATE m)
endif()

if(SWPOR_BUILD_SERVER)
    swpor_add_app(pord pord/main.c)
endif()
