# 应用程序（SPEC 9.1）。pord 只在 SWPOR_BUILD_SERVER=ON 时构建（Windows 默认关闭）。

function(swpor_add_app name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE swpor::swpor)
    # 应用可以使用平台抽象层（如 porbench 的计时），但不能直接包含系统头文件
    target_include_directories(${name} PRIVATE "${PROJECT_SOURCE_DIR}/src/platform")
    swpor_set_warnings(${name})
    swpor_enable_sanitizers(${name})
    install(TARGETS ${name} RUNTIME DESTINATION bin)
endfunction()

swpor_add_app(porctl   porctl/main.c)
swpor_add_app(porta    porta/main.c)
swpor_add_app(porbench porbench/main.c)

if(SWPOR_BUILD_SERVER)
    swpor_add_app(pord pord/main.c)
endif()
