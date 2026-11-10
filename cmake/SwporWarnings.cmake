# swpor_set_warnings(<target>)
# 只对本项目自己的目标启用严格警告；第三方库（blst）不受影响。
function(swpor_set_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /utf-8)
        # C4996：MSVC 认为 fopen 等 CRT 函数"不安全"，本项目统一走平台层，关闭该提示
        target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
        if(SWPOR_WERROR)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow
            -Wstrict-prototypes -Wmissing-prototypes -Wvla)
        if(SWPOR_WERROR)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()
endfunction()
