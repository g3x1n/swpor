# swpor_utf8_manifest(<target>)
# Windows（MSVC）上为可执行文件嵌入 cmake/utf8.manifest，使 argv 与 ANSI 接口使用 UTF-8（T-26）。
# 其他平台什么也不做（POSIX 上 argv 本来就是 UTF-8 字节串）。
function(swpor_utf8_manifest target)
    if(MSVC)
        target_sources(${target} PRIVATE "${PROJECT_SOURCE_DIR}/cmake/utf8.manifest")
    endif()
endfunction()
