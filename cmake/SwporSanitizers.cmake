# swpor_enable_sanitizers(<target>)
# Debug 构建时启用 AddressSanitizer / UndefinedBehaviorSanitizer（见 CLAUDE.md）。
#   - macOS/Linux：-fsanitize=address,undefined
#   - MSVC：/fsanitize=address（MSVC 没有 UBSan；且 /RTC1 与 ASan 冲突，需去掉）

if(MSVC AND SWPOR_SANITIZE)
    string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
endif()

function(swpor_enable_sanitizers target)
    if(NOT SWPOR_SANITIZE)
        return()
    endif()
    if(MSVC)
        target_compile_options(${target} PRIVATE $<$<CONFIG:Debug>:/fsanitize=address>)
    else()
        set(_flags -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
        target_compile_options(${target} PRIVATE $<$<CONFIG:Debug>:${_flags}>)
        target_link_options(${target} PRIVATE $<$<CONFIG:Debug>:-fsanitize=address,undefined>)
    endif()
endfunction()
