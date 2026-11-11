# 以脚本模式运行（cmake -P），每次构建时生成 buildinfo.h：git commit 哈希与工作区是否有改动。
# 基准测试结果需要记录 git commit（SPEC 10.3）。内容不变时不改写文件，避免触发重新编译。
#   输入：SRC_DIR、OUT_FILE
execute_process(COMMAND git rev-parse --short=12 HEAD
    WORKING_DIRECTORY "${SRC_DIR}" OUTPUT_VARIABLE _commit
    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET RESULT_VARIABLE _rc)
if(NOT _rc EQUAL 0 OR _commit STREQUAL "")
    set(_commit "unknown")
endif()
execute_process(COMMAND git status --porcelain --untracked-files=no
    WORKING_DIRECTORY "${SRC_DIR}" OUTPUT_VARIABLE _dirty
    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
if(NOT _dirty STREQUAL "")
    set(_commit "${_commit}-dirty")
endif()
set(_content "/* 自动生成，请勿编辑（cmake/BuildInfo.cmake） */\n#define SWPOR_GIT_COMMIT \"${_commit}\"\n")
if(EXISTS "${OUT_FILE}")
    file(READ "${OUT_FILE}" _old)
else()
    set(_old "")
endif()
if(NOT _old STREQUAL _content)
    file(WRITE "${OUT_FILE}" "${_content}")
endif()
