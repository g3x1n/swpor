/*
 * pord：存储服务端（SPEC 8、9.3）。计划在 M3 实现。
 * 只在 macOS / Linux 上构建（SPEC 2.1：Windows 不部署服务端）。
 */

#include <stdio.h>
#include <string.h>

#include "swpor/swpor.h"

int main(int argc, char **argv)
{
    if (argc >= 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "version") == 0)) {
        printf("pord %s\n", swpor_version());
        return 0;
    }
    fprintf(stderr,
            "pord %s: not implemented yet (planned for M3, see SPEC 8 and 9.3)\n"
            "usage: pord --listen <addr:port> --data-dir <dir> [--threads N] [--max-l N]\n",
            swpor_version());
    return 2;
}
