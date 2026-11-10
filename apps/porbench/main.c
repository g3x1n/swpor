/*
 * porbench：基准测试工具（SPEC 10.3）。计划在 M4 实现。
 * 输出 CSV 到 bench/results/，每次运行记录环境信息与 git commit（SPEC 10.3）。
 */

#include <stdio.h>
#include <string.h>

#include "platform.h"
#include "swpor/swpor.h"

int main(int argc, char **argv)
{
    if (argc >= 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "version") == 0)) {
        printf("porbench %s (%s)\n", swpor_version(), swpor_platform_name());
        return 0;
    }
    fprintf(stderr, "porbench %s: not implemented yet (planned for M4, see SPEC 10.3)\n",
            swpor_version());
    return 2;
}
