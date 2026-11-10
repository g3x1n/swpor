/*
 * porta：第三方审计者（SPEC 9.1）。计划在 M4 实现。
 * 只持有公钥 pk 与文件标签 t，对 Pub 方案的文件定期发起审计并记录日志。
 */

#include <stdio.h>
#include <string.h>

#include "swpor/swpor.h"

int main(int argc, char **argv)
{
    if (argc >= 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "version") == 0)) {
        printf("porta %s\n", swpor_version());
        return 0;
    }
    fprintf(stderr, "porta %s: not implemented yet (planned for M4)\n", swpor_version());
    return 2;
}
