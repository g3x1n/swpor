/*
 * 不依赖 libFuzzer 的驱动：
 *   无参数：运行 N 次随机输入（N 默认 2000，可用环境变量 SWPOR_FUZZ_RUNS 修改），用于 ctest 冒烟测试；
 *   有参数：把每个参数当作输入文件运行一次（复现崩溃用例）。
 * 正式的模糊测试（每个目标至少 1 小时，SPEC 10.4）请用 libFuzzer 构建：-DSWPOR_FUZZ=ON。
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "swpor/swpor.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv)
{
    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            uint8_t *buf = NULL;
            size_t len = 0;
            if (swpor_read_file(argv[i], 1u << 24, &buf, &len) != SWPOR_OK) {
                fprintf(stderr, "cannot read %s\n", argv[i]);
                return 2;
            }
            LLVMFuzzerTestOneInput(buf, len);
            free(buf);
        }
        return 0;
    }
    long runs = 2000;
    const char *env = getenv("SWPOR_FUZZ_RUNS");
    if (env != NULL) {
        runs = strtol(env, NULL, 10);
    }
    static uint8_t buf[4096];
    for (long r = 0; r < runs; r++) {
        uint8_t lenb[2];
        if (swpor_random_bytes(lenb, 2) != SWPOR_OK) {
            return 2;
        }
        size_t len = ((size_t)lenb[0] << 8 | lenb[1]) % sizeof(buf);
        /* 一部分输入取"接近合法"的长度，提高进入深层分支的概率 */
        static const size_t near[] = {37, 37 + 32, 37 + 24, 37 + 48, 72, 164, 168, 228, 99, 115};
        if (r % 3 == 0) {
            len = near[(size_t)r / 3 % (sizeof(near) / sizeof(near[0]))];
        }
        if (swpor_random_bytes(buf, len) != SWPOR_OK) {
            return 2;
        }
        if (r % 5 == 0 && len >= 72) {
            buf[0] = 'S';
            buf[1] = 'W';
            buf[2] = 'P';
            buf[3] = 'T';
            buf[4] = 1;
            buf[5] = (uint8_t)(1 + (r % 2));
        }
        LLVMFuzzerTestOneInput(buf, len);
    }
    printf("%ld random inputs: no crash\n", runs);
    return 0;
}
