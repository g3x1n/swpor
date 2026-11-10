/*
 * porctl：数据所有者客户端（SPEC 9.2）。
 *
 * 骨架阶段只实现 version / doctor / help；其余子命令按里程碑逐步实现。
 * 退出码约定见 SPEC 9.2：0 成功/PASS，1 审计 FAIL，2 参数错误，3 I/O 错误，
 * 4 网络错误，5 密码学/格式错误。
 */

#include <stdio.h>
#include <string.h>

#include "platform.h"
#include "swpor/swpor.h"

enum {
    EXIT_OK = 0,
    EXIT_AUDIT_FAIL = 1,
    EXIT_USAGE = 2,
    EXIT_IO = 3,
    EXIT_NET = 4,
    EXIT_CRYPTO = 5
};

typedef struct {
    const char *name;
    const char *milestone; /* 计划实现的里程碑（SPEC 1.3） */
    const char *summary;
} subcommand_t;

static const subcommand_t k_subcommands[] = {
    {"keygen", "M1", "generate a key pair (priv | pub)"},
    {"store", "M2", "preprocess, tag and store a file (local dir or server)"},
    {"audit", "M2", "challenge the storage and verify the proof"},
    {"retrieve", "M2", "download, check and decode a stored file"},
    {"info", "M2", "show the public header of a file tag"},
    {"tamper", "M2", "corrupt stored blocks for testing (local mode only)"},
};

static void print_usage(FILE *out)
{
    fprintf(out,
            "porctl %s - proof-of-retrievability client\n"
            "\n"
            "usage: porctl <command> [options]\n"
            "\n"
            "commands:\n",
            swpor_version());
    for (size_t i = 0; i < sizeof(k_subcommands) / sizeof(k_subcommands[0]); i++) {
        fprintf(out, "  %-10s %s  [planned: %s]\n", k_subcommands[i].name,
                k_subcommands[i].summary, k_subcommands[i].milestone);
    }
    fprintf(out,
            "  %-10s %s\n"
            "  %-10s %s\n"
            "  %-10s %s\n",
            "doctor", "check that OpenSSL and blst are linked and working", "version",
            "print version information", "help", "show this message");
}

static int cmd_version(void)
{
    printf("porctl %s\n", swpor_version());
    printf("platform: %s\n", swpor_platform_name());
    printf("openssl:  %s\n", swpor_openssl_version());
    return EXIT_OK;
}

static int cmd_doctor(void)
{
    int rc = swpor_selftest();
    if (rc != SWPOR_OK) {
        fprintf(stderr, "doctor: FAILED (%s)\n", swpor_strerror(rc));
        return EXIT_CRYPTO;
    }
    printf("doctor: OK (OpenSSL RAND/HMAC, blst hash-to-G1/pairing)\n");
    return EXIT_OK;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage(stderr);
        return EXIT_USAGE;
    }
    const char *cmd = argv[1];

    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        print_usage(stdout);
        return EXIT_OK;
    }
    if (strcmp(cmd, "version") == 0 || strcmp(cmd, "--version") == 0) {
        return cmd_version();
    }
    if (strcmp(cmd, "doctor") == 0) {
        return cmd_doctor();
    }
    for (size_t i = 0; i < sizeof(k_subcommands) / sizeof(k_subcommands[0]); i++) {
        if (strcmp(cmd, k_subcommands[i].name) == 0) {
            fprintf(stderr, "porctl %s: not implemented yet (planned for %s, see SPEC 9.2)\n",
                    cmd, k_subcommands[i].milestone);
            return EXIT_USAGE;
        }
    }

    fprintf(stderr, "porctl: unknown command '%s'\n\n", cmd);
    print_usage(stderr);
    return EXIT_USAGE;
}
