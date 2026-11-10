/*
 * 基础设施测试：确认骨架的构建、依赖链接与通用工具函数正常。
 * 这些不是 SPEC 第 10 节的算法测试（T-xx），因此不带编号。
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "endian.h"
#include "internal.h"
#include "platform.h"
#include "swpor/swpor.h"

static void test_infra_version_string(void **state)
{
    (void)state;
    assert_string_equal(swpor_version(), SWPOR_VERSION_STRING);
    assert_non_null(swpor_openssl_version());
}

static void test_infra_strerror_covers_all_codes(void **state)
{
    (void)state;
    static const int codes[] = {
        SWPOR_OK,          SWPOR_E_INVALID_ARG, SWPOR_E_NOMEM,   SWPOR_E_IO,
        SWPOR_E_PARSE,     SWPOR_E_TAG_AUTH,    SWPOR_E_CRYPTO,  SWPOR_E_RANGE,
        SWPOR_E_UNSUPPORTED, SWPOR_E_NET,       SWPOR_E_TIMEOUT, SWPOR_E_BUSY,
        SWPOR_E_EXISTS,    SWPOR_E_NOT_FOUND,   SWPOR_E_DECODE,  SWPOR_E_NOT_IMPLEMENTED,
    };
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); i++) {
        assert_string_not_equal(swpor_strerror(codes[i]), "unknown error");
    }
    assert_string_equal(swpor_strerror(12345), "unknown error");
}

static void test_infra_endian_roundtrip(void **state)
{
    (void)state;
    uint8_t buf[8];

    swpor_store_be16(buf, 0x1234u);
    assert_int_equal(buf[0], 0x12);
    assert_int_equal(buf[1], 0x34);
    assert_int_equal(swpor_load_be16(buf), 0x1234u);

    swpor_store_be32(buf, 0xA1B2C3D4u);
    assert_int_equal(buf[0], 0xA1);
    assert_int_equal(buf[3], 0xD4);
    assert_int_equal(swpor_load_be32(buf), 0xA1B2C3D4u);

    const uint64_t v = 0x0102030405060708ull;
    swpor_store_be64(buf, v);
    for (int i = 0; i < 8; i++) {
        assert_int_equal(buf[i], i + 1);
    }
    assert_true(swpor_load_be64(buf) == v);
}

static void test_infra_time_monotonic(void **state)
{
    (void)state;
    uint64_t a = swpor_time_ns();
    uint64_t b = swpor_time_ns();
    assert_true(a > 0);
    assert_true(b >= a);
}

typedef struct {
    int calls;
    char last[256];
} trace_capture_t;

static void capture_trace(const swpor_event_t *ev, void *user)
{
    trace_capture_t *cap = user;
    cap->calls++;
    strncpy(cap->last, ev->json, sizeof(cap->last) - 1);
    cap->last[sizeof(cap->last) - 1] = '\0';
}

static void test_infra_trace_dispatch(void **state)
{
    (void)state;
    swpor_ctx_t *ctx = NULL;
    assert_int_equal(swpor_ctx_new(&ctx), SWPOR_OK);

    trace_capture_t cap = {0};
    /* 未设置回调：不应调用 */
    swpor_trace_emit(ctx, SWPOR_EV_TAG_DONE, "\"n\":4");
    assert_int_equal(cap.calls, 0);

    swpor_set_trace(ctx, capture_trace, &cap);
    swpor_trace_emit(ctx, SWPOR_EV_TAG_DONE, "\"n\":4");
    assert_int_equal(cap.calls, 1);
    assert_string_equal(cap.last, "{\"type\":\"tag_done\",\"n\":4}");

    swpor_trace_emit(ctx, SWPOR_EV_VERIFY, NULL);
    assert_string_equal(cap.last, "{\"type\":\"verify\"}");

    swpor_ctx_free(ctx);
    swpor_ctx_free(NULL); /* 必须安全 */
    assert_int_equal(swpor_ctx_new(NULL), SWPOR_E_INVALID_ARG);
}

static void test_infra_dependency_selftest(void **state)
{
    (void)state;
    assert_int_equal(swpor_selftest(), SWPOR_OK);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_infra_version_string),
        cmocka_unit_test(test_infra_strerror_covers_all_codes),
        cmocka_unit_test(test_infra_endian_roundtrip),
        cmocka_unit_test(test_infra_time_monotonic),
        cmocka_unit_test(test_infra_trace_dispatch),
        cmocka_unit_test(test_infra_dependency_selftest),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
