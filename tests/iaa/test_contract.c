/* SPDX-License-Identifier: MIT */
/* Host-only independent observations: never submits an IAA request. */
#define main iaa_program_main
#include "test_iaa_unified_ops.c"
#undef main
#include "../../kernel/io_uring/iaa/xdev_ext_iaa_core.h"

#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "contract failure at line %d: %s\n", __LINE__, #x); return 1; } } while (0)

int main(void)
{
    uint8_t before[UMEM_SIZE] = {0}, data[UMEM_SIZE], plain[PLAIN_LEN];
    struct io_uring_unified_shared stats = {0};
    struct observation completion = {.cookie = COOKIE_BASE, .result = PLAIN_LEN};
    struct io_uring_sqe sqe;
    struct case_spec spec = case_specification(CASE_A, 1234);
    unsigned rejected = 0;

    /* Actual kernel provider has cra_name=deflate, driver=deflate-iaa. */
    char provider_text[] = "name         : deflate\ndriver       : deflate-iaa\ntype         : acomp\n";
    FILE *provider = fmemopen(provider_text, sizeof(provider_text) - 1, "r");
    REQUIRE(provider != NULL);
    REQUIRE(provider_in_stream(provider, "deflate-iaa"));
    fclose(provider);

    char software_text[] = "name : deflate-iaa\ndriver : deflate-generic\n";
    provider = fmemopen(software_text, sizeof(software_text) - 1, "r");
    REQUIRE(provider != NULL);
    REQUIRE(!provider_in_stream(provider, "deflate-iaa"));
    fclose(provider);
    provider = fmemopen(software_text, sizeof(software_text) - 1, "r");
    REQUIRE(provider != NULL);
    REQUIRE(provider_in_stream(provider, "deflate-generic"));
    fclose(provider);

    /* Selection and per-driver capacity-overflow contract. */
    char driver[DRIVER_MAX];
    char selection_text[] = "deflate-generic\n", bare_text[] = "deflate-generic";
    char overlong_text[DRIVER_MAX + 2];
    provider = fmemopen(selection_text, sizeof(selection_text) - 1, "r");
    REQUIRE(provider && selection_from_stream(provider, driver) && !strcmp(driver, "deflate-generic"));
    fclose(provider);
    provider = fmemopen(bare_text, sizeof(bare_text) - 1, "r");
    REQUIRE(provider && !selection_from_stream(provider, driver));
    fclose(provider);
    memset(overlong_text, 'a', sizeof(overlong_text));
    overlong_text[DRIVER_MAX] = '\n';
    provider = fmemopen(overlong_text, DRIVER_MAX + 1, "r");
    REQUIRE(provider && !selection_from_stream(provider, driver));
    fclose(provider);
    REQUIRE(provider_contract("deflate-iaa")->overflow == EOVERFLOW);
    REQUIRE(provider_contract("deflate-generic")->overflow == ENOSPC);
    REQUIRE(provider_contract("deflate") == NULL && provider_contract("lz4") == NULL);

    /* Served-driver attribution: exactly A and B reach the selected driver. */
    struct served sb, sa, ob, oa;
    char served_before[] = "deflate-iaa requests=4 errors=0 bytes=100\n"
                           "deflate-generic requests=7 errors=2 bytes=50\nuntracked requests=0\n";
    char served_after[] = "deflate-iaa requests=4 errors=0 bytes=100\n"
                          "deflate-generic requests=9 errors=3 bytes=9266\nuntracked requests=0\n";
    char served_other[] = "deflate-iaa requests=5 errors=0 bytes=100\n"
                          "deflate-generic requests=9 errors=3 bytes=9266\nuntracked requests=0\n";
    char served_bad[] = "deflate-generic requests=9 errors=3\n";
    char served_twice[] = "deflate-generic requests=1 errors=0 bytes=1\n"
                          "deflate-generic requests=1 errors=0 bytes=1\n";
    provider = fmemopen(served_before, sizeof(served_before) - 1, "r");
    REQUIRE(provider && !served_from_stream(provider, "deflate-generic", &sb, &ob));
    fclose(provider);
    REQUIRE(sb.requests == 7 && sb.errors == 2 && sb.bytes == 50 && ob.requests == 4);
    provider = fmemopen(served_after, sizeof(served_after) - 1, "r");
    REQUIRE(provider && !served_from_stream(provider, "deflate-generic", &sa, &oa));
    fclose(provider);
    REQUIRE(served_delta_valid(&sb, &sa, &ob, &oa));
    provider = fmemopen(served_other, sizeof(served_other) - 1, "r");
    REQUIRE(provider && !served_from_stream(provider, "deflate-generic", &sa, &oa));
    fclose(provider);
    REQUIRE(!served_delta_valid(&sb, &sa, &ob, &oa));
    rejected++;
    REQUIRE(!served_delta_valid(&sb, &sb, &ob, &ob));
    rejected++;
    provider = fmemopen(served_bad, sizeof(served_bad) - 1, "r");
    REQUIRE(provider && served_from_stream(provider, "deflate-generic", &sa, &oa) < 0);
    fclose(provider);
    provider = fmemopen(served_twice, sizeof(served_twice) - 1, "r");
    REQUIRE(provider && served_from_stream(provider, "deflate-generic", &sa, &oa) < 0);
    fclose(provider);

    fill_plaintext(plain, sizeof(plain));
    /* The gate's blob must inflate with deflate-generic's 2KiB window. Like its
     * destination walk, each inflate call gets one bounded output piece, so
     * history beyond the window cannot come from the output buffer itself. */
    uint8_t blob[PLAIN_LEN + 1024], inflated[PLAIN_LEN];
    size_t blob_len = raw_deflate(plain, PLAIN_LEN, blob, sizeof(blob));
    int inflate_rc = Z_OK;
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    REQUIRE(blob_len <= FRAME_SIZE - GUARD_LEN);
    REQUIRE(inflateInit2(&zs, -11) == Z_OK);
    zs.next_in = blob; zs.avail_in = (uInt)blob_len;
    while (inflate_rc == Z_OK && zs.total_out < sizeof(inflated)) {
        zs.next_out = inflated + zs.total_out;
        zs.avail_out = (uInt)(sizeof(inflated) - zs.total_out < 1024 ? sizeof(inflated) - zs.total_out : 1024);
        inflate_rc = inflate(&zs, Z_NO_FLUSH);
    }
    if (inflate_rc == Z_OK) inflate_rc = inflate(&zs, Z_FINISH);
    size_t inflated_len = zs.total_out;
    inflateEnd(&zs);
    REQUIRE(inflate_rc == Z_STREAM_END && inflated_len == PLAIN_LEN);
    REQUIRE(!memcmp(inflated, plain, PLAIN_LEN));
    memset(before + GUARD_LO_OFF, GUARD_BYTE, GUARD_LEN);
    memset(before + GUARD_HI_OFF, GUARD_BYTE, GUARD_LEN);
    memcpy(data, before, sizeof(data));
    memcpy(data + DST_OFF, plain, sizeof(plain));
    stats.calc_count = 1; stats.calc_result = PLAIN_LEN; stats.timestamp = 1;
    prepare_sqe(&sqe, &spec, COOKIE_BASE);
    REQUIRE(sqe.opcode == IORING_OP_UNIFIED_OPS);
    REQUIRE(sqe.len == IO_UNIFIED_OP_IAA_DECOMPRESS && sqe.len == 5);
    REQUIRE(sqe.flags == IOSQE_XDEV_EXT_UMEM && sqe.fd == -1);
    REQUIRE(sqe.addr == 0 && sqe.off == 16384 && sqe.rw_flags == 1234);
    REQUIRE(sqe.addr3 == 16384 && sqe.user_data == COOKIE_BASE);
    REQUIRE(FRAME_SIZE >= DST_CAP && PLAIN_LEN == 9216);
    struct xdev_ext_iaa_sqe_fields fields = xdev_ext_iaa_sqe_fields_from_words(
        sqe.addr, sqe.off, sqe.rw_flags, sqe.addr3);
    struct xdev_ext_iaa_window_plan plan;
    REQUIRE(xdev_ext_iaa_decode_windows(&fields, UMEM_SIZE, FRAME_SIZE, &plan) == 0);
    REQUIRE(xdev_ext_iaa_decode_windows(&fields, UMEM_SIZE, 4096, &plan) == -EMSGSIZE);
    struct xdev_ext_iaa_sg_cursor cursor;
    struct xdev_ext_iaa_sg_segment segment;
    REQUIRE(xdev_ext_iaa_sg_cursor_init(&cursor, 0, UMEM_SIZE / 4096, DST_OFF, PLAIN_LEN) == 0);
    REQUIRE(cursor.nents == 3);
    for (unsigned page = 0; page < 3; page++) {
        REQUIRE(xdev_ext_iaa_sg_cursor_next(&cursor, &segment) == 1);
        REQUIRE(segment.page_index == 4 + page && segment.page_offset == 0);
        REQUIRE(segment.length == (page == 2 ? 1024U : 4096U));
    }
    REQUIRE(xdev_ext_iaa_sg_cursor_next(&cursor, &segment) == 0);
    for (enum case_id id = CASE_A; id <= CASE_E; id++) {
        struct case_spec geometry = case_specification(id, 1234);
        prepare_sqe(&sqe, &geometry, COOKIE_BASE + id);
        fields = xdev_ext_iaa_sqe_fields_from_words(sqe.addr, sqe.off, sqe.rw_flags, sqe.addr3);
        REQUIRE(xdev_ext_iaa_decode_windows(&fields, UMEM_SIZE, FRAME_SIZE, &plan) ==
                (id < CASE_C ? 0 : -EINVAL));
    }
    REQUIRE(validate_result(CASE_A, COOKIE_BASE, &completion, data, before, plain, &stats, false));

#define REJECT() do { REQUIRE(!validate_result(CASE_A, COOKIE_BASE, &completion, data, before, plain, &stats, false)); rejected++; } while (0)
    completion.cookie++; REJECT(); completion.cookie--;
    completion.result--; REJECT(); completion.result++;
    completion.result = -EINVAL; REJECT(); completion.result = PLAIN_LEN;
    completion.flags = IORING_CQE_F_MORE; REJECT(); completion.flags = 0;
    data[DST_OFF + PLAIN_LEN - 1] ^= 1; REJECT(); data[DST_OFF + PLAIN_LEN - 1] ^= 1;
    data[GUARD_LO_OFF] ^= 1; REJECT(); data[GUARD_LO_OFF] ^= 1;
    data[GUARD_HI_OFF] ^= 1; REJECT(); data[GUARD_HI_OFF] ^= 1;
    data[DST_OFF + PLAIN_LEN] = 1; REJECT(); data[DST_OFF + PLAIN_LEN] = 0;
    data[0] = 1; REJECT(); data[0] = 0;
    stats.calc_count++; REJECT(); stats.calc_count--;
    stats.calc_result--; REJECT(); stats.calc_result++;
    stats.calc_errors++; REJECT(); stats.calc_errors--;
    stats.send_count++; REJECT(); stats.send_count--;
    stats.timestamp = 0; REJECT(); stats.timestamp = 1;

    /* Error observations remain failures if their identity/stats/isolation fail. */
    memcpy(data, before, sizeof(data));
    memset(&stats, 0, sizeof(stats)); stats.calc_errors = 1; stats.timestamp = 1;
    for (enum case_id id = CASE_B; id <= CASE_E; id++) {
        completion.result = id == CASE_B ? -EOVERFLOW : -EINVAL;
        REQUIRE(validate_result(id, COOKIE_BASE, &completion, data, before, plain, &stats, false));
        completion.result = -EOPNOTSUPP;
        REQUIRE(!validate_result(id, COOKIE_BASE, &completion, data, before, plain, &stats, false));
        rejected++;
    }
    completion.result = -EOVERFLOW;
    data[DST_OFF + TINY_CAP] = 1;
    REQUIRE(!validate_result(CASE_B, COOKIE_BASE, &completion, data, before, plain, &stats, false));
    rejected++;
    data[DST_OFF + TINY_CAP] = 0;
    data[DST_OFF] = 0x55; /* bounded partial output is permitted on overflow. */
    REQUIRE(validate_result(CASE_B, COOKIE_BASE, &completion, data, before, plain, &stats, false));
    completion.result = -EINVAL;
    REQUIRE(!validate_result(CASE_C, COOKIE_BASE, &completion, data, before, plain, &stats, false));
    rejected++;
    /* deflate-generic reports a too-small destination as ENOSPC. */
    overflow_errno = ENOSPC;
    completion.result = -ENOSPC;
    REQUIRE(validate_result(CASE_B, COOKIE_BASE, &completion, data, before, plain, &stats, false));
    completion.result = -EOVERFLOW;
    REQUIRE(!validate_result(CASE_B, COOKIE_BASE, &completion, data, before, plain, &stats, false));
    rejected++;
    overflow_errno = EOVERFLOW;
    printf("PASS: host contract accepted A-E observations and rejected %u corruptions; no device execution\n", rejected);
    return 0;
}
