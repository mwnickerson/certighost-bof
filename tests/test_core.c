#include <stdio.h>
#include <string.h>

#include "certighost_core.h"

#define TEST_BUF_CAP 4096u
#define TEST_OUTER_HEADER_LEN 4u

static int failures = 0;

static void write_u32_le(cg_u8 *buf, cg_u32 value) {
    buf[0] = (cg_u8)(value & 0xffu);
    buf[1] = (cg_u8)((value >> 8) & 0xffu);
    buf[2] = (cg_u8)((value >> 16) & 0xffu);
    buf[3] = (cg_u8)((value >> 24) & 0xffu);
}

static cg_u32 read_u32_le(const cg_u8 *buf) {
    return (cg_u32)buf[0] |
           ((cg_u32)buf[1] << 8) |
           ((cg_u32)buf[2] << 16) |
           ((cg_u32)buf[3] << 24);
}

static cg_u32 append_field(cg_u8 *buf, cg_u32 offset, const cg_u8 *value, cg_u32 len) {
    write_u32_le(buf + offset, len);
    offset += 4u;
    if (len != 0u) {
        memcpy(buf + offset, value, len);
        offset += len;
    }
    return offset;
}

static cg_u32 append_typed_binary_field(cg_u8 *buf, cg_u32 offset, const cg_u8 *value, cg_u32 len) {
    write_u32_le(buf + offset, 0u);
    return append_field(buf, offset + 4u, value, len);
}

static cg_u32 build_pack(cg_u8 *buf, const cg_u8 *csr, cg_u32 csr_len, const cg_u8 *template_name, cg_u32 template_len, const cg_u8 *san, cg_u32 san_len) {
    static const cg_u8 ca_config[] = "ca01.lab.local\\LAB-CA";
    static const cg_u8 cdc[] = "10.10.10.44";
    static const cg_u8 rmd[] = "dc01.lab.local";
    cg_u32 offset = TEST_OUTER_HEADER_LEN;

    offset = append_field(buf, offset, csr, csr_len);
    offset = append_field(buf, offset, ca_config, (cg_u32)sizeof(ca_config) - 1u);
    offset = append_field(buf, offset, template_name, template_len);
    offset = append_field(buf, offset, san, san_len);
    offset = append_field(buf, offset, cdc, (cg_u32)sizeof(cdc) - 1u);
    offset = append_field(buf, offset, rmd, (cg_u32)sizeof(rmd) - 1u);
    write_u32_le(buf, offset - TEST_OUTER_HEADER_LEN);
    return offset;
}

static cg_u32 build_valid_pack(cg_u8 *buf, const cg_u8 *template_name, cg_u32 template_len, const cg_u8 *san, cg_u32 san_len) {
    static const cg_u8 csr[] = {0x30u, 0x03u, 0x02u, 0x01u, 0x00u};

    return build_pack(buf, csr, (cg_u32)sizeof(csr), template_name, template_len, san, san_len);
}

static cg_u32 build_valid_apollo_pack(cg_u8 *buf) {
    static const cg_u8 csr[] = {0x30u, 0x03u, 0x02u, 0x01u, 0x00u};
    static const cg_u8 ca_config[] = "ca01.lab.local\\LAB-CA";
    static const cg_u8 template_name[] = "Machine";
    static const cg_u8 san[] = "ghost01.lab.local";
    static const cg_u8 cdc[] = "10.10.10.44";
    static const cg_u8 rmd[] = "dc01.lab.local";
    cg_u32 offset = 0u;

    offset = append_typed_binary_field(buf, offset, csr, (cg_u32)sizeof(csr));
    offset = append_typed_binary_field(buf, offset, ca_config, (cg_u32)sizeof(ca_config) - 1u);
    offset = append_typed_binary_field(buf, offset, template_name, (cg_u32)sizeof(template_name) - 1u);
    offset = append_typed_binary_field(buf, offset, san, (cg_u32)sizeof(san) - 1u);
    offset = append_typed_binary_field(buf, offset, cdc, (cg_u32)sizeof(cdc) - 1u);
    return append_typed_binary_field(buf, offset, rmd, (cg_u32)sizeof(rmd) - 1u);
}

static cg_u32 field_header_offset(const cg_u8 *buf, cg_u32 field_index) {
    cg_u32 offset = TEST_OUTER_HEADER_LEN;
    cg_u32 i;

    for (i = 0u; i < field_index; ++i) {
        cg_u32 field_len = read_u32_le(buf + offset);
        offset += 4u + field_len;
    }
    return offset;
}

static cg_u32 field_value_offset(const cg_u8 *buf, cg_u32 field_index) {
    return field_header_offset(buf, field_index) + 4u;
}

static void expect_status(const char *name, cg_status got, cg_status want) {
    if (got != want) {
        fprintf(stderr, "FAIL %-34s got=%s want=%s\n", name, cg_status_string(got), cg_status_string(want));
        failures += 1;
    } else {
        printf("PASS %s\n", name);
    }
}

static void test_valid_construction(void) {
    static const cg_u8 template_name[] = "Machine";
    static const cg_u8 san[] = "ghost01.lab.local";
    static const char expected[] =
        "CertificateTemplate:Machine\n"
        "SAN:dns=ghost01.lab.local\n"
        "cdc:10.10.10.44\n"
        "rmd:dc01.lab.local";
    cg_u8 packed[TEST_BUF_CAP];
    char attributes[CG_MAX_ATTRIBUTES_LEN + 1u];
    cg_u32 packed_len = build_valid_pack(packed, template_name, (cg_u32)sizeof(template_name) - 1u, san, (cg_u32)sizeof(san) - 1u);
    cg_u32 attributes_len = 0u;
    cg_input input;
    cg_status status;

    status = cg_parse_packed_args(packed, packed_len, &input);
    expect_status("valid packed arguments", status, CG_OK);
    if (read_u32_le(packed) != (packed_len - TEST_OUTER_HEADER_LEN)) {
        fprintf(stderr, "FAIL canonical outer frame length\n");
        failures += 1;
    } else {
        printf("PASS canonical outer frame length\n");
    }
    status = cg_build_attributes(&input, attributes, (cg_u32)sizeof(attributes), &attributes_len);
    expect_status("valid attribute construction", status, CG_OK);
    if (status == CG_OK && (attributes_len != (cg_u32)strlen(expected) || strcmp(attributes, expected) != 0)) {
        fprintf(stderr, "FAIL valid attribute bytes\n");
        failures += 1;
    } else if (status == CG_OK) {
        printf("PASS valid attribute bytes\n");
    }
}

static void test_valid_apollo_pack(void) {
    cg_u8 packed[TEST_BUF_CAP];
    cg_u32 packed_len = build_valid_apollo_pack(packed);
    cg_input input;

    expect_status("Apollo typed binary arguments", cg_parse_packed_args(packed, packed_len, &input), CG_OK);
}

static void test_optional_san(void) {
    static const cg_u8 template_name[] = "Machine";
    static const char expected[] =
        "CertificateTemplate:Machine\n"
        "cdc:10.10.10.44\n"
        "rmd:dc01.lab.local";
    cg_u8 packed[TEST_BUF_CAP];
    char attributes[CG_MAX_ATTRIBUTES_LEN + 1u];
    cg_u32 packed_len = build_valid_pack(packed, template_name, (cg_u32)sizeof(template_name) - 1u, (const cg_u8 *)"", 0u);
    cg_u32 attributes_len = 0u;
    cg_input input;
    cg_status status;

    status = cg_parse_packed_args(packed, packed_len, &input);
    expect_status("empty optional SAN accepted", status, CG_OK);
    status = cg_build_attributes(&input, attributes, (cg_u32)sizeof(attributes), &attributes_len);
    expect_status("attributes without SAN", status, CG_OK);
    if (status == CG_OK && (attributes_len != (cg_u32)strlen(expected) || strcmp(attributes, expected) != 0)) {
        fprintf(stderr, "FAIL optional SAN attribute bytes\n");
        failures += 1;
    } else if (status == CG_OK) {
        printf("PASS optional SAN attribute bytes\n");
    }
}

static void test_empty_csr(void) {
    static const cg_u8 template_name[] = "Machine";
    static const cg_u8 san[] = "ghost01.lab.local";
    cg_u8 packed[TEST_BUF_CAP];
    cg_u32 packed_len = build_pack(packed, (const cg_u8 *)"", 0u, template_name, (cg_u32)sizeof(template_name) - 1u, san, (cg_u32)sizeof(san) - 1u);
    cg_input input;

    expect_status("empty CSR rejected", cg_parse_packed_args(packed, packed_len, &input), CG_ERR_CSR_EMPTY);
}

static void test_overlong_template(void) {
    cg_u8 template_name[CG_MAX_TEMPLATE_LEN + 1u];
    static const cg_u8 san[] = "ghost01.lab.local";
    cg_u8 packed[TEST_BUF_CAP];
    cg_u32 i;
    cg_u32 packed_len;
    cg_input input;

    for (i = 0u; i < (cg_u32)sizeof(template_name); ++i) {
        template_name[i] = (cg_u8)'A';
    }
    packed_len = build_valid_pack(packed, template_name, (cg_u32)sizeof(template_name), san, (cg_u32)sizeof(san) - 1u);
    expect_status("overlong template rejected", cg_parse_packed_args(packed, packed_len, &input), CG_ERR_TEMPLATE_TOO_LONG);
}

static void test_malformed_der(void) {
    static const cg_u8 template_name[] = "Machine";
    static const cg_u8 san[] = "ghost01.lab.local";
    cg_u8 packed[TEST_BUF_CAP];
    cg_u32 packed_len = build_valid_pack(packed, template_name, (cg_u32)sizeof(template_name) - 1u, san, (cg_u32)sizeof(san) - 1u);
    cg_input input;

    packed[field_value_offset(packed, 0u)] = 0x31u;
    expect_status("malformed CSR DER rejected", cg_parse_packed_args(packed, packed_len, &input), CG_ERR_CSR_DER);
}

static void test_truncated_pack(void) {
    static const cg_u8 template_name[] = "Machine";
    static const cg_u8 san[] = "ghost01.lab.local";
    cg_u8 packed[TEST_BUF_CAP];
    cg_u32 packed_len = build_valid_pack(packed, template_name, (cg_u32)sizeof(template_name) - 1u, san, (cg_u32)sizeof(san) - 1u);
    cg_input input;

    packed_len -= 1u;
    write_u32_le(packed, packed_len - TEST_OUTER_HEADER_LEN);
    expect_status("truncated inner payload rejected", cg_parse_packed_args(packed, packed_len, &input), CG_ERR_PACK_TRUNCATED);
    expect_status("short outer header rejected", cg_parse_packed_args(packed, 3u, &input), CG_ERR_PACK_HEADER);
}

static void test_outer_length_mismatch(void) {
    static const cg_u8 template_name[] = "Machine";
    static const cg_u8 san[] = "ghost01.lab.local";
    cg_u8 packed[TEST_BUF_CAP];
    cg_u32 packed_len = build_valid_pack(packed, template_name, (cg_u32)sizeof(template_name) - 1u, san, (cg_u32)sizeof(san) - 1u);
    cg_input input;

    write_u32_le(packed, read_u32_le(packed) + 1u);
    expect_status("oversized outer length rejected", cg_parse_packed_args(packed, packed_len, &input), CG_ERR_PACK_TRUNCATED);

    packed_len = build_valid_pack(packed, template_name, (cg_u32)sizeof(template_name) - 1u, san, (cg_u32)sizeof(san) - 1u);
    write_u32_le(packed, read_u32_le(packed) - 1u);
    expect_status("undersized outer length rejected", cg_parse_packed_args(packed, packed_len, &input), CG_ERR_PACK_TRAILING);
}

static void test_inner_truncated_pack(void) {
    static const cg_u8 template_name[] = "Machine";
    static const cg_u8 san[] = "ghost01.lab.local";
    cg_u8 packed[TEST_BUF_CAP];
    cg_u32 packed_len = build_valid_pack(packed, template_name, (cg_u32)sizeof(template_name) - 1u, san, (cg_u32)sizeof(san) - 1u);
    cg_u32 rmd_header = field_header_offset(packed, 5u);
    cg_input input;

    write_u32_le(packed + rmd_header, 0xffffffffu);
    expect_status("inner field length rejected", cg_parse_packed_args(packed, packed_len, &input), CG_ERR_PACK_TRUNCATED);

    packed_len = build_valid_pack(packed, template_name, (cg_u32)sizeof(template_name) - 1u, san, (cg_u32)sizeof(san) - 1u);
    rmd_header = field_header_offset(packed, 5u);
    packed_len = rmd_header + 2u;
    write_u32_le(packed, packed_len - TEST_OUTER_HEADER_LEN);
    expect_status("inner field header rejected", cg_parse_packed_args(packed, packed_len, &input), CG_ERR_PACK_TRUNCATED);
}

static void test_trailing_pack(void) {
    static const cg_u8 template_name[] = "Machine";
    static const cg_u8 san[] = "ghost01.lab.local";
    cg_u8 packed[TEST_BUF_CAP];
    cg_u32 packed_len = build_valid_pack(packed, template_name, (cg_u32)sizeof(template_name) - 1u, san, (cg_u32)sizeof(san) - 1u);
    cg_input input;

    packed[packed_len] = 0u;
    packed_len += 1u;
    write_u32_le(packed, packed_len - TEST_OUTER_HEADER_LEN);
    expect_status("trailing inner bytes rejected", cg_parse_packed_args(packed, packed_len, &input), CG_ERR_PACK_TRAILING);
}

static void test_extra_field(void) {
    static const cg_u8 template_name[] = "Machine";
    static const cg_u8 san[] = "ghost01.lab.local";
    cg_u8 packed[TEST_BUF_CAP];
    cg_u32 packed_len = build_valid_pack(packed, template_name, (cg_u32)sizeof(template_name) - 1u, san, (cg_u32)sizeof(san) - 1u);
    cg_input input;

    packed_len = append_field(packed, packed_len, (const cg_u8 *)"", 0u);
    write_u32_le(packed, packed_len - TEST_OUTER_HEADER_LEN);
    expect_status("extra seventh field rejected", cg_parse_packed_args(packed, packed_len, &input), CG_ERR_PACK_TRAILING);
}

static void test_attribute_injection(void) {
    static const cg_u8 template_name[] = "Machine\ncdc:evil";
    static const cg_u8 san[] = "ghost01.lab.local";
    cg_u8 packed[TEST_BUF_CAP];
    cg_u32 packed_len = build_valid_pack(packed, template_name, (cg_u32)sizeof(template_name) - 1u, san, (cg_u32)sizeof(san) - 1u);
    cg_input input;

    expect_status("attribute injection rejected", cg_parse_packed_args(packed, packed_len, &input), CG_ERR_TEMPLATE_INVALID);
}

static void test_base64(void) {
    static const cg_u8 input[] = {0x01u, 0x02u, 0x03u, 0xfeu};
    char output[16];
    cg_u32 output_len = 0u;
    cg_status status = cg_base64_encode(input, (cg_u32)sizeof(input), output, (cg_u32)sizeof(output), &output_len);

    expect_status("base64 encode", status, CG_OK);
    if (status == CG_OK && (output_len != 8u || strcmp(output, "AQID/g==") != 0)) {
        fprintf(stderr, "FAIL base64 bytes\n");
        failures += 1;
    } else if (status == CG_OK) {
        printf("PASS base64 bytes\n");
    }
}

int main(void) {
    test_valid_construction();
    test_valid_apollo_pack();
    test_optional_san();
    test_empty_csr();
    test_overlong_template();
    test_malformed_der();
    test_truncated_pack();
    test_outer_length_mismatch();
    test_inner_truncated_pack();
    test_trailing_pack();
    test_extra_field();
    test_attribute_injection();
    test_base64();

    if (failures != 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("all core tests passed\n");
    return 0;
}
