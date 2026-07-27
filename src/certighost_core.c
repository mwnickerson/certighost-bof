#include "certighost_core.h"

/* Apollo execute_coff v3 passes a BeaconDataParse-compatible outer length frame. */
static cg_u32 cg_read_u32_le(const cg_u8 *buf) {
    return (cg_u32)buf[0] |
           ((cg_u32)buf[1] << 8) |
           ((cg_u32)buf[2] << 16) |
           ((cg_u32)buf[3] << 24);
}

static int cg_is_visible_ascii(cg_u8 c) {
    return c >= 0x20u && c <= 0x7eu;
}

static int cg_is_dns_value_char(cg_u8 c) {
    if (c >= (cg_u8)'a' && c <= (cg_u8)'z') {
        return 1;
    }
    if (c >= (cg_u8)'A' && c <= (cg_u8)'Z') {
        return 1;
    }
    if (c >= (cg_u8)'0' && c <= (cg_u8)'9') {
        return 1;
    }
    return c == (cg_u8)'.' || c == (cg_u8)'-' || c == (cg_u8)'_';
}

static cg_status cg_validate_der_sequence(const cg_slice *csr) {
    cg_u32 header_len;
    cg_u32 content_len;
    cg_u32 octets;
    cg_u32 i;

    if (csr->len == 0u) {
        return CG_ERR_CSR_EMPTY;
    }
    if (csr->len > CG_MAX_CSR_LEN) {
        return CG_ERR_CSR_TOO_LONG;
    }
    if (csr->len < 2u || csr->ptr[0] != 0x30u) {
        return CG_ERR_CSR_DER;
    }
    if ((csr->ptr[1] & 0x80u) == 0u) {
        header_len = 2u;
        content_len = (cg_u32)csr->ptr[1];
    } else {
        octets = (cg_u32)(csr->ptr[1] & 0x7fu);
        if (octets == 0u || octets > 4u || csr->len < (2u + octets)) {
            return CG_ERR_CSR_DER;
        }
        if (csr->ptr[2] == 0u) {
            return CG_ERR_CSR_DER;
        }
        content_len = 0u;
        for (i = 0u; i < octets; ++i) {
            content_len = (content_len << 8) | (cg_u32)csr->ptr[2u + i];
        }
        if (content_len < 128u) {
            return CG_ERR_CSR_DER;
        }
        header_len = 2u + octets;
    }
    if (header_len > csr->len || content_len != (csr->len - header_len)) {
        return CG_ERR_CSR_DER;
    }
    return CG_OK;
}

static cg_status cg_validate_ca_config(const cg_slice *value) {
    cg_u32 i;
    cg_u32 slash_count = 0u;
    cg_u32 slash_pos = 0u;

    if (value->len == 0u) {
        return CG_ERR_CA_CONFIG_EMPTY;
    }
    if (value->len > CG_MAX_CA_CONFIG_LEN) {
        return CG_ERR_CA_CONFIG_TOO_LONG;
    }
    for (i = 0u; i < value->len; ++i) {
        cg_u8 c = value->ptr[i];
        if (!cg_is_visible_ascii(c) || c == (cg_u8)':' || c == (cg_u8)'/' || c == (cg_u8)'\r' || c == (cg_u8)'\n') {
            return CG_ERR_CA_CONFIG_INVALID;
        }
        if (c == (cg_u8)'\\') {
            slash_count += 1u;
            slash_pos = i;
        }
    }
    if (slash_count != 1u || slash_pos == 0u || slash_pos == (value->len - 1u)) {
        return CG_ERR_CA_CONFIG_INVALID;
    }
    return CG_OK;
}

static cg_status cg_validate_template(const cg_slice *value) {
    cg_u32 i;

    if (value->len == 0u) {
        return CG_ERR_TEMPLATE_EMPTY;
    }
    if (value->len > CG_MAX_TEMPLATE_LEN) {
        return CG_ERR_TEMPLATE_TOO_LONG;
    }
    for (i = 0u; i < value->len; ++i) {
        cg_u8 c = value->ptr[i];
        if (!cg_is_visible_ascii(c) || c == (cg_u8)':' || c == (cg_u8)'\r' || c == (cg_u8)'\n') {
            return CG_ERR_TEMPLATE_INVALID;
        }
    }
    return CG_OK;
}

static cg_status cg_validate_dns_value(const cg_slice *value, int optional, cg_status empty_error, cg_status too_long_error, cg_status invalid_error) {
    cg_u32 i;

    if (value->len == 0u) {
        return optional ? CG_OK : empty_error;
    }
    if (value->len > CG_MAX_DNS_VALUE_LEN) {
        return too_long_error;
    }
    for (i = 0u; i < value->len; ++i) {
        if (!cg_is_dns_value_char(value->ptr[i])) {
            return invalid_error;
        }
    }
    return CG_OK;
}

static cg_status cg_append_bytes(char *out, cg_u32 out_cap, cg_u32 *offset, const cg_u8 *value, cg_u32 value_len) {
    cg_u32 i;

    if (*offset > out_cap || value_len > (out_cap - *offset)) {
        return CG_ERR_ATTR_BUFFER_TOO_SMALL;
    }
    for (i = 0u; i < value_len; ++i) {
        out[*offset + i] = (char)value[i];
    }
    *offset += value_len;
    return CG_OK;
}

static cg_status cg_append_literal(char *out, cg_u32 out_cap, cg_u32 *offset, const char *literal, cg_u32 literal_len) {
    return cg_append_bytes(out, out_cap, offset, (const cg_u8 *)literal, literal_len);
}

cg_status cg_validate_input(const cg_input *input) {
    cg_status status;

    if (input == (const cg_input *)0) {
        return CG_ERR_NULL;
    }
    status = cg_validate_der_sequence(&input->csr);
    if (status != CG_OK) {
        return status;
    }
    status = cg_validate_ca_config(&input->ca_config);
    if (status != CG_OK) {
        return status;
    }
    status = cg_validate_template(&input->template_name);
    if (status != CG_OK) {
        return status;
    }
    status = cg_validate_dns_value(&input->san_dns, 1, CG_ERR_SAN_INVALID, CG_ERR_SAN_TOO_LONG, CG_ERR_SAN_INVALID);
    if (status != CG_OK) {
        return status;
    }
    status = cg_validate_dns_value(&input->cdc, 0, CG_ERR_CDC_EMPTY, CG_ERR_CDC_TOO_LONG, CG_ERR_CDC_INVALID);
    if (status != CG_OK) {
        return status;
    }
    return cg_validate_dns_value(&input->rmd, 0, CG_ERR_RMD_EMPTY, CG_ERR_RMD_TOO_LONG, CG_ERR_RMD_INVALID);
}

cg_status cg_parse_packed_args(const cg_u8 *buf, cg_u32 len, cg_input *out) {
    cg_slice fields[CG_PACKED_FIELD_COUNT];
    const cg_u8 *payload;
    cg_u32 payload_len;
    cg_u32 offset;
    cg_u32 i;

    if (buf == (const cg_u8 *)0 || out == (cg_input *)0) {
        return CG_ERR_NULL;
    }
    if (len < 4u) {
        return CG_ERR_PACK_HEADER;
    }
    payload_len = cg_read_u32_le(buf);
    if (payload_len > (len - 4u)) {
        return CG_ERR_PACK_TRUNCATED;
    }
    if (payload_len < (len - 4u)) {
        return CG_ERR_PACK_TRAILING;
    }
    payload = buf + 4u;
    offset = 0u;
    for (i = 0u; i < CG_PACKED_FIELD_COUNT; ++i) {
        cg_u32 field_len;
        if ((payload_len - offset) < 4u) {
            return CG_ERR_PACK_TRUNCATED;
        }
        field_len = cg_read_u32_le(payload + offset);
        offset += 4u;
        if (field_len > (payload_len - offset)) {
            return CG_ERR_PACK_TRUNCATED;
        }
        fields[i].ptr = payload + offset;
        fields[i].len = field_len;
        offset += field_len;
    }
    if (offset != payload_len) {
        return CG_ERR_PACK_TRAILING;
    }
    out->csr = fields[0];
    out->ca_config = fields[1];
    out->template_name = fields[2];
    out->san_dns = fields[3];
    out->cdc = fields[4];
    out->rmd = fields[5];
    return cg_validate_input(out);
}

cg_status cg_build_attributes(const cg_input *input, char *out, cg_u32 out_cap, cg_u32 *out_len) {
    cg_status status;
    cg_u32 offset = 0u;

    if (input == (const cg_input *)0 || out == (char *)0 || out_len == (cg_u32 *)0) {
        return CG_ERR_NULL;
    }
    status = cg_validate_input(input);
    if (status != CG_OK) {
        return status;
    }
    status = cg_append_literal(out, out_cap, &offset, "CertificateTemplate:", 20u);
    if (status != CG_OK) {
        return status;
    }
    status = cg_append_bytes(out, out_cap, &offset, input->template_name.ptr, input->template_name.len);
    if (status != CG_OK) {
        return status;
    }
    if (input->san_dns.len != 0u) {
        status = cg_append_literal(out, out_cap, &offset, "\nSAN:dns=", 9u);
        if (status != CG_OK) {
            return status;
        }
        status = cg_append_bytes(out, out_cap, &offset, input->san_dns.ptr, input->san_dns.len);
        if (status != CG_OK) {
            return status;
        }
    }
    status = cg_append_literal(out, out_cap, &offset, "\ncdc:", 5u);
    if (status != CG_OK) {
        return status;
    }
    status = cg_append_bytes(out, out_cap, &offset, input->cdc.ptr, input->cdc.len);
    if (status != CG_OK) {
        return status;
    }
    status = cg_append_literal(out, out_cap, &offset, "\nrmd:", 5u);
    if (status != CG_OK) {
        return status;
    }
    status = cg_append_bytes(out, out_cap, &offset, input->rmd.ptr, input->rmd.len);
    if (status != CG_OK) {
        return status;
    }
    if (offset >= out_cap) {
        return CG_ERR_ATTR_BUFFER_TOO_SMALL;
    }
    out[offset] = '\0';
    *out_len = offset;
    return CG_OK;
}

cg_u32 cg_base64_encoded_size(cg_u32 input_len) {
    if (input_len > 0x3ffffffdu) {
        return 0u;
    }
    return ((input_len + 2u) / 3u) * 4u;
}

cg_status cg_base64_encode(const cg_u8 *input, cg_u32 input_len, char *out, cg_u32 out_cap, cg_u32 *out_len) {
    static char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    cg_u32 required;
    cg_u32 i = 0u;
    cg_u32 o = 0u;

    if (input == (const cg_u8 *)0 || out == (char *)0 || out_len == (cg_u32 *)0) {
        return CG_ERR_NULL;
    }
    required = cg_base64_encoded_size(input_len);
    if (required == 0u && input_len != 0u) {
        return CG_ERR_BASE64_INPUT_TOO_LONG;
    }
    if (out_cap <= required) {
        return CG_ERR_BASE64_BUFFER_TOO_SMALL;
    }
    while ((input_len - i) >= 3u) {
        cg_u32 v = ((cg_u32)input[i] << 16) | ((cg_u32)input[i + 1u] << 8) | (cg_u32)input[i + 2u];
        out[o++] = alphabet[(v >> 18) & 0x3fu];
        out[o++] = alphabet[(v >> 12) & 0x3fu];
        out[o++] = alphabet[(v >> 6) & 0x3fu];
        out[o++] = alphabet[v & 0x3fu];
        i += 3u;
    }
    if ((input_len - i) == 1u) {
        cg_u32 v = (cg_u32)input[i] << 16;
        out[o++] = alphabet[(v >> 18) & 0x3fu];
        out[o++] = alphabet[(v >> 12) & 0x3fu];
        out[o++] = '=';
        out[o++] = '=';
    } else if ((input_len - i) == 2u) {
        cg_u32 v = ((cg_u32)input[i] << 16) | ((cg_u32)input[i + 1u] << 8);
        out[o++] = alphabet[(v >> 18) & 0x3fu];
        out[o++] = alphabet[(v >> 12) & 0x3fu];
        out[o++] = alphabet[(v >> 6) & 0x3fu];
        out[o++] = '=';
    }
    out[o] = '\0';
    *out_len = o;
    return CG_OK;
}

const char *cg_status_string(cg_status status) {
    switch (status) {
        case CG_OK: return "ok";
        case CG_ERR_NULL: return "null input";
        case CG_ERR_PACK_HEADER: return "packed argument outer header is missing";
        case CG_ERR_PACK_TRUNCATED: return "packed arguments are truncated";
        case CG_ERR_PACK_TRAILING: return "packed arguments contain trailing data";
        case CG_ERR_CSR_EMPTY: return "CSR is empty";
        case CG_ERR_CSR_TOO_LONG: return "CSR exceeds the maximum length";
        case CG_ERR_CSR_DER: return "CSR is not a bounded DER sequence";
        case CG_ERR_CA_CONFIG_EMPTY: return "CA configuration is empty";
        case CG_ERR_CA_CONFIG_TOO_LONG: return "CA configuration exceeds the maximum length";
        case CG_ERR_CA_CONFIG_INVALID: return "CA configuration must be ASCII host\\\\CAName";
        case CG_ERR_TEMPLATE_EMPTY: return "CertificateTemplate is empty";
        case CG_ERR_TEMPLATE_TOO_LONG: return "CertificateTemplate exceeds the maximum length";
        case CG_ERR_TEMPLATE_INVALID: return "CertificateTemplate contains invalid characters";
        case CG_ERR_SAN_TOO_LONG: return "SAN DNS value exceeds the maximum length";
        case CG_ERR_SAN_INVALID: return "SAN DNS value contains invalid characters";
        case CG_ERR_CDC_EMPTY: return "cdc is empty";
        case CG_ERR_CDC_TOO_LONG: return "cdc exceeds the maximum length";
        case CG_ERR_CDC_INVALID: return "cdc contains invalid characters";
        case CG_ERR_RMD_EMPTY: return "rmd is empty";
        case CG_ERR_RMD_TOO_LONG: return "rmd exceeds the maximum length";
        case CG_ERR_RMD_INVALID: return "rmd contains invalid characters";
        case CG_ERR_ATTR_BUFFER_TOO_SMALL: return "attribute buffer is too small";
        case CG_ERR_BASE64_BUFFER_TOO_SMALL: return "base64 output buffer is too small";
        case CG_ERR_BASE64_INPUT_TOO_LONG: return "base64 input exceeds the supported length";
        default: return "unknown validation error";
    }
}

void cg_secure_zero(void *buf, cg_u32 len) {
    volatile cg_u8 *cursor = (volatile cg_u8 *)buf;
    cg_u32 i;

    if (buf == (void *)0) {
        return;
    }
    for (i = 0u; i < len; ++i) {
        cursor[i] = 0u;
    }
}
