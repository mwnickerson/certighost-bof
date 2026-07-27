#ifndef CERTIGHOST_CORE_H
#define CERTIGHOST_CORE_H

typedef unsigned char cg_u8;
typedef unsigned short cg_u16;
typedef unsigned int cg_u32;

#ifndef CG_CORE_API
#define CG_CORE_API
#endif

#define CG_PACKED_FIELD_COUNT 6u
#define CG_MAX_CSR_LEN 262144u
#define CG_MAX_CA_CONFIG_LEN 512u
#define CG_MAX_TEMPLATE_LEN 128u
#define CG_MAX_DNS_VALUE_LEN 255u
#define CG_MAX_ATTRIBUTES_LEN 1024u
#define CG_MAX_CERT_LEN 1048576u

typedef struct {
    const cg_u8 *ptr;
    cg_u32 len;
} cg_slice;

typedef struct {
    cg_slice csr;
    cg_slice ca_config;
    cg_slice template_name;
    cg_slice san_dns;
    cg_slice cdc;
    cg_slice rmd;
} cg_input;

typedef enum {
    CG_OK = 0,
    CG_ERR_NULL,
    CG_ERR_PACK_HEADER,
    CG_ERR_PACK_TRUNCATED,
    CG_ERR_PACK_TRAILING,
    CG_ERR_CSR_EMPTY,
    CG_ERR_CSR_TOO_LONG,
    CG_ERR_CSR_DER,
    CG_ERR_CA_CONFIG_EMPTY,
    CG_ERR_CA_CONFIG_TOO_LONG,
    CG_ERR_CA_CONFIG_INVALID,
    CG_ERR_TEMPLATE_EMPTY,
    CG_ERR_TEMPLATE_TOO_LONG,
    CG_ERR_TEMPLATE_INVALID,
    CG_ERR_SAN_TOO_LONG,
    CG_ERR_SAN_INVALID,
    CG_ERR_CDC_EMPTY,
    CG_ERR_CDC_TOO_LONG,
    CG_ERR_CDC_INVALID,
    CG_ERR_RMD_EMPTY,
    CG_ERR_RMD_TOO_LONG,
    CG_ERR_RMD_INVALID,
    CG_ERR_ATTR_BUFFER_TOO_SMALL,
    CG_ERR_BASE64_BUFFER_TOO_SMALL,
    CG_ERR_BASE64_INPUT_TOO_LONG
} cg_status;

CG_CORE_API cg_status cg_parse_packed_args(const cg_u8 *buf, cg_u32 len, cg_input *out);
CG_CORE_API cg_status cg_validate_input(const cg_input *input);
CG_CORE_API cg_status cg_build_attributes(const cg_input *input, char *out, cg_u32 out_cap, cg_u32 *out_len);
CG_CORE_API cg_status cg_base64_encode(const cg_u8 *input, cg_u32 input_len, char *out, cg_u32 out_cap, cg_u32 *out_len);
CG_CORE_API cg_u32 cg_base64_encoded_size(cg_u32 input_len);
CG_CORE_API const char *cg_status_string(cg_status status);
CG_CORE_API void cg_secure_zero(void *buf, cg_u32 len);

#endif
