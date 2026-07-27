#ifndef CERTIGHOST_WIN_H
#define CERTIGHOST_WIN_H

#ifndef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT __declspec(dllimport)
#endif

#ifndef WINAPI
#define WINAPI __stdcall
#endif

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned short WCHAR;
typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef unsigned int ULONG;
typedef signed int LONG;
typedef signed int HRESULT;
typedef unsigned long long SIZE_T;
typedef int BOOL;
typedef void *LPVOID;
typedef void *HANDLE;
typedef WCHAR *BSTR;
typedef DWORD LCID;
typedef LONG DISPID;

typedef struct _GUID {
    DWORD Data1;
    WORD Data2;
    WORD Data3;
    BYTE Data4[8];
} GUID;

typedef const GUID *REFIID;
typedef const GUID *REFCLSID;

typedef struct ITypeInfo ITypeInfo;
typedef struct tagDISPPARAMS DISPPARAMS;
typedef struct tagVARIANT VARIANT;
typedef struct tagEXCEPINFO EXCEPINFO;
typedef struct ICertRequest ICertRequest;

typedef struct ICertRequestVtbl {
    HRESULT (WINAPI *QueryInterface)(ICertRequest *self, REFIID riid, void **object);
    ULONG (WINAPI *AddRef)(ICertRequest *self);
    ULONG (WINAPI *Release)(ICertRequest *self);
    HRESULT (WINAPI *GetTypeInfoCount)(ICertRequest *self, UINT *count);
    HRESULT (WINAPI *GetTypeInfo)(ICertRequest *self, UINT index, LCID lcid, ITypeInfo **type_info);
    HRESULT (WINAPI *GetIDsOfNames)(ICertRequest *self, REFIID riid, WCHAR **names, UINT count, LCID lcid, DISPID *dispids);
    HRESULT (WINAPI *Invoke)(ICertRequest *self, DISPID dispid, REFIID riid, LCID lcid, WORD flags, DISPPARAMS *params, VARIANT *result, EXCEPINFO *exception, UINT *arg_error);
    HRESULT (WINAPI *Submit)(ICertRequest *self, LONG flags, const BSTR request, const BSTR attributes, const BSTR config, LONG *disposition);
    HRESULT (WINAPI *RetrievePending)(ICertRequest *self, LONG request_id, const BSTR config, LONG *disposition);
    HRESULT (WINAPI *GetLastStatus)(ICertRequest *self, LONG *status);
    HRESULT (WINAPI *GetRequestId)(ICertRequest *self, LONG *request_id);
    HRESULT (WINAPI *GetDispositionMessage)(ICertRequest *self, BSTR *message);
    HRESULT (WINAPI *GetCACertificate)(ICertRequest *self, LONG exchange_certificate, const BSTR config, LONG flags, BSTR *certificate);
    HRESULT (WINAPI *GetCertificate)(ICertRequest *self, LONG flags, BSTR *certificate);
} ICertRequestVtbl;

struct ICertRequest {
    const ICertRequestVtbl *lpVtbl;
};

#define CG_NULL ((void *)0)
#define CG_S_OK ((HRESULT)0)
#define CG_S_FALSE ((HRESULT)1)
#define CG_RPC_E_CHANGED_MODE ((HRESULT)0x80010106u)
#define CG_COINIT_MULTITHREADED 0x0u
#define CG_CLSCTX_INPROC_SERVER 0x1u
#define CG_CR_IN_BINARY 0x2
#define CG_CR_IN_PKCS10 0x100
#define CG_CR_IN_RPC 0x20000
#define CG_CR_OUT_BINARY 0x2
#define CG_CR_DISP_ISSUED 0x3

#define CG_FAILED(hr) ((HRESULT)(hr) < 0)
#define CG_SUCCEEDED(hr) ((HRESULT)(hr) >= 0)

DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID reserved, DWORD coinit);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID clsid, LPVOID outer, DWORD context, REFIID iid, LPVOID *object);
DECLSPEC_IMPORT void WINAPI OLE32$CoUninitialize(void);

DECLSPEC_IMPORT BSTR WINAPI OLEAUT32$SysAllocStringLen(const WCHAR *source, UINT len);
DECLSPEC_IMPORT BSTR WINAPI OLEAUT32$SysAllocStringByteLen(const char *source, UINT len);
DECLSPEC_IMPORT void WINAPI OLEAUT32$SysFreeString(BSTR value);
DECLSPEC_IMPORT UINT WINAPI OLEAUT32$SysStringLen(BSTR value);
DECLSPEC_IMPORT UINT WINAPI OLEAUT32$SysStringByteLen(BSTR value);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE heap, DWORD flags, SIZE_T bytes);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE heap, DWORD flags, LPVOID memory);

#endif
