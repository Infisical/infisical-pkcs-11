/*
 * PKCS#11 struct bridge for Windows compatibility.
 *
 * On Win64, unsigned long is 32-bit while pointers are 64-bit. The OASIS PKCS#11
 * spec requires byte-packed structs on Windows. Standard PKCS#11 consumers expect
 * #pragma pack(1), so struct fields containing pointers after CK_ULONG fields have
 * different offsets than what CGo generates (CGo cannot handle packed structs).
 *
 * This file defines packed versions of the 3 affected structs (CK_INFO, CK_MECHANISM,
 * CK_ATTRIBUTE) and provides C bridge functions that Go calls instead of accessing
 * struct fields directly. On Unix, packing has no effect since CK_ULONG is already
 * pointer-sized.
 */

#include <string.h>

typedef unsigned long CK_ULONG;
typedef CK_ULONG CK_FLAGS;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef unsigned char CK_BYTE;
typedef unsigned char CK_UTF8CHAR;
typedef void *CK_VOID_PTR;

#if defined(_WIN32) || defined(_WIN64)
#pragma pack(push, 1)
#endif

typedef struct {
    CK_BYTE major;
    CK_BYTE minor;
} P11_VERSION;

typedef struct {
    P11_VERSION cryptokiVersion;
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_UTF8CHAR libraryDescription[32];
    P11_VERSION libraryVersion;
} P11_INFO;

typedef struct {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR pParameter;
    CK_ULONG ulParameterLen;
} P11_MECHANISM;

typedef struct {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
} P11_ATTRIBUTE;

#if defined(_WIN32) || defined(_WIN64)
#pragma pack(pop)
#endif

static void padded_copy(CK_UTF8CHAR *dest, const char *src, int len) {
    memset(dest, ' ', len);
    int slen = (int)strlen(src);
    if (slen > len) slen = len;
    memcpy(dest, src, slen);
}

/* CK_INFO bridge */
void bridge_fill_info(void *p,
    CK_BYTE vMajor, CK_BYTE vMinor,
    const char *mfr, CK_FLAGS flags, const char *desc,
    CK_BYTE lvMajor, CK_BYTE lvMinor) {
    P11_INFO *info = (P11_INFO*)p;
    info->cryptokiVersion.major = vMajor;
    info->cryptokiVersion.minor = vMinor;
    padded_copy(info->manufacturerID, mfr, 32);
    info->flags = flags;
    padded_copy(info->libraryDescription, desc, 32);
    info->libraryVersion.major = lvMajor;
    info->libraryVersion.minor = lvMinor;
}

/* CK_MECHANISM bridge */
CK_MECHANISM_TYPE bridge_get_mech_type(void *p) {
    return ((P11_MECHANISM*)p)->mechanism;
}

/* CK_ATTRIBUTE array bridge functions */
CK_ATTRIBUTE_TYPE bridge_attr_type(void *base, int idx) {
    return ((P11_ATTRIBUTE*)base)[idx].type;
}

void *bridge_attr_pvalue(void *base, int idx) {
    return ((P11_ATTRIBUTE*)base)[idx].pValue;
}

CK_ULONG bridge_attr_vallen(void *base, int idx) {
    return ((P11_ATTRIBUTE*)base)[idx].ulValueLen;
}

void bridge_attr_set_vallen(void *base, int idx, CK_ULONG len) {
    ((P11_ATTRIBUTE*)base)[idx].ulValueLen = len;
}

void bridge_attr_copy_to_pvalue(void *base, int idx, void *src, CK_ULONG len) {
    P11_ATTRIBUTE *attr = &((P11_ATTRIBUTE*)base)[idx];
    memcpy(attr->pValue, src, len);
    attr->ulValueLen = len;
}
