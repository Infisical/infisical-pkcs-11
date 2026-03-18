#ifndef INFISICAL_PKCS11_TYPES_H
#define INFISICAL_PKCS11_TYPES_H

#include <stdlib.h>
#include <string.h>

/* PKCS#11 base types */
typedef unsigned long CK_ULONG;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_USER_TYPE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef CK_BYTE *CK_BYTE_PTR;
typedef CK_ULONG *CK_ULONG_PTR;
typedef unsigned char CK_BBOOL;
typedef unsigned char CK_UTF8CHAR;
typedef void *CK_VOID_PTR;
typedef void *CK_NOTIFY;

/* Return codes */
#define CKR_OK                          0x00000000
#define CKR_GENERAL_ERROR               0x00000005
#define CKR_ARGUMENTS_BAD               0x00000007
#define CKR_SLOT_ID_INVALID             0x00000003
#define CKR_SESSION_HANDLE_INVALID      0x000000B3
#define CKR_PIN_INCORRECT               0x000000A0
#define CKR_USER_NOT_LOGGED_IN          0x00000101
#define CKR_FUNCTION_NOT_SUPPORTED      0x00000054
#define CKR_BUFFER_TOO_SMALL            0x00000150
#define CKR_OPERATION_NOT_INITIALIZED   0x00000091
#define CKR_MECHANISM_INVALID           0x00000070
#define CKR_KEY_HANDLE_INVALID          0x00000060
#define CKR_DATA_INVALID                0x00000020
#define CKR_DEVICE_ERROR                0x00000030
#define CKR_CRYPTOKI_ALREADY_INITIALIZED 0x00000191
#define CKR_CRYPTOKI_NOT_INITIALIZED    0x00000190
#define CKR_OPERATION_ACTIVE            0x00000090

/* Structs — no packing here (CGo-safe).
 * On Win64, CK_INFO, CK_MECHANISM, and CK_ATTRIBUTE have different packed vs
 * unpacked layouts due to pointer alignment. Access to these 3 structs goes
 * through C bridge functions (pkcs11_bridge.c) that use the correct packed layout.
 * All other structs are naturally aligned and can be accessed directly. */

typedef struct CK_VERSION {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

typedef struct CK_INFO {
    CK_VERSION cryptokiVersion;
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_UTF8CHAR libraryDescription[32];
    CK_VERSION libraryVersion;
} CK_INFO;

typedef struct CK_SLOT_INFO {
    CK_UTF8CHAR slotDescription[64];
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
} CK_SLOT_INFO;

typedef struct CK_TOKEN_INFO {
    CK_UTF8CHAR label[32];
    CK_UTF8CHAR manufacturerID[32];
    CK_UTF8CHAR model[16];
    CK_BYTE serialNumber[16];
    CK_FLAGS flags;
    CK_ULONG ulMaxSessionCount;
    CK_ULONG ulSessionCount;
    CK_ULONG ulMaxRwSessionCount;
    CK_ULONG ulRwSessionCount;
    CK_ULONG ulMaxPinLen;
    CK_ULONG ulMinPinLen;
    CK_ULONG ulTotalPublicMemory;
    CK_ULONG ulFreePublicMemory;
    CK_ULONG ulTotalPrivateMemory;
    CK_ULONG ulFreePrivateMemory;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
    CK_UTF8CHAR utcTime[16];
} CK_TOKEN_INFO;

typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;

typedef struct CK_MECHANISM_INFO {
    CK_ULONG ulMinKeySize;
    CK_ULONG ulMaxKeySize;
    CK_FLAGS flags;
} CK_MECHANISM_INFO;

typedef struct CK_SESSION_INFO {
    CK_SLOT_ID slotID;
    CK_ULONG state;
    CK_FLAGS flags;
    CK_ULONG ulDeviceError;
} CK_SESSION_INFO;

typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;

/* Flags */
#define CKF_TOKEN_PRESENT     0x00000001
#define CKF_HW_SLOT           0x00000004
#define CKF_SERIAL_SESSION    0x00000004
#define CKF_RW_SESSION        0x00000002
#define CKF_LOGIN_REQUIRED    0x00000004
#define CKF_TOKEN_INITIALIZED 0x00000400
#define CKF_SIGN              0x00000800

/* Object classes */
#define CKO_CERTIFICATE  0x00000001
#define CKO_PUBLIC_KEY   0x00000002
#define CKO_PRIVATE_KEY  0x00000003

/* Special values */
#define CK_UNAVAILABLE_INFORMATION ((CK_ULONG)-1)
#define CK_EFFECTIVELY_INFINITE    0

/* Session states */
#define CKS_RO_PUBLIC_SESSION  0
#define CKS_RO_USER_FUNCTIONS  1

/* User types */
#define CKU_USER  1

/* Helper functions */
static inline void copyPaddedString(CK_UTF8CHAR *dest, const char *src, int len) {
    memset(dest, ' ', len);
    int slen = strlen(src);
    if (slen > len) slen = len;
    memcpy(dest, src, slen);
}

static inline void copyBytes(CK_BYTE *dest, const char *src, int len) {
    memset(dest, ' ', len);
    int slen = strlen(src);
    if (slen > len) slen = len;
    memcpy(dest, src, slen);
}

#endif /* INFISICAL_PKCS11_TYPES_H */
