/*
 * PKCS#11 C_GetFunctionList implementation.
 * This file builds the CK_FUNCTION_LIST struct pointing to the Go-exported functions.
 */

#include "pkcs11_types.h"

/* Forward-declare Go-exported functions */
extern CK_RV C_Initialize(CK_VOID_PTR pInitArgs);
extern CK_RV C_Finalize(CK_VOID_PTR pReserved);
extern CK_RV C_GetInfo(CK_INFO *pInfo);
extern CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID *pSlotList, CK_ULONG *pulCount);
extern CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO *pInfo);
extern CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO *pInfo);
extern CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE *pMechanismList, CK_ULONG *pulCount);
extern CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO *pInfo);
extern CK_RV C_InitToken(CK_SLOT_ID slotID, CK_BYTE *pPin, CK_ULONG ulPinLen, CK_BYTE *pLabel);
extern CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_BYTE *pPin, CK_ULONG ulPinLen);
extern CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_BYTE *pOldPin, CK_ULONG ulOldLen, CK_BYTE *pNewPin, CK_ULONG ulNewLen);
extern CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify, CK_SESSION_HANDLE *phSession);
extern CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);
extern CK_RV C_CloseAllSessions(CK_SLOT_ID slotID);
extern CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO *pInfo);
extern CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE *pOperationState, CK_ULONG *pulOperationStateLen);
extern CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE *pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
extern CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_BYTE *pPin, CK_ULONG ulPinLen);
extern CK_RV C_Logout(CK_SESSION_HANDLE hSession);
extern CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE *phObject);
extern CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE *phNewObject);
extern CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
extern CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG *pulSize);
extern CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount);
extern CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount);
extern CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount);
extern CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE *phObject, CK_ULONG ulMaxObjectCount, CK_ULONG *pulObjectCount);
extern CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession);
extern CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
extern CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE *pData, CK_ULONG ulDataLen, CK_BYTE *pEncryptedData, CK_ULONG *pulEncryptedDataLen);
extern CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE *pPart, CK_ULONG ulPartLen, CK_BYTE *pEncryptedPart, CK_ULONG *pulEncryptedPartLen);
extern CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE *pLastEncryptedPart, CK_ULONG *pulLastEncryptedPartLen);
extern CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
extern CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE *pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE *pData, CK_ULONG *pulDataLen);
extern CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE *pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE *pPart, CK_ULONG *pulPartLen);
extern CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE *pLastPart, CK_ULONG *pulLastPartLen);
extern CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism);
extern CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE *pData, CK_ULONG ulDataLen, CK_BYTE *pDigest, CK_ULONG *pulDigestLen);
extern CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE *pPart, CK_ULONG ulPartLen);
extern CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
extern CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE *pDigest, CK_ULONG *pulDigestLen);
extern CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
extern CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE *pData, CK_ULONG ulDataLen, CK_BYTE *pSignature, CK_ULONG *pulSignatureLen);
extern CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE *pPart, CK_ULONG ulPartLen);
extern CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE *pSignature, CK_ULONG *pulSignatureLen);
extern CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
extern CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE *pData, CK_ULONG ulDataLen, CK_BYTE *pSignature, CK_ULONG *pulSignatureLen);
extern CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
extern CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE *pData, CK_ULONG ulDataLen, CK_BYTE *pSignature, CK_ULONG ulSignatureLen);
extern CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE *pPart, CK_ULONG ulPartLen);
extern CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE *pSignature, CK_ULONG ulSignatureLen);
extern CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey);
extern CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE *pSignature, CK_ULONG ulSignatureLen, CK_BYTE *pData, CK_ULONG *pulDataLen);
extern CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE *phKey);
extern CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_ATTRIBUTE *pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE *pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE *phPublicKey, CK_OBJECT_HANDLE *phPrivateKey);
extern CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE *pWrappedKey, CK_ULONG *pulWrappedKeyLen);
extern CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE *pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE *pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE *phKey);
extern CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE *pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE *phKey);
extern CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE *pSeed, CK_ULONG ulSeedLen);
extern CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE *pRandomData, CK_ULONG ulRandomLen);
extern CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID *pSlot, CK_VOID_PTR pReserved);

/* CK_FUNCTION_LIST per PKCS#11 v2.40 spec.
 * Must be byte-packed on Windows — CK_VERSION (2 bytes) is followed by
 * function pointers (8 bytes each), and without packing the compiler
 * inserts 6 bytes of padding after version. */
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR *CK_FUNCTION_LIST_PTR_PTR;

#if defined(_WIN32) || defined(_WIN64)
#pragma pack(push, 1)
#endif

struct CK_FUNCTION_LIST {
    CK_VERSION version;
    CK_RV (*C_Initialize)(CK_VOID_PTR);
    CK_RV (*C_Finalize)(CK_VOID_PTR);
    CK_RV (*C_GetInfo)(CK_INFO *);
    CK_RV (*C_GetFunctionList)(CK_FUNCTION_LIST_PTR *);
    CK_RV (*C_GetSlotList)(CK_BBOOL, CK_SLOT_ID *, CK_ULONG *);
    CK_RV (*C_GetSlotInfo)(CK_SLOT_ID, CK_SLOT_INFO *);
    CK_RV (*C_GetTokenInfo)(CK_SLOT_ID, CK_TOKEN_INFO *);
    CK_RV (*C_GetMechanismList)(CK_SLOT_ID, CK_MECHANISM_TYPE *, CK_ULONG *);
    CK_RV (*C_GetMechanismInfo)(CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO *);
    CK_RV (*C_InitToken)(CK_SLOT_ID, CK_BYTE *, CK_ULONG, CK_BYTE *);
    CK_RV (*C_InitPIN)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG);
    CK_RV (*C_SetPIN)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG);
    CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE *);
    CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
    CK_RV (*C_CloseAllSessions)(CK_SLOT_ID);
    CK_RV (*C_GetSessionInfo)(CK_SESSION_HANDLE, CK_SESSION_INFO *);
    CK_RV (*C_GetOperationState)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_SetOperationState)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE);
    CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_BYTE *, CK_ULONG);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE);
    CK_RV (*C_CreateObject)(CK_SESSION_HANDLE, CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *);
    CK_RV (*C_CopyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *);
    CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
    CK_RV (*C_GetObjectSize)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG *);
    CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE *, CK_ULONG);
    CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE *, CK_ULONG);
    CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE *, CK_ULONG);
    CK_RV (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE *, CK_ULONG, CK_ULONG *);
    CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
    CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE);
    CK_RV (*C_Encrypt)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_EncryptUpdate)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_EncryptFinal)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE);
    CK_RV (*C_Decrypt)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_DecryptUpdate)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_DecryptFinal)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_DigestInit)(CK_SESSION_HANDLE, CK_MECHANISM *);
    CK_RV (*C_Digest)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_DigestUpdate)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG);
    CK_RV (*C_DigestKey)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
    CK_RV (*C_DigestFinal)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE);
    CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG);
    CK_RV (*C_SignFinal)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_SignRecoverInit)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE);
    CK_RV (*C_SignRecover)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE);
    CK_RV (*C_Verify)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG);
    CK_RV (*C_VerifyUpdate)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG);
    CK_RV (*C_VerifyFinal)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG);
    CK_RV (*C_VerifyRecoverInit)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE);
    CK_RV (*C_VerifyRecover)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_DigestEncryptUpdate)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_DecryptDigestUpdate)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_SignEncryptUpdate)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_DecryptVerifyUpdate)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *);
    CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_ATTRIBUTE *, CK_ULONG, CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *, CK_OBJECT_HANDLE *);
    CK_RV (*C_WrapKey)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_UnwrapKey)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE, CK_BYTE *, CK_ULONG, CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *);
    CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE, CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *);
    CK_RV (*C_SeedRandom)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG);
    CK_RV (*C_GenerateRandom)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG);
    CK_RV (*C_GetFunctionStatus)(CK_SESSION_HANDLE);
    CK_RV (*C_CancelFunction)(CK_SESSION_HANDLE);
    CK_RV (*C_WaitForSlotEvent)(CK_FLAGS, CK_SLOT_ID *, CK_VOID_PTR);
};

#if defined(_WIN32) || defined(_WIN64)
#pragma pack(pop)
#endif

/* Stub functions for combined operations (not supported) */
static CK_RV stub_not_supported_2(CK_SESSION_HANDLE s, CK_BYTE *a, CK_ULONG b, CK_BYTE *c, CK_ULONG *d) {
    (void)s; (void)a; (void)b; (void)c; (void)d;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV stub_legacy(CK_SESSION_HANDLE s) {
    (void)s;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Forward declare C_GetFunctionList itself */
CK_RV C_GetFunctionList_impl(CK_FUNCTION_LIST_PTR *ppFunctionList);

static CK_FUNCTION_LIST function_list = {
    .version = { 2, 40 },
    .C_Initialize = C_Initialize,
    .C_Finalize = C_Finalize,
    .C_GetInfo = C_GetInfo,
    .C_GetFunctionList = C_GetFunctionList_impl,
    .C_GetSlotList = C_GetSlotList,
    .C_GetSlotInfo = C_GetSlotInfo,
    .C_GetTokenInfo = C_GetTokenInfo,
    .C_GetMechanismList = C_GetMechanismList,
    .C_GetMechanismInfo = C_GetMechanismInfo,
    .C_InitToken = C_InitToken,
    .C_InitPIN = C_InitPIN,
    .C_SetPIN = C_SetPIN,
    .C_OpenSession = C_OpenSession,
    .C_CloseSession = C_CloseSession,
    .C_CloseAllSessions = C_CloseAllSessions,
    .C_GetSessionInfo = C_GetSessionInfo,
    .C_GetOperationState = C_GetOperationState,
    .C_SetOperationState = C_SetOperationState,
    .C_Login = C_Login,
    .C_Logout = C_Logout,
    .C_CreateObject = C_CreateObject,
    .C_CopyObject = C_CopyObject,
    .C_DestroyObject = C_DestroyObject,
    .C_GetObjectSize = C_GetObjectSize,
    .C_GetAttributeValue = C_GetAttributeValue,
    .C_SetAttributeValue = C_SetAttributeValue,
    .C_FindObjectsInit = C_FindObjectsInit,
    .C_FindObjects = C_FindObjects,
    .C_FindObjectsFinal = C_FindObjectsFinal,
    .C_EncryptInit = C_EncryptInit,
    .C_Encrypt = C_Encrypt,
    .C_EncryptUpdate = C_EncryptUpdate,
    .C_EncryptFinal = C_EncryptFinal,
    .C_DecryptInit = C_DecryptInit,
    .C_Decrypt = C_Decrypt,
    .C_DecryptUpdate = C_DecryptUpdate,
    .C_DecryptFinal = C_DecryptFinal,
    .C_DigestInit = C_DigestInit,
    .C_Digest = C_Digest,
    .C_DigestUpdate = C_DigestUpdate,
    .C_DigestKey = C_DigestKey,
    .C_DigestFinal = C_DigestFinal,
    .C_SignInit = C_SignInit,
    .C_Sign = C_Sign,
    .C_SignUpdate = C_SignUpdate,
    .C_SignFinal = C_SignFinal,
    .C_SignRecoverInit = C_SignRecoverInit,
    .C_SignRecover = C_SignRecover,
    .C_VerifyInit = C_VerifyInit,
    .C_Verify = C_Verify,
    .C_VerifyUpdate = C_VerifyUpdate,
    .C_VerifyFinal = C_VerifyFinal,
    .C_VerifyRecoverInit = C_VerifyRecoverInit,
    .C_VerifyRecover = C_VerifyRecover,
    .C_DigestEncryptUpdate = stub_not_supported_2,
    .C_DecryptDigestUpdate = stub_not_supported_2,
    .C_SignEncryptUpdate = stub_not_supported_2,
    .C_DecryptVerifyUpdate = stub_not_supported_2,
    .C_GenerateKey = C_GenerateKey,
    .C_GenerateKeyPair = C_GenerateKeyPair,
    .C_WrapKey = C_WrapKey,
    .C_UnwrapKey = C_UnwrapKey,
    .C_DeriveKey = C_DeriveKey,
    .C_SeedRandom = C_SeedRandom,
    .C_GenerateRandom = C_GenerateRandom,
    .C_GetFunctionStatus = stub_legacy,
    .C_CancelFunction = stub_legacy,
    .C_WaitForSlotEvent = C_WaitForSlotEvent,
};

CK_RV C_GetFunctionList_impl(CK_FUNCTION_LIST_PTR *ppFunctionList) {
    if (ppFunctionList == NULL) return CKR_ARGUMENTS_BAD;
    *ppFunctionList = &function_list;
    return CKR_OK;
}
