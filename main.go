package main

/*
#include "pkcs11_types.h"

// Bridge functions for Win64 struct packing compatibility (pkcs11_bridge.c).
// On Win64, CK_INFO, CK_MECHANISM, and CK_ATTRIBUTE have different packed vs
// unpacked layouts. These C functions use the correct packed layout.
extern void bridge_fill_info(void *p,
    CK_BYTE vMajor, CK_BYTE vMinor,
    const char *mfr, CK_FLAGS flags, const char *desc,
    CK_BYTE lvMajor, CK_BYTE lvMinor);
extern CK_MECHANISM_TYPE bridge_get_mech_type(void *p);
extern CK_ATTRIBUTE_TYPE bridge_attr_type(void *base, int idx);
extern void *bridge_attr_pvalue(void *base, int idx);
extern CK_ULONG bridge_attr_vallen(void *base, int idx);
extern void bridge_attr_set_vallen(void *base, int idx, CK_ULONG len);
extern void bridge_attr_copy_to_pvalue(void *base, int idx, void *src, CK_ULONG len);
*/
import "C"

import (
	"errors"
	"os/signal"
	"unsafe"

	"github.com/miekg/pkcs11"
)

// maxTemplateAttrs is the upper bound on template attributes to prevent
// unsafe.Slice from reading out-of-bounds memory on untrusted input.
const maxTemplateAttrs = 256

func init() {
	// Reset Go signal handlers to avoid conflicting with host process.
	signal.Reset()
}

func main() {}

func checkInitialized() C.CK_RV {
	if !backend.initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	return C.CKR_OK
}

//export C_Initialize
func C_Initialize(pInitArgs C.CK_VOID_PTR) C.CK_RV {
	if err := backend.Initialize(); err != nil {
		if errors.Is(err, ErrAlreadyInitialized) {
			return C.CKR_CRYPTOKI_ALREADY_INITIALIZED
		}
		return C.CKR_GENERAL_ERROR
	}
	return C.CKR_OK
}

//export C_Finalize
func C_Finalize(pReserved C.CK_VOID_PTR) C.CK_RV {
	if rv := checkInitialized(); rv != C.CKR_OK {
		return rv
	}
	if err := backend.Finalize(); err != nil {
		return C.CKR_GENERAL_ERROR
	}
	return C.CKR_OK
}

//export C_GetInfo
func C_GetInfo(pInfo *C.CK_INFO) C.CK_RV {
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	mfr := C.CString("Infisical")
	defer C.free(unsafe.Pointer(mfr))
	desc := C.CString("Infisical PKCS#11 Module")
	defer C.free(unsafe.Pointer(desc))
	C.bridge_fill_info(unsafe.Pointer(pInfo),
		2, 40,
		mfr, 0, desc,
		1, 0)
	return C.CKR_OK
}

//export C_GetSlotList
func C_GetSlotList(tokenPresent C.CK_BBOOL, pSlotList *C.CK_SLOT_ID, pulCount *C.CK_ULONG) C.CK_RV {
	if rv := checkInitialized(); rv != C.CKR_OK {
		return rv
	}
	if pulCount == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	slots, err := backend.GetSlotList(tokenPresent != 0)
	if err != nil {
		return mapErrorToRV(err)
	}

	if pSlotList == nil {
		*pulCount = C.CK_ULONG(len(slots))
		return C.CKR_OK
	}

	if uint(*pulCount) < uint(len(slots)) {
		*pulCount = C.CK_ULONG(len(slots))
		return C.CKR_BUFFER_TOO_SMALL
	}

	slotArray := unsafe.Slice(pSlotList, len(slots))
	for i, s := range slots {
		slotArray[i] = C.CK_SLOT_ID(s)
	}
	*pulCount = C.CK_ULONG(len(slots))
	return C.CKR_OK
}

//export C_GetSlotInfo
func C_GetSlotInfo(slotID C.CK_SLOT_ID, pInfo *C.CK_SLOT_INFO) C.CK_RV {
	if rv := checkInitialized(); rv != C.CKR_OK {
		return rv
	}
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	info, err := backend.GetSlotInfo(uint(slotID))
	if err != nil {
		return mapErrorToRV(err)
	}

	C.memset(unsafe.Pointer(pInfo), 0, C.size_t(unsafe.Sizeof(*pInfo)))
	cSlotDesc := C.CString(info.SlotDescription)
	defer C.free(unsafe.Pointer(cSlotDesc))
	cMfr := C.CString(info.ManufacturerID)
	defer C.free(unsafe.Pointer(cMfr))
	C.copyPaddedString(&pInfo.slotDescription[0], cSlotDesc, 64)
	C.copyPaddedString(&pInfo.manufacturerID[0], cMfr, 32)
	pInfo.flags = C.CK_FLAGS(info.Flags)
	pInfo.hardwareVersion.major = C.CK_BYTE(info.HardwareVersion.Major)
	pInfo.hardwareVersion.minor = C.CK_BYTE(info.HardwareVersion.Minor)
	pInfo.firmwareVersion.major = C.CK_BYTE(info.FirmwareVersion.Major)
	pInfo.firmwareVersion.minor = C.CK_BYTE(info.FirmwareVersion.Minor)
	return C.CKR_OK
}

//export C_GetTokenInfo
func C_GetTokenInfo(slotID C.CK_SLOT_ID, pInfo *C.CK_TOKEN_INFO) C.CK_RV {
	if rv := checkInitialized(); rv != C.CKR_OK {
		return rv
	}
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	info, err := backend.GetTokenInfo(uint(slotID))
	if err != nil {
		return mapErrorToRV(err)
	}

	// Zero-initialize to avoid garbage in fields we don't explicitly set.
	C.memset(unsafe.Pointer(pInfo), 0, C.size_t(unsafe.Sizeof(*pInfo)))

	cLabel := C.CString(info.Label)
	defer C.free(unsafe.Pointer(cLabel))
	cMfr2 := C.CString(info.ManufacturerID)
	defer C.free(unsafe.Pointer(cMfr2))
	cModel := C.CString(info.Model)
	defer C.free(unsafe.Pointer(cModel))
	cSerial := C.CString(info.SerialNumber)
	defer C.free(unsafe.Pointer(cSerial))
	C.copyPaddedString(&pInfo.label[0], cLabel, 32)
	C.copyPaddedString(&pInfo.manufacturerID[0], cMfr2, 32)
	C.copyPaddedString(&pInfo.model[0], cModel, 16)
	C.copyBytes(&pInfo.serialNumber[0], cSerial, 16)
	pInfo.flags = C.CK_FLAGS(info.Flags)
	pInfo.ulMaxSessionCount = C.CK_ULONG(info.MaxSessionCount)
	pInfo.ulSessionCount = C.CK_ULONG(info.SessionCount)
	pInfo.ulMaxRwSessionCount = C.CK_ULONG(info.MaxSessionCount)
	pInfo.ulRwSessionCount = 0
	pInfo.ulMaxPinLen = C.CK_ULONG(info.MaxPinLen)
	pInfo.ulMinPinLen = C.CK_ULONG(info.MinPinLen)
	// CK_UNAVAILABLE_INFORMATION = (CK_ULONG)-1 = max unsigned long
	pInfo.ulTotalPublicMemory = ^C.CK_ULONG(0)
	pInfo.ulFreePublicMemory = ^C.CK_ULONG(0)
	pInfo.ulTotalPrivateMemory = ^C.CK_ULONG(0)
	pInfo.ulFreePrivateMemory = ^C.CK_ULONG(0)
	pInfo.hardwareVersion.major = C.CK_BYTE(info.HardwareVersion.Major)
	pInfo.hardwareVersion.minor = C.CK_BYTE(info.HardwareVersion.Minor)
	pInfo.firmwareVersion.major = C.CK_BYTE(info.FirmwareVersion.Major)
	pInfo.firmwareVersion.minor = C.CK_BYTE(info.FirmwareVersion.Minor)
	return C.CKR_OK
}

//export C_OpenSession
func C_OpenSession(slotID C.CK_SLOT_ID, flags C.CK_FLAGS, pApplication C.CK_VOID_PTR, notify C.CK_NOTIFY, phSession *C.CK_SESSION_HANDLE) C.CK_RV {
	if rv := checkInitialized(); rv != C.CKR_OK {
		return rv
	}
	if phSession == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	handle, err := backend.OpenSession(uint(slotID), uint(flags))
	if err != nil {
		return mapErrorToRV(err)
	}

	*phSession = C.CK_SESSION_HANDLE(handle)
	return C.CKR_OK
}

//export C_CloseSession
func C_CloseSession(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	if rv := checkInitialized(); rv != C.CKR_OK {
		return rv
	}
	if err := backend.CloseSession(pkcs11.SessionHandle(hSession)); err != nil {
		return mapErrorToRV(err)
	}
	return C.CKR_OK
}

//export C_CloseAllSessions
func C_CloseAllSessions(slotID C.CK_SLOT_ID) C.CK_RV {
	if rv := checkInitialized(); rv != C.CKR_OK {
		return rv
	}
	backend.sessions.closeAllForSlot(uint(slotID))
	return C.CKR_OK
}

//export C_GetSessionInfo
func C_GetSessionInfo(hSession C.CK_SESSION_HANDLE, pInfo *C.CK_SESSION_INFO) C.CK_RV {
	if rv := checkInitialized(); rv != C.CKR_OK {
		return rv
	}
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	info, err := backend.GetSessionInfo(pkcs11.SessionHandle(hSession))
	if err != nil {
		return mapErrorToRV(err)
	}

	pInfo.slotID = C.CK_SLOT_ID(info.SlotID)
	pInfo.state = C.CK_ULONG(info.State)
	pInfo.flags = C.CK_FLAGS(info.Flags)
	pInfo.ulDeviceError = 0
	return C.CKR_OK
}

//export C_Login
func C_Login(hSession C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin *C.CK_BYTE, ulPinLen C.CK_ULONG) C.CK_RV {
	if rv := checkInitialized(); rv != C.CKR_OK {
		return rv
	}
	var pin string
	if pPin != nil && ulPinLen > 0 {
		pin = C.GoStringN((*C.char)(unsafe.Pointer(pPin)), C.int(ulPinLen))
	}
	if err := backend.Login(pkcs11.SessionHandle(hSession), uint(userType), pin); err != nil {
		return mapErrorToRV(err)
	}
	return C.CKR_OK
}

//export C_Logout
func C_Logout(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	if rv := checkInitialized(); rv != C.CKR_OK {
		return rv
	}
	if err := backend.Logout(pkcs11.SessionHandle(hSession)); err != nil {
		return mapErrorToRV(err)
	}
	return C.CKR_OK
}

//export C_GetMechanismList
func C_GetMechanismList(slotID C.CK_SLOT_ID, pMechanismList *C.CK_MECHANISM_TYPE, pulCount *C.CK_ULONG) C.CK_RV {
	if rv := checkInitialized(); rv != C.CKR_OK {
		return rv
	}
	if pulCount == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mechs, err := backend.GetMechanismList(uint(slotID))
	if err != nil {
		return mapErrorToRV(err)
	}

	if pMechanismList == nil {
		*pulCount = C.CK_ULONG(len(mechs))
		return C.CKR_OK
	}

	if uint(*pulCount) < uint(len(mechs)) {
		*pulCount = C.CK_ULONG(len(mechs))
		return C.CKR_BUFFER_TOO_SMALL
	}

	mechArray := unsafe.Slice(pMechanismList, len(mechs))
	for i, m := range mechs {
		mechArray[i] = C.CK_MECHANISM_TYPE(m.Mechanism)
	}
	*pulCount = C.CK_ULONG(len(mechs))
	return C.CKR_OK
}

//export C_GetMechanismInfo
func C_GetMechanismInfo(slotID C.CK_SLOT_ID, mechType C.CK_MECHANISM_TYPE, pInfo *C.CK_MECHANISM_INFO) C.CK_RV {
	if rv := checkInitialized(); rv != C.CKR_OK {
		return rv
	}
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mech := uint(mechType)
	switch mech {
	case pkcs11.CKM_ECDSA, pkcs11.CKM_ECDSA_SHA256, pkcs11.CKM_ECDSA_SHA384, pkcs11.CKM_ECDSA_SHA512:
		pInfo.ulMinKeySize = 256
		pInfo.ulMaxKeySize = 521
	default:
		// RSA mechanisms
		pInfo.ulMinKeySize = 2048
		pInfo.ulMaxKeySize = 4096
	}
	pInfo.flags = C.CKF_SIGN
	return C.CKR_OK
}

//export C_FindObjectsInit
func C_FindObjectsInit(hSession C.CK_SESSION_HANDLE, pTemplate *C.CK_ATTRIBUTE, ulCount C.CK_ULONG) C.CK_RV {
	if rv := checkInitialized(); rv != C.CKR_OK {
		return rv
	}
	if ulCount > maxTemplateAttrs {
		return C.CKR_ARGUMENTS_BAD
	}

	var attrs []*pkcs11.Attribute
	if ulCount > 0 && pTemplate != nil {
		base := unsafe.Pointer(pTemplate)
		for i := 0; i < int(ulCount); i++ {
			attrType := C.bridge_attr_type(base, C.int(i))
			pValue := C.bridge_attr_pvalue(base, C.int(i))
			valLen := C.bridge_attr_vallen(base, C.int(i))
			var val []byte
			if pValue != nil && valLen > 0 {
				val = C.GoBytes(pValue, C.int(valLen))
			}
			attrs = append(attrs, &pkcs11.Attribute{
				Type:  uint(attrType),
				Value: val,
			})
		}
	}

	if err := backend.FindObjectsInit(pkcs11.SessionHandle(hSession), attrs); err != nil {
		return mapErrorToRV(err)
	}
	return C.CKR_OK
}

//export C_FindObjects
func C_FindObjects(hSession C.CK_SESSION_HANDLE, phObject *C.CK_OBJECT_HANDLE, ulMaxObjectCount C.CK_ULONG, pulObjectCount *C.CK_ULONG) C.CK_RV {
	if rv := checkInitialized(); rv != C.CKR_OK {
		return rv
	}
	if phObject == nil || pulObjectCount == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	objects, err := backend.FindObjects(pkcs11.SessionHandle(hSession), int(ulMaxObjectCount))
	if err != nil {
		return mapErrorToRV(err)
	}

	objArray := unsafe.Slice(phObject, int(ulMaxObjectCount))
	for i, obj := range objects {
		objArray[i] = C.CK_OBJECT_HANDLE(obj)
	}
	*pulObjectCount = C.CK_ULONG(len(objects))
	return C.CKR_OK
}

//export C_FindObjectsFinal
func C_FindObjectsFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	if rv := checkInitialized(); rv != C.CKR_OK {
		return rv
	}
	if err := backend.FindObjectsFinal(pkcs11.SessionHandle(hSession)); err != nil {
		return mapErrorToRV(err)
	}
	return C.CKR_OK
}

//export C_GetAttributeValue
func C_GetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate *C.CK_ATTRIBUTE, ulCount C.CK_ULONG) C.CK_RV {
	if rv := checkInitialized(); rv != C.CKR_OK {
		return rv
	}
	if pTemplate == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	if ulCount > maxTemplateAttrs {
		return C.CKR_ARGUMENTS_BAD
	}

	// Use bridge functions for CK_ATTRIBUTE — has packing differences on Win64.
	base := unsafe.Pointer(pTemplate)
	count := int(ulCount)

	template := make([]*pkcs11.Attribute, count)
	for i := 0; i < count; i++ {
		template[i] = &pkcs11.Attribute{Type: uint(C.bridge_attr_type(base, C.int(i)))}
	}

	results, err := backend.GetAttributeValue(
		pkcs11.SessionHandle(hSession),
		pkcs11.ObjectHandle(hObject),
		template,
	)
	if err != nil {
		return mapErrorToRV(err)
	}

	for i, result := range results {
		if i >= count {
			break
		}
		valLen := len(result.Value)
		pValue := C.bridge_attr_pvalue(base, C.int(i))
		if pValue == nil {
			// Size query phase
			C.bridge_attr_set_vallen(base, C.int(i), C.ulong(valLen))
		} else if valLen == 0 {
			C.bridge_attr_set_vallen(base, C.int(i), 0)
		} else if uint(C.bridge_attr_vallen(base, C.int(i))) >= uint(valLen) {
			C.bridge_attr_copy_to_pvalue(base, C.int(i), unsafe.Pointer(&result.Value[0]), C.ulong(valLen))
		} else {
			C.bridge_attr_set_vallen(base, C.int(i), C.ulong(valLen))
			return C.CKR_BUFFER_TOO_SMALL
		}
	}

	return C.CKR_OK
}

//export C_SignInit
func C_SignInit(hSession C.CK_SESSION_HANDLE, pMechanism *C.CK_MECHANISM, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	if rv := checkInitialized(); rv != C.CKR_OK {
		return rv
	}
	if pMechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	mechType := C.bridge_get_mech_type(unsafe.Pointer(pMechanism))
	mech := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(uint(mechType), nil),
	}

	if err := backend.SignInit(pkcs11.SessionHandle(hSession), mech, pkcs11.ObjectHandle(hKey)); err != nil {
		if errors.Is(err, ErrNotLoggedIn) {
			return C.CKR_USER_NOT_LOGGED_IN
		}
		return mapErrorToRV(err)
	}
	return C.CKR_OK
}

//export C_Sign
func C_Sign(hSession C.CK_SESSION_HANDLE, pData *C.CK_BYTE, ulDataLen C.CK_ULONG, pSignature *C.CK_BYTE, pulSignatureLen *C.CK_ULONG) C.CK_RV {
	if rv := checkInitialized(); rv != C.CKR_OK {
		return rv
	}
	if pData == nil || pulSignatureLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	sh := pkcs11.SessionHandle(hSession)

	// Per PKCS#11 spec: if pSignature is NULL, return required buffer size without signing
	if pSignature == nil {
		size := backend.EstimateSignatureSize(sh)
		*pulSignatureLen = C.CK_ULONG(size)
		return C.CKR_OK
	}

	data := C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))

	sig, err := backend.Sign(sh, data)
	if err != nil {
		return mapErrorToRV(err)
	}

	if uint(*pulSignatureLen) < uint(len(sig)) {
		// Per PKCS#11 spec: CKR_BUFFER_TOO_SMALL must NOT terminate the operation.
		// Cache the signature so the caller can retry with a larger buffer.
		backend.cacheSignResult(sh, sig)
		*pulSignatureLen = C.CK_ULONG(len(sig))
		return C.CKR_BUFFER_TOO_SMALL
	}

	C.memcpy(unsafe.Pointer(pSignature), unsafe.Pointer(&sig[0]), C.size_t(len(sig)))
	*pulSignatureLen = C.CK_ULONG(len(sig))
	backend.clearSignStateByHandle(sh)
	return C.CKR_OK
}

//export C_SignUpdate
func C_SignUpdate(hSession C.CK_SESSION_HANDLE, pPart *C.CK_BYTE, ulPartLen C.CK_ULONG) C.CK_RV {
	if rv := checkInitialized(); rv != C.CKR_OK {
		return rv
	}
	if pPart == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	data := C.GoBytes(unsafe.Pointer(pPart), C.int(ulPartLen))
	if err := backend.SignUpdate(pkcs11.SessionHandle(hSession), data); err != nil {
		return mapErrorToRV(err)
	}
	return C.CKR_OK
}

//export C_SignFinal
func C_SignFinal(hSession C.CK_SESSION_HANDLE, pSignature *C.CK_BYTE, pulSignatureLen *C.CK_ULONG) C.CK_RV {
	if rv := checkInitialized(); rv != C.CKR_OK {
		return rv
	}
	if pulSignatureLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	sh := pkcs11.SessionHandle(hSession)

	// Per PKCS#11 spec: if pSignature is NULL, return required buffer size without finalizing
	if pSignature == nil {
		size := backend.EstimateSignatureSize(sh)
		*pulSignatureLen = C.CK_ULONG(size)
		return C.CKR_OK
	}

	sig, err := backend.SignFinal(sh)
	if err != nil {
		return mapErrorToRV(err)
	}

	if uint(*pulSignatureLen) < uint(len(sig)) {
		backend.cacheSignResult(sh, sig)
		*pulSignatureLen = C.CK_ULONG(len(sig))
		return C.CKR_BUFFER_TOO_SMALL
	}

	C.memcpy(unsafe.Pointer(pSignature), unsafe.Pointer(&sig[0]), C.size_t(len(sig)))
	*pulSignatureLen = C.CK_ULONG(len(sig))
	backend.clearSignStateByHandle(sh)
	return C.CKR_OK
}

//export C_InitToken
func C_InitToken(slotID C.CK_SLOT_ID, pPin *C.CK_BYTE, ulPinLen C.CK_ULONG, pLabel *C.CK_BYTE) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_InitPIN
func C_InitPIN(hSession C.CK_SESSION_HANDLE, pPin *C.CK_BYTE, ulPinLen C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SetPIN
func C_SetPIN(hSession C.CK_SESSION_HANDLE, pOldPin *C.CK_BYTE, ulOldLen C.CK_ULONG, pNewPin *C.CK_BYTE, ulNewLen C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_CreateObject
func C_CreateObject(hSession C.CK_SESSION_HANDLE, pTemplate *C.CK_ATTRIBUTE, ulCount C.CK_ULONG, phObject *C.CK_OBJECT_HANDLE) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DestroyObject
func C_DestroyObject(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_CopyObject
func C_CopyObject(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate *C.CK_ATTRIBUTE, ulCount C.CK_ULONG, phNewObject *C.CK_OBJECT_HANDLE) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SetAttributeValue
func C_SetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate *C.CK_ATTRIBUTE, ulCount C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_EncryptInit
func C_EncryptInit(hSession C.CK_SESSION_HANDLE, pMechanism *C.CK_MECHANISM, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Encrypt
func C_Encrypt(hSession C.CK_SESSION_HANDLE, pData *C.CK_BYTE, ulDataLen C.CK_ULONG, pEncryptedData *C.CK_BYTE, pulEncryptedDataLen *C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DecryptInit
func C_DecryptInit(hSession C.CK_SESSION_HANDLE, pMechanism *C.CK_MECHANISM, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Decrypt
func C_Decrypt(hSession C.CK_SESSION_HANDLE, pEncryptedData *C.CK_BYTE, ulEncryptedDataLen C.CK_ULONG, pData *C.CK_BYTE, pulDataLen *C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DigestInit
func C_DigestInit(hSession C.CK_SESSION_HANDLE, pMechanism *C.CK_MECHANISM) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Digest
func C_Digest(hSession C.CK_SESSION_HANDLE, pData *C.CK_BYTE, ulDataLen C.CK_ULONG, pDigest *C.CK_BYTE, pulDigestLen *C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyInit
func C_VerifyInit(hSession C.CK_SESSION_HANDLE, pMechanism *C.CK_MECHANISM, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Verify
func C_Verify(hSession C.CK_SESSION_HANDLE, pData *C.CK_BYTE, ulDataLen C.CK_ULONG, pSignature *C.CK_BYTE, ulSignatureLen C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GenerateKeyPair
func C_GenerateKeyPair(hSession C.CK_SESSION_HANDLE, pMechanism *C.CK_MECHANISM, pPublicKeyTemplate *C.CK_ATTRIBUTE, ulPublicKeyAttributeCount C.CK_ULONG, pPrivateKeyTemplate *C.CK_ATTRIBUTE, ulPrivateKeyAttributeCount C.CK_ULONG, phPublicKey *C.CK_OBJECT_HANDLE, phPrivateKey *C.CK_OBJECT_HANDLE) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GenerateKey
func C_GenerateKey(hSession C.CK_SESSION_HANDLE, pMechanism *C.CK_MECHANISM, pTemplate *C.CK_ATTRIBUTE, ulCount C.CK_ULONG, phKey *C.CK_OBJECT_HANDLE) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_WrapKey
func C_WrapKey(hSession C.CK_SESSION_HANDLE, pMechanism *C.CK_MECHANISM, hWrappingKey C.CK_OBJECT_HANDLE, hKey C.CK_OBJECT_HANDLE, pWrappedKey *C.CK_BYTE, pulWrappedKeyLen *C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_UnwrapKey
func C_UnwrapKey(hSession C.CK_SESSION_HANDLE, pMechanism *C.CK_MECHANISM, hUnwrappingKey C.CK_OBJECT_HANDLE, pWrappedKey *C.CK_BYTE, ulWrappedKeyLen C.CK_ULONG, pTemplate *C.CK_ATTRIBUTE, ulAttributeCount C.CK_ULONG, phKey *C.CK_OBJECT_HANDLE) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SeedRandom
func C_SeedRandom(hSession C.CK_SESSION_HANDLE, pSeed *C.CK_BYTE, ulSeedLen C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GenerateRandom
func C_GenerateRandom(hSession C.CK_SESSION_HANDLE, pRandomData *C.CK_BYTE, ulRandomLen C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetObjectSize
func C_GetObjectSize(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pulSize *C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetOperationState
func C_GetOperationState(hSession C.CK_SESSION_HANDLE, pOperationState *C.CK_BYTE, pulOperationStateLen *C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SetOperationState
func C_SetOperationState(hSession C.CK_SESSION_HANDLE, pOperationState *C.CK_BYTE, ulOperationStateLen C.CK_ULONG, hEncryptionKey C.CK_OBJECT_HANDLE, hAuthenticationKey C.CK_OBJECT_HANDLE) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_EncryptUpdate
func C_EncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart *C.CK_BYTE, ulPartLen C.CK_ULONG, pEncryptedPart *C.CK_BYTE, pulEncryptedPartLen *C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_EncryptFinal
func C_EncryptFinal(hSession C.CK_SESSION_HANDLE, pLastEncryptedPart *C.CK_BYTE, pulLastEncryptedPartLen *C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DecryptUpdate
func C_DecryptUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart *C.CK_BYTE, ulEncryptedPartLen C.CK_ULONG, pPart *C.CK_BYTE, pulPartLen *C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DecryptFinal
func C_DecryptFinal(hSession C.CK_SESSION_HANDLE, pLastPart *C.CK_BYTE, pulLastPartLen *C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DigestUpdate
func C_DigestUpdate(hSession C.CK_SESSION_HANDLE, pPart *C.CK_BYTE, ulPartLen C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DigestKey
func C_DigestKey(hSession C.CK_SESSION_HANDLE, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DigestFinal
func C_DigestFinal(hSession C.CK_SESSION_HANDLE, pDigest *C.CK_BYTE, pulDigestLen *C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SignRecoverInit
func C_SignRecoverInit(hSession C.CK_SESSION_HANDLE, pMechanism *C.CK_MECHANISM, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SignRecover
func C_SignRecover(hSession C.CK_SESSION_HANDLE, pData *C.CK_BYTE, ulDataLen C.CK_ULONG, pSignature *C.CK_BYTE, pulSignatureLen *C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyUpdate
func C_VerifyUpdate(hSession C.CK_SESSION_HANDLE, pPart *C.CK_BYTE, ulPartLen C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyFinal
func C_VerifyFinal(hSession C.CK_SESSION_HANDLE, pSignature *C.CK_BYTE, ulSignatureLen C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyRecoverInit
func C_VerifyRecoverInit(hSession C.CK_SESSION_HANDLE, pMechanism *C.CK_MECHANISM, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyRecover
func C_VerifyRecover(hSession C.CK_SESSION_HANDLE, pSignature *C.CK_BYTE, ulSignatureLen C.CK_ULONG, pData *C.CK_BYTE, pulDataLen *C.CK_ULONG) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DeriveKey
func C_DeriveKey(hSession C.CK_SESSION_HANDLE, pMechanism *C.CK_MECHANISM, hBaseKey C.CK_OBJECT_HANDLE, pTemplate *C.CK_ATTRIBUTE, ulAttributeCount C.CK_ULONG, phKey *C.CK_OBJECT_HANDLE) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_WaitForSlotEvent
func C_WaitForSlotEvent(flags C.CK_FLAGS, pSlot *C.CK_SLOT_ID, pReserved C.CK_VOID_PTR) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

func mapErrorToRV(err error) C.CK_RV {
	// Check sentinel errors first
	if errors.Is(err, ErrNotLoggedIn) {
		return C.CKR_USER_NOT_LOGGED_IN
	}
	if errors.Is(err, ErrSessionHandleInvalid) {
		return C.CKR_SESSION_HANDLE_INVALID
	}
	if errors.Is(err, ErrSlotIDInvalid) {
		return C.CKR_SLOT_ID_INVALID
	}
	if errors.Is(err, ErrSignNotActive) || errors.Is(err, ErrFindNotActive) {
		return C.CKR_OPERATION_NOT_INITIALIZED
	}
	if errors.Is(err, ErrSignAlreadyActive) || errors.Is(err, ErrFindAlreadyActive) {
		return C.CKR_OPERATION_ACTIVE
	}
	// Check API errors
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return C.CK_RV(mapHTTPError(apiErr.StatusCode))
	}
	return C.CKR_GENERAL_ERROR
}
