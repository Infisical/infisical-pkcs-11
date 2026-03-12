package main

/*
#include "pkcs11_types.h"

// Forward declarations from function_list.c
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;
extern CK_RV C_GetFunctionList_impl(CK_FUNCTION_LIST_PTR *ppFunctionList);
*/
import "C"

//export C_GetFunctionList
func C_GetFunctionList(ppFunctionList *C.CK_FUNCTION_LIST_PTR) C.CK_RV {
	return C.C_GetFunctionList_impl(ppFunctionList)
}
