package main

/*
#cgo LDFLAGS: -L ./target/release -l lib
#include <stdlib.h>

extern _Bool is_authorized(const char* principal, const char* action, const char* resource, const char* policy, const char* entities);
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func main() {
	cPrincipal := C.CString(`User::"alice"`)
	defer C.free(unsafe.Pointer(cPrincipal))

	cAction := C.CString(`Action::"view"`)
	defer C.free(unsafe.Pointer(cAction))

	cResource := C.CString(`File::"93"`)
	defer C.free(unsafe.Pointer(cResource))

	cPolicy := C.CString(`permit(principal == User::"alice", action == Action::"view", resource == File::"93");`)
	defer C.free(unsafe.Pointer(cPolicy))

	cEntities := C.CString(`[]`)
	defer C.free(unsafe.Pointer(cEntities))

	result := C.is_authorized(cPrincipal, cAction, cResource, cPolicy, cEntities)
	fmt.Println("Result:", result)
}
