package trustSigner

/*
#cgo LDFLAGS: -L${SRCDIR} -Wl,-rpath=\$ORIGIN/trustSigner -ltrustsigner

#include <stdlib.h>

unsigned char *TrustSigner_getWBInitializeData(char *app_id);
char *TrustSigner_getWBPublicKey(char *app_id, unsigned char *wb_data, char *coin_symbol, int hd_depth, int hd_change, int hd_index);
unsigned char *TrustSigner_getWBSignatureData(char *app_id, unsigned char *wb_data, char *coin_symbol, int hd_depth, int hd_change, int hd_index, unsigned char *hash_message, int hash_len);
char *TrustSigner_getWBRecoveryData(char *app_id, unsigned char *wb_data, char *user_key, char *server_key);
unsigned char *TrustSigner_setWBRecoveryData(char *app_id, char *user_key, char *recovery_data);
*/
import "C"
import (
	"bytes"
	"errors"
	"unsafe"
)

const recoveryKeyLength int = 128
const recoveryDataLength int = 1024

type WhiteBox struct {
	AppID   *C.char
	Pointer *C.uchar
}

func DeriveAddress(bcType BlockChainType, publicKey string, bcNetwork string) (string, error) {
	return bcConfig[bcType].Address(publicKey, chooseNetwork(bcNetwork))
}

//unsigned char *TrustSigner_getWBInitializeData(char *app_id);
func GetWBInitializeData(appId string) ([]byte, error) {
	cPtrCharAppID := C.CString(appId)
	defer C.free(unsafe.Pointer(cPtrCharAppID))

	cUcharPtrResult := C.TrustSigner_getWBInitializeData(cPtrCharAppID)
	defer C.free(unsafe.Pointer(cUcharPtrResult))

	return ptrToWhiteboxData(cUcharPtrResult)
}

func ptrToWhiteboxData(ptr *C.uchar) ([]byte, error) {
	if ptr == nil {
		return nil, errors.New("whitebox initialization failed")
	}

	wbLength := *(*int32)(unsafe.Pointer(ptr))
	cIntWBLength := C.int(wbLength)

	wbData := C.GoBytes(unsafe.Pointer(ptr), cIntWBLength)

	if wbData != nil {
		return wbData, nil
	} else {
		return nil, errors.New("whitebox initialization failed")
	}
}

func ConvertToWhiteBox(appID string, wbBytes []byte) *WhiteBox {
	var buf bytes.Buffer
	buf.Write(wbBytes)
	return &WhiteBox{C.CString(appID), (*C.uchar)(unsafe.Pointer(&buf.Bytes()[0]))}
}

//char *TrustSigner_getWBPublicKey(char *app_id, unsigned char *wb_data, char *coin_symbol, int hd_depth, int hd_change, int hd_index);
func GetWBPublicKey(wb *WhiteBox, bcType BlockChainType) (string, error) {
	cPtrCharSymbol := C.CString(string(bcType))
	defer C.free(unsafe.Pointer(cPtrCharSymbol))

	cCharPtrResult := C.TrustSigner_getWBPublicKey(wb.AppID, wb.Pointer, cPtrCharSymbol, C.int(bcConfig[bcType].HDDepth), C.int(0), C.int(0))
	defer C.free(unsafe.Pointer(cCharPtrResult))

	if cCharPtrResult != nil {
		publicKey := C.GoBytes(unsafe.Pointer(cCharPtrResult), C.int(bcConfig[bcType].PublicKeyLength))

		return string(publicKey), nil
	} else {
		return "", errors.New("public key generation failed")
	}
}

//unsigned char *TrustSigner_getWBSignatureData(char *app_id, unsigned char *wb_data, char *coin_symbol, int hd_depth, int hd_change, int hd_index, unsigned char *hash_message, int hash_len);
func GetWBSignatureData(wb *WhiteBox, bcType BlockChainType, message []byte) ([]byte, error) {
	cPtrCharSymbol := C.CString(string(bcType))
	defer C.free(unsafe.Pointer(cPtrCharSymbol))

	var buf bytes.Buffer
	buf.Write(message)

	cCharPtrResult := C.TrustSigner_getWBSignatureData(wb.AppID, wb.Pointer, cPtrCharSymbol, C.int(bcConfig[bcType].HDDepth), C.int(0), C.int(0), (*C.uchar)(unsafe.Pointer(&buf.Bytes()[0])), C.int(C.size_t(len(message))))
	defer C.free(unsafe.Pointer(cCharPtrResult))

	if cCharPtrResult != nil {
		return C.GoBytes(unsafe.Pointer(cCharPtrResult), C.int(bcConfig[bcType].SignatureLength)), nil
	} else {
		return nil, errors.New("signing error")
	}
}

// BACKUP MODE IS NOT USING THIS FUNCTION
//char *TrustSigner_getWBRecoveryData(char *app_id, unsigned char *wb_data, char *user_key, char *server_key);
func GetWBRecoveryData(wb *WhiteBox, recoveryKey []byte) ([]byte, error) {
	if len(recoveryKey) != recoveryKeyLength {
		return nil, errors.New("recovery key length must be 128")
	}

	cCharPtrResult := C.TrustSigner_getWBRecoveryData(wb.AppID, wb.Pointer, (*C.char)(unsafe.Pointer(&recoveryKey[0])), (*C.char)(unsafe.Pointer(&recoveryKey[0])))
	defer C.free(unsafe.Pointer(cCharPtrResult))

	if cCharPtrResult != nil {
		rBytes := C.GoBytes(unsafe.Pointer(cCharPtrResult), C.int(recoveryDataLength))
		nt := clen(rBytes)
		if nt == 0 {
			return nil, errors.New("recovery data generation returned null")
		} else {
			return rBytes[:nt], nil
		}
	} else {
		return nil, errors.New("recovery data generation failed")
	}
}

func clen(n []byte) int {
	for i := 0; i < len(n); i++ {
		if n[i] == 0 {
			return i
		}
	}
	return len(n)
}

// RESTORING MODE IS NOT USING THIS FUNCTION
//unsigned char *TrustSigner_setWBRecoveryData(char *app_id, char *user_key, char *recovery_data);
func SetWBRecoveryData(appId string, recoveryKey []byte, recoveryData []byte) ([]byte, error) {
	if len(recoveryKey) != recoveryKeyLength {
		return nil, errors.New("recovery key length must be 128")
	}

	cPtrCharAppID := C.CString(appId)
	defer C.free(unsafe.Pointer(cPtrCharAppID))

	cUcharPtrResult := C.TrustSigner_setWBRecoveryData(cPtrCharAppID, (*C.char)(unsafe.Pointer(&recoveryKey[0])), (*C.char)(unsafe.Pointer(&recoveryData[0])))
	defer C.free(unsafe.Pointer(cUcharPtrResult))

	return ptrToWhiteboxData(cUcharPtrResult)
}
