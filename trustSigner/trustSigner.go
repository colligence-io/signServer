package trustSigner

/*
#cgo LDFLAGS: -L${SRCDIR} -Wl,-rpath=\$ORIGIN/trustSigner -ltrustsigner

#include <stdlib.h>

unsigned char *TrustSigner_getWBInitializeData(char *app_id);
char *TrustSigner_getWBPublicKey(char *app_id, unsigned char *wb_data, int wb_data_len, char *coin_symbol, int hd_depth, int hd_change, int hd_index);
unsigned char *TrustSigner_getWBSignatureData(char *app_id, unsigned char *wb_data, int wb_data_len, char *coin_symbol, int hd_depth, int hd_change, int hd_index, char *hash_message, int hash_len);
*/
import "C"
import (
	"bytes"
	"errors"
	"unsafe"
)

const wbLength int = 1275881 + 80

type WhiteBox struct {
	AppID   *C.char
	Size    C.int
	Pointer *C.uchar
}

func DeriveAddress(bcType BlockChainType, publicKey string) (string, error) {
	return bcConfig[bcType].Address(publicKey)
}

//unsigned char *TrustSigner_getWBInitializeData(char *app_id);
func GetWBInitializeData(appId string) []byte {
	cPtrCharAppID := C.CString(appId)
	defer C.free(unsafe.Pointer(cPtrCharAppID))

	cUcharPtrResult := C.TrustSigner_getWBInitializeData(cPtrCharAppID)
	defer C.free(unsafe.Pointer(cUcharPtrResult))

	//size := C.size_t(*c_result_p_uchar) * C.ulong(WB_LENGTH)
	//
	//fmt.Printf("%v", size)
	cIntWBLength := C.int(wbLength)

	wbData := C.GoBytes(unsafe.Pointer(cUcharPtrResult), cIntWBLength)
	return wbData
}

func ConvertToWhiteBox(appID string, wbBytes []byte) *WhiteBox {
	var buf bytes.Buffer
	buf.Write(wbBytes)
	return &WhiteBox{C.CString(appID), C.int(C.size_t(len(wbBytes))), (*C.uchar)(unsafe.Pointer(&buf.Bytes()[0]))}
}

//char *TrustSigner_getWBPublicKey(char *app_id, unsigned char *wb_data, int wb_data_len, char *coin_symbol, int hd_depth, int hd_change, int hd_index);
func GetWBPublicKey(wb *WhiteBox, bcType BlockChainType) string {
	cPtrCharSymbol := C.CString(string(bcType))
	defer C.free(unsafe.Pointer(cPtrCharSymbol))

	cCharPtrResult := C.TrustSigner_getWBPublicKey(wb.AppID, wb.Pointer, wb.Size, cPtrCharSymbol, C.int(bcConfig[bcType].HDDepth), C.int(0), C.int(0))
	defer C.free(unsafe.Pointer(cCharPtrResult))

	publicKey := C.GoBytes(unsafe.Pointer(cCharPtrResult), C.int(bcConfig[bcType].PublicKeyLength))

	return string(publicKey)
}

//unsigned char *TrustSigner_getWBSignatureData(char *app_id, unsigned char *wb_data, int wb_data_len, char *coin_symbol, int hd_depth, int hd_change, int hd_index, char *hash_message, int hash_len);
func GetWBSignatureData(wb *WhiteBox, bcType BlockChainType, message []byte) ([]byte, error) {
	cPtrCharSymbol := C.CString(string(bcType))
	defer C.free(unsafe.Pointer(cPtrCharSymbol))

	cCharPtrResult := C.TrustSigner_getWBSignatureData(wb.AppID, wb.Pointer, wb.Size, cPtrCharSymbol, C.int(bcConfig[bcType].HDDepth), C.int(0), C.int(0), (*C.char)(unsafe.Pointer(&message[0])), C.int(C.size_t(len(message))))
	defer C.free(unsafe.Pointer(cCharPtrResult))

	if cCharPtrResult != nil {
		return C.GoBytes(unsafe.Pointer(cCharPtrResult), C.int(bcConfig[bcType].SignatureLength)), nil
	} else {
		return nil, errors.New("signing error")
	}
}
