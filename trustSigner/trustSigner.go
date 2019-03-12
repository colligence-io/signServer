package trustSigner

/*
#cgo CFLAGS: -I${SRCDIR}/lib
#cgo LDFLAGS: -L${SRCDIR}/lib -Wl,-rpath=\$ORIGIN/trustSigner/lib -ltrustsigner
#include "libtrustsigner.h"
#include <stdlib.h>
*/
import "C"
import (
	"bytes"
	"unsafe"
)

const wbLength int = 1275881 + 80

type BlockChainType string

const (
	BTC BlockChainType = "BTC"
	ETH BlockChainType = "ETH"
	XLM BlockChainType = "XLM"
)

var BCTypes = map[string]BlockChainType{
	string(BTC): BTC,
	string(ETH): ETH,
	string(XLM): XLM,
}

type blockChainDefinition struct {
	PublicKeyLength int
	SignatureLength int
	HDDepth         int
}

var BCDefs = map[BlockChainType]blockChainDefinition{
	BTC: {
		PublicKeyLength: 111,
		SignatureLength: 65,
		HDDepth:         5,
	},
	ETH: {
		PublicKeyLength: 111,
		SignatureLength: 65,
		HDDepth:         5,
	},
	XLM: {
		PublicKeyLength: 56,
		SignatureLength: 64,
		HDDepth:         3,
	},
}

type WhiteBox struct {
	AppID   string
	Size    C.int
	Pointer *C.uchar
}

//unsigned char[] TrustSigner_getWBInitializeData(char *app_id);
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
	return &WhiteBox{appID, C.int(C.size_t(len(wbBytes))), (*C.uchar)(unsafe.Pointer(&buf.Bytes()[0]))}
}

//char *TrustSigner_getWBPublicKey(char *app_id, unsigned char *wb_data, int wb_data_len, char *coin_symbol, int hd_depth, int hd_change, int hd_index);
func GetWBPublicKey(wb *WhiteBox, bcType BlockChainType) string {
	cPtrCharAppID := C.CString(wb.AppID)
	defer C.free(unsafe.Pointer(cPtrCharAppID))

	cPtrCharSymbol := C.CString(string(bcType))
	defer C.free(unsafe.Pointer(cPtrCharSymbol))

	cCharPtrResult := C.TrustSigner_getWBPublicKey(cPtrCharAppID, wb.Pointer, wb.Size, cPtrCharSymbol, C.int(BCDefs[bcType].HDDepth), C.int(0), C.int(0))
	defer C.free(unsafe.Pointer(cCharPtrResult))

	publicKey := C.GoBytes(unsafe.Pointer(cCharPtrResult), C.int(BCDefs[bcType].PublicKeyLength))

	return string(publicKey)
}

//char *TrustSigner_getWBSignatureData(char *app_id, unsigned char *wb_data, int wb_data_len, char *coin_symbol, int hd_depth, int hd_change, int hd_index, char *hash_message);
func GetWBSignatureData(wb *WhiteBox, bcType BlockChainType, message []byte) []byte {
	cPtrUcharAppID := C.CString(wb.AppID)
	defer C.free(unsafe.Pointer(cPtrUcharAppID))

	cPtrCharSymbol := C.CString(string(bcType))
	defer C.free(unsafe.Pointer(cPtrCharSymbol))

	cCharPtrResult := C.TrustSigner_getWBSignatureData(cPtrUcharAppID, wb.Pointer, wb.Size, cPtrCharSymbol, C.int(BCDefs[bcType].HDDepth), C.int(0), C.int(0), (*C.char)(unsafe.Pointer(&message[0])))
	defer C.free(unsafe.Pointer(cCharPtrResult))

	signature := C.GoBytes(unsafe.Pointer(cCharPtrResult), C.int(BCDefs[bcType].SignatureLength))

	return signature
}
