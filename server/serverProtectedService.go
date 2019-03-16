package server

import (
	"encoding/hex"
	"github.com/colligence-io/signServer/rr"
	"github.com/colligence-io/signServer/trustSigner"
	"log"
	"net/http"
	"time"
)

// ProtectedService
type ProtectedService struct {
	instance    *Instance
	authService *AuthService
	handlerType interface{}
}

// NewProtectedService
func NewProtectedService(instance *Instance, authService *AuthService) *ProtectedService {
	return &ProtectedService{instance: instance, authService: authService}
}

// handlerClosure
// closure to simplify http.HandlerFunc
func (svcp *ProtectedService) handlerClosure(rw http.ResponseWriter, req *http.Request, handler func(appName string, req *http.Request) rr.ResponseEntity) {
	appName, ok := req.Context().Value(svcp.authService.ctxAppNameKey).(string)
	if !ok || appName == "" {
		rr.WriteResponseEntity(rw, rr.UnauthorizedResponse)
		return
	}

	appInfo, found := svcp.authService.appInfos[appName]
	if !found {
		rr.WriteResponseEntity(rw, rr.UnauthorizedResponse)
		return
	}
	if !appInfo.checkStringCIDR(req.RemoteAddr) {
		rr.WriteResponseEntity(rw, rr.UnauthorizedResponse)
		return
	}

	rr.WriteResponseEntity(rw, handler(appName, req))
}

// KnockHandler
// knock knock
func (svcp *ProtectedService) KnockHandler(rw http.ResponseWriter, req *http.Request) {
	svcp.handlerClosure(rw, req, svcp.knock)
}
func (svcp *ProtectedService) knock(appName string, req *http.Request) rr.ResponseEntity {
	return rr.OkResponse(time.Now().UTC().Unix())
}

// Sign
// sign requested message
func (svcp *ProtectedService) SignHandler(rw http.ResponseWriter, req *http.Request) {
	svcp.handlerClosure(rw, req, svcp.sign)
}
func (svcp *ProtectedService) sign(appName string, req *http.Request) rr.ResponseEntity {
	var request struct {
		KeyID   string                     `json:"keyID"`
		Type    trustSigner.BlockChainType `json:"type"`
		Address string                     `json:"address"`
		Data    string                     `json:"data"`
	}

	var response struct {
		Signature string `json:"signature"`
	}

	// Parse request
	if err := rr.ReadRequestBody(req, &request); err != nil {
		return rr.ErrorResponse(err)
	}

	log.Println("sign request from", appName, ":", request.Data)

	// get data to sign
	dataToSign, err := hex.DecodeString(request.Data)

	if err != nil {
		return rr.ErrorResponse(err)
	}

	// get whitebox from
	wb := svcp.instance.ks.GetWhiteBoxData(request.KeyID, request.Type)

	if wb == nil {
		return rr.KoResponse(http.StatusNotFound, "")
	}

	// sign message with trustSigner
	signature := trustSigner.GetWBSignatureData(wb, request.Type, dataToSign)

	// OK, send signature
	response.Signature = hex.EncodeToString(signature)

	return rr.OkResponse(response)
}

// Reload
// reload keyStore
//func (svcp *ProtectedService) ReloadHandler(rw http.ResponseWriter, req *http.Request) { svcp.handlerClosure(rw, req, svcp.reload) }
//func (svcp *ProtectedService) reload(appName string, req *http.Request) rr.ResponseEntity {
//	initKeyStore()
//	return rr.OkResponse("OK")
//}
