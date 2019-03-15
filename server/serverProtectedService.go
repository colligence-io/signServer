package server

import (
	"encoding/hex"
	"github.com/colligence-io/signServer/rr"
	"github.com/colligence-io/signServer/trustSigner"
	"log"
	"net/http"
	"time"
)

type ProtectedService struct {
	instance    *Instance
	authService *AuthService
}

func NewProtectedService(instance *Instance, authService *AuthService) *ProtectedService {
	return &ProtectedService{instance: instance, authService: authService}
}

// http.HandlerFunc Closure
func (svcp *ProtectedService) closure(handler func(appName string, req *http.Request) rr.ResponseEntity) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
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
}

// Knock
// knock knock
func (svcp *ProtectedService) Knock() http.HandlerFunc { return svcp.closure(svcp.knockHandler) }
func (svcp *ProtectedService) knockHandler(appName string, req *http.Request) rr.ResponseEntity {
	return rr.OkResponse(time.Now().UTC().Unix())
}

// Sign
// sign requested message
func (svcp *ProtectedService) Sign() http.HandlerFunc { return svcp.closure(svcp.signHandler) }
func (svcp *ProtectedService) signHandler(appName string, req *http.Request) rr.ResponseEntity {
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

//// Reload
//// reload keyStore
//func (svcp *ProtectedService) Reload() http.HandlerFunc { return svcp.closure(svcp.reloadHandler) }
//func (svcp *ProtectedService) reloadHandler(appName string, req *http.Request) rr.ResponseEntity {
//	initKeyStore()
//	return rr.OkResponse("OK")
//}
