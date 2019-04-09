package server

import (
	"encoding/hex"
	"github.com/colligence-io/signServer/rr"
	"github.com/colligence-io/signServer/server/auth"
	"github.com/colligence-io/signServer/trustSigner"
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
func (svcp *ProtectedService) handlerClosure(rw http.ResponseWriter, req *http.Request, handler func(session *auth.Session, req *http.Request) rr.ResponseEntity) {
	session, ok := req.Context().Value(svcp.authService.ctxSessionKey).(*auth.Session)
	if !ok || session == nil {
		rr.WriteResponseEntity(rw, rr.UnauthorizedResponse)
		return
	}
	rr.WriteResponseEntity(rw, handler(session, req))
}

// KnockHandler
// knock knock
func (svcp *ProtectedService) KnockHandler(rw http.ResponseWriter, req *http.Request) {
	svcp.handlerClosure(rw, req, svcp.knock)
}
func (svcp *ProtectedService) knock(session *auth.Session, req *http.Request) rr.ResponseEntity {
	return rr.OkResponse(time.Now().UTC().Unix())
}

// Sign
// sign requested message
func (svcp *ProtectedService) SignHandler(rw http.ResponseWriter, req *http.Request) {
	svcp.handlerClosure(rw, req, svcp.sign)
}
func (svcp *ProtectedService) sign(session *auth.Session, req *http.Request) rr.ResponseEntity {
	var request struct {
		Type             trustSigner.BlockChainType `json:"type"`
		Address          string                     `json:"address"`
		RequestSignature string                     `json:"answer"`
		Data             string                     `json:"data"`
	}

	var response struct {
		Signature string `json:"signature"`
	}

	// Parse request
	if err := rr.ReadRequestBody(req, &request); err != nil {
		return rr.ErrorResponse(err)
	}

	logger.Info("sign request from ", session.AppName, " : ", request.Data)

	requestKey := string(request.Type) + ":" + request.Address

	quiz, found := session.Quizzes[requestKey]
	if !found {
		return rr.KoResponse(http.StatusNotAcceptable, "")
	}

	if request.RequestSignature != quiz.Answer {
		return rr.KoResponse(http.StatusBadRequest, "")
	}

	// get data to sign
	dataToSign, err := hex.DecodeString(request.Data)

	if err != nil {
		return rr.ErrorResponse(err)
	}

	if len(dataToSign)%32 != 0 {
		return rr.KoResponse(http.StatusBadRequest, "data length must be 32*N")
	}

	wb := svcp.instance.ks.GetWhiteBoxData(quiz.KeyID, request.Type)

	if wb == nil {
		return rr.KoResponse(http.StatusNotFound, "")
	}

	// sign message with trustSigner
	signature, err := trustSigner.GetWBSignatureData(wb, request.Type, dataToSign)
	if err != nil {
		return rr.ErrorResponse(err)
	}

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
