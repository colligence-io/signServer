package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"github.com/colligence-io/signServer/rr"
	"github.com/colligence-io/signServer/util"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/jwtauth"
	stellarkp "github.com/stellar/go/keypair"
	"github.com/yl2chen/cidranger"
	"io"
	"net"
	"net/http"
	"time"
)

// AuthService
type AuthService struct {
	instance *Instance

	// stores appInfos for apps
	appInfos map[string]*appClientInfo

	// stores issued tokenIDs for appName
	issuedTokens map[string]string

	// appName key
	ctxAppNameKey *struct{ name string }

	// jwt TokenAuth
	jwtSecretKey []byte

	// jwt TokenVerifier
	jwtVerifier func(handler http.Handler) http.Handler
}

// NewAuthService
func NewAuthService(instance *Instance) *AuthService {
	svc := &AuthService{}

	svc.instance = instance

	svc.ctxAppNameKey = &struct{ name string }{"AppName"}

	svc.jwtSecretKey = util.Crypto.Sha256Hash(svc.instance.config.JwtSecret)

	tokenAuth := jwtauth.New("HS256", svc.jwtSecretKey, nil)
	svc.jwtVerifier = jwtauth.Verifier(tokenAuth)

	svc.appInfos = make(map[string]*appClientInfo)
	svc.issuedTokens = make(map[string]string)

	return svc
}

// JWT Verifier
func (svc *AuthService) JwtVerifier(next http.Handler) http.Handler {
	return svc.jwtVerifier(next)
}

// JWT Authenticator
func (svc *AuthService) JwtAuthenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		token, _, err := jwtauth.FromContext(ctx)

		if err != nil || token == nil || !token.Valid {
			rr.WriteResponseEntity(w, rr.UnauthorizedResponse)
			return
		}

		// check authentication
		// MAN! this is messy!
		var authed = false
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if appName, ok := claims["sub"].(string); ok {
				if tokenID, ok := claims["jti"].(string); ok {
					if issuedToken, found := svc.issuedTokens[appName]; found && issuedToken == tokenID {
						authed = true
						ctx = context.WithValue(ctx, svc.ctxAppNameKey, appName)
					}
				}
			}
		}

		if !authed {
			rr.WriteResponseEntity(w, rr.UnauthorizedResponse)
			return
		}

		// Token is authenticated, pass it through
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// handlerClosure
// closure to simplify http.HandlerFunc
func (svc *AuthService) handlerClosure(rw http.ResponseWriter, req *http.Request, handler func(req *http.Request) rr.ResponseEntity) {
	rr.WriteResponseEntity(rw, handler(req))
}

// IntroduceHandler
// send question to client
func (svc *AuthService) IntroduceHandler(rw http.ResponseWriter, r *http.Request) {
	svc.handlerClosure(rw, r, svc.introduce)
}
func (svc *AuthService) introduce(req *http.Request) rr.ResponseEntity {
	var request struct {
		AppName string `json:"myNameIs"`
	}

	var response struct {
		Question string `json:"question"`
		Expires  string `json:"expires"`
	}

	// Parse request
	if err := rr.ReadRequestBody(req, &request); err != nil {
		return rr.ErrorResponse(err)
	}

	// validate request
	if request.AppName == "" {
		return rr.UnauthorizedResponse
	}

	appInfo, found := svc.appInfos[request.AppName]
	if !found {
		// Get appAuth secret from vault
		appAuthSecret, e := svc.instance.vc.Logical().Read(svc.instance.config.VaultAuthPath + "/" + request.AppName)
		if appAuthSecret == nil || e != nil {
			return rr.UnauthorizedResponse
		}

		if appAuthSecret.Data == nil {
			logger.Println("Broken AppAuth : Data is null - ", request.AppName)
			return rr.UnauthorizedResponse
		}

		// get bind_cidr
		cidr, ok := appAuthSecret.Data["bind_cidr"].(string)
		if !ok {
			logger.Println("Broken AppAuth : CIDR not found - ", request.AppName)
			return rr.UnauthorizedResponse
		}

		ranger := cidranger.NewPCTrieRanger()
		_, network1, e := net.ParseCIDR(cidr)

		e = ranger.Insert(cidranger.NewBasicRangerEntry(*network1))
		if e != nil {
			logger.Println("Broken AppAuth : CIDR parse error - ", request.AppName)
			return rr.UnauthorizedResponse
		}

		// get privateKey for app
		// NOTE : publicKey is assumed to be pair with private key
		// maybe assertion needed for make sure
		privateKey, ok := appAuthSecret.Data["privateKey"].(string)
		if !ok {
			logger.Println("Broken AppAuth : privateKey not found - ", request.AppName)
			return rr.UnauthorizedResponse
		}

		kp, e := stellarkp.Parse(privateKey)
		if e != nil {
			logger.Println("Broken AppAuth : privateKey parse error - ", request.AppName)
			return rr.UnauthorizedResponse
		}

		appInfo = &appClientInfo{
			keypair:     kp,
			cidrChecker: ranger,
		}

		svc.appInfos[request.AppName] = appInfo
	}

	// get remote ip
	ip := getIPfromAddress(req.RemoteAddr)
	if ip == nil {
		return rr.UnauthorizedResponse
	}

	if !appInfo.checkCIDR(ip) {
		return rr.UnauthorizedResponse
	}

	appInfo.lastRequestIP = ip

	// OK, seems proper access
	logger.Println("introduce from ", req.RemoteAddr, " by ", request.AppName)

	// generate random question
	appInfo.lastQuestion = make([]byte, 32)
	_, e := io.ReadFull(rand.Reader, appInfo.lastQuestion)

	if e != nil {
		return rr.ErrorResponse(e)
	}

	appInfo.lastQuestionExpires = time.Now().UTC().Add(time.Second * time.Duration(svc.instance.config.QuestionExpires))

	// OK, send question
	logger.Println("sending question to ", request.AppName)

	response.Question = base64.StdEncoding.EncodeToString(appInfo.lastQuestion)
	response.Expires = appInfo.lastQuestionExpires.Format(time.RFC3339)

	return rr.OkResponse(response)
}

// Answer
// check answer and send new jwt token to client
func (svc *AuthService) AnswerHandler(rw http.ResponseWriter, r *http.Request) {
	svc.handlerClosure(rw, r, svc.answer)
}
func (svc *AuthService) answer(req *http.Request) rr.ResponseEntity {
	var request struct {
		AppName   string `json:"myNameIs"`
		Signature string `json:"myAnswerIs"`
	}

	var response struct {
		JwtToken string `json:"welcomePresent"`
	}

	// Parse request
	if err := rr.ReadRequestBody(req, &request); err != nil {
		return rr.ErrorResponse(err)
	}

	// validate request
	if request.AppName == "" || request.Signature == "" {
		return rr.UnauthorizedResponse
	}

	// search appInfo
	appInfo, found := svc.appInfos[request.AppName]
	if !found {
		return rr.UnauthorizedResponse
	}

	// check request ip is same with intruduce
	ip := getIPfromAddress(req.RemoteAddr)
	if ip == nil {
		return rr.UnauthorizedResponse
	}

	// FIXME : this may interfere proper handshake when introducer & answerer are different (even if both is proper)
	// this can be changed for CIDR check
	if !appInfo.lastRequestIP.Equal(ip) {
		return rr.UnauthorizedResponse
	}

	logger.Println("answer from ", req.RemoteAddr, " by ", request.AppName)

	// check expiration
	if appInfo.isQuestionExpired() {
		return rr.KoResponse(http.StatusGone, "I forgot question. duh.")
	}

	// verify signature
	if !appInfo.verifySignature(request.Signature) {
		return rr.KoResponse(http.StatusNotAcceptable, "I don't like your answer.")
	}

	// generate tokenID from question
	tokenID := hex.EncodeToString(appInfo.lastQuestion)

	// build JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.StandardClaims{
		Id:        tokenID,
		Subject:   request.AppName,
		IssuedAt:  time.Now().UTC().Unix(),
		ExpiresAt: time.Now().UTC().Add(time.Second * time.Duration(svc.instance.config.JwtExpires)).Unix(),
	})

	// sign JWT into JWS
	tokenString, e := token.SignedString(svc.jwtSecretKey)
	if e != nil {
		return rr.ErrorResponse(e)
	}

	// store issued token for authenticator
	svc.issuedTokens[request.AppName] = tokenID

	// OK, send token
	logger.Println("sending welcome present to ", request.AppName)

	response.JwtToken = tokenString

	return rr.OkResponse(response)
}
