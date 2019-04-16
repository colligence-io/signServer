package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"github.com/colligence-io/signServer/server/auth"
	"github.com/colligence-io/signServer/server/rr"
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

	// key = appName
	authContainer *auth.Container

	// session ctx key
	ctxSessionKey *struct{ name string }

	// jwt TokenAuth
	jwtSecretKey []byte

	// jwt TokenVerifier
	jwtVerifier func(handler http.Handler) http.Handler
}

// NewAuthService
func NewAuthService(instance *Instance) *AuthService {
	svc := &AuthService{}

	svc.instance = instance

	svc.ctxSessionKey = &struct{ name string }{"SESSION"}

	svc.jwtSecretKey = util.Crypto.Sha256Hash(svc.instance.config.Auth.JwtSecret)

	tokenAuth := jwtauth.New("HS256", svc.jwtSecretKey, nil)
	svc.jwtVerifier = jwtauth.Verifier(tokenAuth)

	svc.authContainer = auth.New()

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
		// get claims
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			// get appname from subject claim
			if appName, ok := claims["sub"].(string); ok {
				// get app from auth container
				if app, ok := svc.authContainer.GetApp(appName); ok {
					// check remote addr CIDR match
					if app.CheckStringCIDR(r.RemoteAddr) {
						// get tokenID from jti claim
						if tokenID, ok := claims["jti"].(string); ok {
							// get session from auth container
							if session, found := app.Sessions[tokenID]; found {
								// check session expiration
								if !session.IsExpired() {
									authed = true
									ctx = context.WithValue(ctx, svc.ctxSessionKey, &session)
								}
							}
						}
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
		Expires  int64  `json:"expires"`
	}

	// Parse request
	if err := rr.ReadRequestBody(req, &request); err != nil {
		return rr.ErrorResponse(err)
	}

	// validate request
	if request.AppName == "" {
		return rr.UnauthorizedResponse
	}

	app, found := svc.authContainer.GetApp(request.AppName)
	if !found {
		// Get appAuth secret from vault
		appAuthSecret, e := svc.instance.vc.Logical().Read(svc.instance.config.Vault.AuthPath + "/" + request.AppName)
		if appAuthSecret == nil || e != nil {
			return rr.UnauthorizedResponse
		}

		if appAuthSecret.Data == nil {
			logger.Error("Broken AppAuth : Data is null - ", request.AppName)
			return rr.UnauthorizedResponse
		}

		// get bind_cidr
		cidr, ok := appAuthSecret.Data["bind_cidr"].(string)
		if !ok {
			logger.Error("Broken AppAuth : CIDR not found - ", request.AppName)
			return rr.UnauthorizedResponse
		}

		ranger := cidranger.NewPCTrieRanger()
		_, network1, e := net.ParseCIDR(cidr)

		e = ranger.Insert(cidranger.NewBasicRangerEntry(*network1))
		if e != nil {
			logger.Error("Broken AppAuth : CIDR parse error - ", request.AppName)
			return rr.UnauthorizedResponse
		}

		// get privateKey for app
		// NOTE : publicKey is assumed to be pair with private key
		// maybe assertion needed for make sure
		privateKey, ok := appAuthSecret.Data["privateKey"].(string)
		if !ok {
			logger.Error("Broken AppAuth : privateKey not found - ", request.AppName)
			return rr.UnauthorizedResponse
		}

		kp, e := stellarkp.Parse(privateKey)
		if e != nil {
			logger.Error("Broken AppAuth : privateKey parse error - ", request.AppName)
			return rr.UnauthorizedResponse
		}

		app = svc.authContainer.NewApp(request.AppName)

		app.KeyPair = kp
		app.CIDRChecker = ranger
	}

	// get remote ip
	ip := auth.GetIPFromAddress(req.RemoteAddr)
	if ip == nil {
		return rr.UnauthorizedResponse
	}

	if !app.CheckCIDR(ip) {
		return rr.UnauthorizedResponse
	}

	// OK, seems proper access
	logger.Info("introduce from ", req.RemoteAddr, " by ", request.AppName)

	// generate random question
	qbytes := make([]byte, 32)
	_, e := io.ReadFull(rand.Reader, qbytes)
	if e != nil {
		return rr.ErrorResponse(e)
	}

	tokenID := base64.StdEncoding.EncodeToString(qbytes)

	question := auth.Question{}
	question.Expires = time.Now().UTC().Add(time.Second * time.Duration(svc.instance.config.Auth.QuestionExpires))
	question.RequestIP = ip

	app.Questions[tokenID] = question

	// OK, send question
	logger.Info("sending question to ", request.AppName)

	response.Question = tokenID
	response.Expires = question.Expires.Unix()

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
		Question  string `json:"yourQuestionWas"`
		Signature string `json:"myAnswerIs"`
	}

	var response struct {
		JWS          string            `json:"welcomePresent"`
		KeyQuestions map[string]string `json:"welcomePackage"`
		Expires      int64             `json:"expires"`
	}

	// Parse request
	if err := rr.ReadRequestBody(req, &request); err != nil {
		return rr.ErrorResponse(err)
	}

	// validate request
	if request.AppName == "" || request.Signature == "" {
		return rr.UnauthorizedResponse
	}

	// search session
	app, found := svc.authContainer.GetApp(request.AppName)
	if !found {
		return rr.UnauthorizedResponse
	}

	question, found := app.Questions[request.Question]
	if !found {
		return rr.UnauthorizedResponse
	}

	ip := auth.GetIPFromAddress(req.RemoteAddr)
	if ip == nil {
		return rr.UnauthorizedResponse
	}

	// FIXME : this may interfere proper handshake when introducer & answerer are different (even if both is proper)
	// this can be changed for CIDR check
	if !question.RequestIP.Equal(ip) {
		return rr.UnauthorizedResponse
	}

	logger.Info("answer from ", req.RemoteAddr, " by ", request.AppName)

	// check expiration
	if question.IsExpired() {
		return rr.KoResponse(http.StatusGone, "I forgot question. duh.")
	}

	mBytes, e := base64.StdEncoding.DecodeString(request.Question)
	if e != nil {
		return rr.KoResponse(http.StatusBadRequest, "You are so bad.")
	}

	sBytes, e := base64.StdEncoding.DecodeString(request.Signature)
	if e != nil {
		return rr.KoResponse(http.StatusBadRequest, "You are so bad.")
	}

	// Verify returns nil of matched, otherwise error returned
	if app.KeyPair.Verify(mBytes, sBytes) != nil {
		return rr.KoResponse(http.StatusNotAcceptable, "I don't like your answer.")
	}

	// Answer Verified ///////////////////////////////////////////////////////////

	// use question hex string as jti
	tokenID := request.Question

	expires := time.Now().UTC().Add(time.Second * time.Duration(svc.instance.config.Auth.JwtExpires))

	// build JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.StandardClaims{
		Id:        tokenID,
		Subject:   request.AppName,
		IssuedAt:  time.Now().UTC().Unix(),
		ExpiresAt: expires.Unix(),
	})

	// sign JWT into JWS
	jwsString, e := token.SignedString(svc.jwtSecretKey)
	if e != nil {
		return rr.ErrorResponse(e)
	}

	// get keyID / type:address map
	keymap, e := svc.instance.ks.GetKeyMap()

	// welcomePackage
	welcomePackage := make(map[string]string)

	// quiz map stored in session
	sessionQuizMap := make(map[string]auth.Quiz)

	for keyID, addrString := range keymap {

		kqBytes := make([]byte, 32)
		_, e := io.ReadFull(rand.Reader, kqBytes)

		if e != nil {
			return rr.ErrorResponse(e)
		}

		keyQuestion := base64.StdEncoding.EncodeToString(kqBytes)

		keyAnswer, e := app.KeyPair.Sign(kqBytes)
		if e != nil {
			return rr.ErrorResponse(e)
		}

		welcomePackage[addrString] = keyQuestion

		sessionQuizMap[addrString] = auth.Quiz{
			Question: keyQuestion,
			Answer:   base64.StdEncoding.EncodeToString(keyAnswer),
			KeyID:    keyID,
		}
	}
	// build session
	app.Sessions[tokenID] = auth.Session{
		JWS:     jwsString,
		AppName: request.AppName,
		Quizzes: sessionQuizMap,
		Expires: expires,
	}

	// OK, send token
	logger.Info("sending welcome present to ", request.AppName)

	response.JWS = jwsString
	response.KeyQuestions = welcomePackage
	response.Expires = expires.Unix()

	return rr.OkResponse(response)
}
