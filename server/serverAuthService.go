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
	"io"
	"net/http"
	"time"
)

// AuthService
type AuthService struct {
	instance *Instance

	// key = appName
	authData *auth.Data

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

	svc.authData = auth.New(instance.vc, instance.config.Vault.AuthPath)

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
				if app, ok := svc.authData.GetApp(appName); ok {
					// check remote addr CIDR match
					if app.CheckStringCIDR(r.RemoteAddr) {
						// get tokenID from jti claim
						if tokenID, ok := claims["jti"].(string); ok {
							// get session from auth container (will got nil if session is expired)
							if session, found := svc.authData.GetSession(tokenID); found {
								// check session is owned by requested app
								if session.AppName == appName {
									authed = true
									ctx = context.WithValue(ctx, svc.ctxSessionKey, session)
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

	app, found := svc.authData.GetApp(request.AppName)
	if !found {
		return rr.UnauthorizedResponse
	}

	// get remote ip
	ip := util.GetIPFromAddress(req.RemoteAddr)
	if ip == nil {
		return rr.UnauthorizedResponse
	}

	if !app.CheckCIDR(ip) {
		return rr.UnauthorizedResponse
	}

	// OK, seems proper access
	logger.Info("introduce from ", req.RemoteAddr, " by ", request.AppName)

	expires := time.Now().UTC().Add(time.Second * time.Duration(svc.instance.config.Auth.QuestionExpires))

	questionId, e := svc.authData.CreateQuestion(auth.Question{
		AppName:   request.AppName,
		Expires:   expires,
		RequestIP: ip,
	})

	if e != nil {
		return rr.ErrorResponse(e)
	}

	// OK, send question
	logger.Info("sending question to ", request.AppName)

	response.Question = questionId
	response.Expires = expires.Unix()

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

	// check app is present
	app, found := svc.authData.GetApp(request.AppName)
	if !found {
		return rr.UnauthorizedResponse
	}

	// get question (nil, false will be returned if expired)
	question, found := svc.authData.GetQuestion(request.Question)
	if !found {
		return rr.UnauthorizedResponse
	}

	// check appname with introducer
	if question.AppName != request.AppName {
		return rr.UnauthorizedResponse
	}

	// get ip from request
	ip := util.GetIPFromAddress(req.RemoteAddr)
	if ip == nil {
		return rr.UnauthorizedResponse
	}

	// check ip with introducer
	// FIXME : this may interfere proper handshake when introducer & answerer are different (even if both is proper)
	if !question.RequestIP.Equal(ip) {
		return rr.UnauthorizedResponse
	}

	logger.Info("answer from ", req.RemoteAddr, " by ", request.AppName)

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

	// build quizzes for session
	// get keyID / type:address map
	keymap, e := svc.instance.ks.GetKeyMap()

	// welcomePackage (addrString:question)
	welcomePackage := make(map[string]string)

	// quiz map stored in session (addrString:Quiz{question, answer, keyID})
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

	// store session
	svc.authData.CreateSession(tokenID, auth.Session{
		JWS:     jwsString,
		AppName: request.AppName,
		Quizzes: sessionQuizMap,
		Expires: expires,
	})

	// OK, send token
	logger.Info("sending welcome present to ", request.AppName)

	response.JWS = jwsString
	response.KeyQuestions = welcomePackage
	response.Expires = expires.Unix()

	return rr.OkResponse(response)
}
