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

	// stores sessions for apps
	// key=appName, this prevents issueing multiple access token per app
	sessions map[string]*authSession

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

	svc.sessions = make(map[string]*authSession)

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
					if session, found := svc.sessions[appName]; found && session.issuedToken == tokenID {
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

	session, found := svc.sessions[request.AppName]
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

		session = &authSession{
			appName:     request.AppName,
			keypair:     kp,
			cidrChecker: ranger,
		}

		svc.sessions[request.AppName] = session
	}

	// get remote ip
	ip := getIPfromAddress(req.RemoteAddr)
	if ip == nil {
		return rr.UnauthorizedResponse
	}

	if !session.checkCIDR(ip) {
		return rr.UnauthorizedResponse
	}

	session.lastRequestIP = ip

	// OK, seems proper access
	logger.Println("introduce from ", req.RemoteAddr, " by ", request.AppName)

	// generate random question
	session.lastQuestion = make([]byte, 32)
	_, e := io.ReadFull(rand.Reader, session.lastQuestion)

	if e != nil {
		return rr.ErrorResponse(e)
	}

	session.lastQuestionExpires = time.Now().UTC().Add(time.Second * time.Duration(svc.instance.config.QuestionExpires))

	// OK, send question
	logger.Println("sending question to ", request.AppName)

	response.Question = base64.StdEncoding.EncodeToString(session.lastQuestion)
	response.Expires = session.lastQuestionExpires.Unix()

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
		JwtToken     string            `json:"welcomePresent"`
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
	session, found := svc.sessions[request.AppName]
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
	if !session.lastRequestIP.Equal(ip) {
		return rr.UnauthorizedResponse
	}

	logger.Println("answer from ", req.RemoteAddr, " by ", request.AppName)

	// check expiration
	if session.isQuestionExpired() {
		return rr.KoResponse(http.StatusGone, "I forgot question. duh.")
	}

	// verify signature
	if !session.verifySignature(request.Signature) {
		return rr.KoResponse(http.StatusNotAcceptable, "I don't like your answer.")
	}

	// generate tokenID from question
	tokenID := hex.EncodeToString(session.lastQuestion)

	expires := time.Now().UTC().Add(time.Second * time.Duration(svc.instance.config.JwtExpires)).Unix()

	// build JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.StandardClaims{
		Id:        tokenID,
		Subject:   request.AppName,
		IssuedAt:  time.Now().UTC().Unix(),
		ExpiresAt: expires,
	})

	// sign JWT into JWS
	jwtString, e := token.SignedString(svc.jwtSecretKey)
	if e != nil {
		return rr.ErrorResponse(e)
	}

	// get keyID / type:address map
	keymap, e := svc.instance.ks.GetKeyMap()

	// welcomePackage
	keyQuestions := make(map[string]string)

	// quiz map stored in session
	keyQuizMap := make(map[string]sessionQuiz)

	for keyID, addrString := range keymap {

		kqBytes := make([]byte, 32)
		_, e := io.ReadFull(rand.Reader, kqBytes)

		if e != nil {
			return rr.ErrorResponse(e)
		}

		keyQuestion := base64.StdEncoding.EncodeToString(kqBytes)

		keyAnswer, e := session.keypair.Sign(kqBytes)
		if e != nil {
			return rr.ErrorResponse(e)
		}

		keyQuestions[addrString] = keyQuestion

		keyQuizMap[addrString] = sessionQuiz{
			question: keyQuestion,
			answer:   base64.StdEncoding.EncodeToString(keyAnswer),
			keyID:    keyID,
		}
	}

	// store issued token for authenticator
	svc.sessions[request.AppName].issuedToken = tokenID
	svc.sessions[request.AppName].keyQuizMap = keyQuizMap

	// OK, send token
	logger.Println("sending welcome present to ", request.AppName)

	response.JwtToken = jwtString
	response.KeyQuestions = keyQuestions
	response.Expires = expires

	return rr.OkResponse(response)
}
