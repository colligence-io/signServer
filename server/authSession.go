package server

import (
	"encoding/base64"
	stellarkp "github.com/stellar/go/keypair"
	"github.com/yl2chen/cidranger"
	"net"
	"time"
)

type authSession struct {
	appName             string
	keypair             stellarkp.KP
	cidrChecker         cidranger.Ranger
	lastQuestion        []byte
	lastRequestIP       net.IP
	lastQuestionExpires time.Time
	issuedToken         string
	keyQuizMap          map[string]sessionQuiz
}

type sessionQuiz struct {
	question string
	answer   string
	keyID    string
}

// verify signature with last question
func (appInfo *authSession) verifySignature(signature string) bool {
	sigBytes, e := base64.StdEncoding.DecodeString(signature)
	if e != nil {
		return false
	}

	// Verify returns nil of matched, otherwise error returned
	return appInfo.keypair.Verify(appInfo.lastQuestion, sigBytes) == nil
}

// check CIDR range match for ip
func (appInfo *authSession) checkCIDR(ip net.IP) bool {
	contains, e := appInfo.cidrChecker.Contains(ip)
	if e != nil {
		return false
	}
	return contains
}

// check CIDR range match for ip string
func (appInfo *authSession) checkStringCIDR(addr string) bool {
	if ip := getIPfromAddress(addr); ip != nil {
		return appInfo.checkCIDR(ip)
	}
	return false
}

// check question is expired
func (appInfo *authSession) isQuestionExpired() bool {
	return appInfo.lastQuestionExpires.Before(time.Now())
}
