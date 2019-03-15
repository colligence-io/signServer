package server

import (
	"encoding/base64"
	"github.com/colligence-io/signServer/util"
	stellarkp "github.com/stellar/go/keypair"
	"github.com/yl2chen/cidranger"
	"net"
	"time"
)

type appClientInfo struct {
	keypair             stellarkp.KP
	cidrChecker         cidranger.Ranger
	lastQuestion        []byte
	lastRequestIP       net.IP
	lastQuestionExpires time.Time
}

// verify signature with last question
func (appInfo *appClientInfo) verifySignature(signature string) bool {
	sigBytes, e := base64.StdEncoding.DecodeString(signature)
	if e != nil {
		return false
	}

	// Verify returns nil of matched, otherwise error returned
	return appInfo.keypair.Verify(appInfo.lastQuestion, sigBytes) == nil
}

// check CIDR range match for ip
func (appInfo *appClientInfo) checkCIDR(ip net.IP) bool {
	contains, e := appInfo.cidrChecker.Contains(ip)
	if e != nil {
		return false
	}
	return contains
}

// check CIDR range match for ip string
func (appInfo *appClientInfo) checkStringCIDR(addr string) bool {
	if ip := util.GetIP(addr); ip != nil {
		return appInfo.checkCIDR(ip)
	}
	return false
}

// check question is expired
func (appInfo *appClientInfo) isQuestionExpired() bool {
	return appInfo.lastQuestionExpires.Before(time.Now())
}
