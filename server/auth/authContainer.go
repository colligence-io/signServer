package auth

import (
	"github.com/sirupsen/logrus"
	stellarkp "github.com/stellar/go/keypair"
	"github.com/yl2chen/cidranger"
	"net"
	"time"
)

var logger = logrus.WithField("module", "AppAuth")

type Container struct {
	data map[string]*AppAuth
}

func New() *Container {
	newContainer := &Container{}
	newContainer.data = make(map[string]*AppAuth)
	newContainer.autoCleanup()
	return newContainer
}

func (c *Container) NewApp(appName string) *AppAuth {
	newAuth := &AppAuth{}
	newAuth.Questions = make(map[string]Question)
	newAuth.Sessions = make(map[string]Session)
	c.data[appName] = newAuth
	return newAuth
}

func (c *Container) GetApp(appName string) (*AppAuth, bool) {
	if aa, found := c.data[appName]; found {
		return aa, true
	}
	return nil, false
}

func (c *Container) autoCleanup() {
	go func() {
		for {
			time.Sleep(time.Second * 5)
			for _, dv := range c.data {
				dv.removeExpired()
			}

			// TODO : add WithCancel Context to graceful shutdown
		}
	}()
}

type AppAuth struct {
	KeyPair     stellarkp.KP
	CIDRChecker cidranger.Ranger
	// key = question(jti)
	Questions map[string]Question
	// key = jws
	Sessions map[string]Session
}

func (aa *AppAuth) removeExpired() {
	for qk, qv := range aa.Questions {
		if qv.IsExpired() {
			logger.Tracef("question %s expired, removed from container", qk)
			delete(aa.Questions, qk)
		}
	}
	for sk, sv := range aa.Sessions {
		if sv.IsExpired() {
			logger.Tracef("session %s expired, removed from container", sk)
			delete(aa.Sessions, sk)
		}
	}
}

// check CIDR range match for ip
func (aa *AppAuth) CheckCIDR(ip net.IP) bool {
	contains, e := aa.CIDRChecker.Contains(ip)
	if e != nil {
		return false
	}
	return contains
}

// check CIDR range match for ip string
func (aa *AppAuth) CheckStringCIDR(addr string) bool {
	if ip := GetIPFromAddress(addr); ip != nil {
		return aa.CheckCIDR(ip)
	}
	return false
}

type Question struct {
	RequestIP net.IP
	Expires   time.Time
}

// check question is expired
func (q *Question) IsExpired() bool {
	return q.Expires.Before(time.Now())
}

type Session struct {
	JWS     string
	AppName string
	Quizzes map[string]Quiz
	Expires time.Time
}

type Quiz struct {
	Question string
	Answer   string
	KeyID    string
}

// check session is expired
func (s *Session) IsExpired() bool {
	return s.Expires.Before(time.Now())
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Global Functions

// GetIPFromAddress returns net.IP from IP:PORT string
func GetIPFromAddress(addr string) net.IP {
	host, _, e := net.SplitHostPort(addr)
	if e != nil {
		return nil
	}
	if host != "" {
		return net.ParseIP(host)
	} else {
		return net.ParseIP(addr)
	}
}
