package auth

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/colligence-io/signServer/util"
	"github.com/colligence-io/signServer/vault"
	"github.com/sirupsen/logrus"
	stellarkp "github.com/stellar/go/keypair"
	"github.com/yl2chen/cidranger"
	"io"
	"net"
	"time"
)

var logger = logrus.WithField("module", "AppAuth")

type Data struct {
	// key = appId
	apps map[string]*App

	// key = random question
	loginQuestions map[string]*Question

	// key = session id
	sessions map[string]*Session
}

func New(vc *vault.Client, authPath string) *Data {
	newData := &Data{}
	newData.apps = loadApps(vc, authPath)
	newData.loginQuestions = make(map[string]*Question)
	newData.sessions = make(map[string]*Session)
	newData.autoCleanup()
	return newData
}

func loadApps(vc *vault.Client, authPath string) map[string]*App {
	apps := make(map[string]*App)

	appList, e := vc.Logical().List(authPath)
	util.CheckAndDie(e)

	for _, ik := range appList.Data["keys"].([]interface{}) {

		appName := ik.(string)

		// Get appAuth secret from vault
		appAuthSecret, e := vc.Logical().Read(authPath + "/" + appName)
		util.CheckAndDie(e)

		if appAuthSecret == nil {
			util.Die("App " + appName + " read failed")
		}

		if appAuthSecret.Data == nil {
			util.Die("Broken AppAuth : Data is null - " + appName)
		}

		// get bind_cidr
		cidr, ok := appAuthSecret.Data["bind_cidr"].(string)
		if !ok {
			util.Die("Broken AppAuth : CIDR not found - " + appName)
		}

		ranger := cidranger.NewPCTrieRanger()
		_, network1, e := net.ParseCIDR(cidr)

		e = ranger.Insert(cidranger.NewBasicRangerEntry(*network1))
		if e != nil {
			logger.Error(e)
			util.Die("Broken AppAuth : CIDR parse error - " + appName)
		}

		// get privateKey for app
		// NOTE : publicKey is assumed to be pair with private key
		// maybe assertion needed for make sure
		privateKey, ok := appAuthSecret.Data["privateKey"].(string)
		if !ok {
			util.Die("Broken AppAuth : privateKey not found - " + appName)
		}

		kp, e := stellarkp.Parse(privateKey)
		if e != nil {
			logger.Error(e)
			util.Die("Broken AppAuth : privateKey parse error - " + appName)
		}

		newApp := &App{}
		newApp.KeyPair = kp
		newApp.CIDRChecker = ranger

		apps[appName] = newApp

		logger.Info("App " + appName + " loaded")
	}

	return apps
}

func (data *Data) GetApp(appName string) (*App, bool) {
	if aa, found := data.apps[appName]; found {
		return aa, true
	}
	return nil, false
}

func (data *Data) GetQuestion(questionId string) (*Question, bool) {
	if qq, found := data.loginQuestions[questionId]; found {
		if !qq.IsExpired() {
			return qq, true
		} else {
			return nil, false
		}
	}
	return nil, false
}

func (data *Data) GetSession(sessionId string) (*Session, bool) {
	if ss, found := data.sessions[sessionId]; found {
		if !ss.IsExpired() {
			return ss, true
		} else {
			return nil, false
		}
	}
	return nil, false
}

func (data *Data) CreateQuestion(question Question) (string, error) {
	// generate random question
	qbytes := make([]byte, 32)
	_, e := io.ReadFull(rand.Reader, qbytes)
	if e != nil {
		return "", e
	}

	tokenID := base64.StdEncoding.EncodeToString(qbytes)

	data.loginQuestions[tokenID] = &question

	return tokenID, nil
}

func (data *Data) CreateSession(sessionID string, session Session) {
	data.sessions[sessionID] = &session
}

func (data *Data) autoCleanup() {
	go func() {
		for {
			time.Sleep(time.Second * 5)
			data.removeExpired()
			// TODO : add WithCancel Context to graceful shutdown
		}
	}()
}

func (data *Data) removeExpired() {
	for qk, qv := range data.loginQuestions {
		if qv.IsExpired() {
			logger.Tracef("question %s expired, removed from container", qk)
			delete(data.loginQuestions, qk)
		}
	}
	for sk, sv := range data.sessions {
		if sv.IsExpired() {
			logger.Tracef("session %s expired, removed from container", sk)
			delete(data.sessions, sk)
		}
	}
}
