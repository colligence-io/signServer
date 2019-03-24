package whitebox

import "C"
import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/colligence-io/signServer/config"
	"github.com/colligence-io/signServer/trustSigner"
	"github.com/colligence-io/signServer/util"
	"github.com/colligence-io/signServer/vault"
	"github.com/sirupsen/logrus"
	stellarkp "github.com/stellar/go/keypair"
	"net"
)

var logger = logrus.WithField("module", "WhiteBoxKeyStore")

type _config struct {
	whiteBoxPath string
	authPath     string
}

type KeyStore struct {
	config *_config

	// vault client
	vc *vault.Client

	// KeyID - keyPair map
	storage map[string]whiteBox
}

type whiteBox struct {
	bcType   trustSigner.BlockChainType
	address  string
	whiteBox *trustSigner.WhiteBox
}

func NewKeyStore(cfg *config.Configuration, vaultClient *vault.Client) *KeyStore {
	return &KeyStore{
		config: &_config{
			authPath:     cfg.Vault.AuthPath,
			whiteBoxPath: cfg.Vault.WhiteBoxPath,
		},
		vc: vaultClient,
	}
}

func (ks *KeyStore) Load() {
	if !ks.vc.IsConnected() {
		ks.vc.Connect()
	}

	ks.storage = make(map[string]whiteBox)

	ksList, e := ks.vc.Logical().List(ks.config.whiteBoxPath)
	util.CheckAndDie(e)

	if ksList == nil {
		logger.Warn("no whitebox data in storage")
		return
	}

	for _, ik := range ksList.Data["keys"].([]interface{}) {
		keyID := ik.(string)

		secret, e := ks.vc.Logical().Read(ks.config.whiteBoxPath + "/" + keyID)
		util.CheckAndDie(e)

		appID := secret.Data["appID"].(string)
		symbol := secret.Data["symbol"].(string)
		address := secret.Data["address"].(string)
		wbBytes, e := base64.StdEncoding.DecodeString(secret.Data["wb"].(string))
		util.CheckAndDie(e)

		bcType, found := trustSigner.BCTypes[symbol]
		if !found {
			util.CheckAndDie(fmt.Errorf("cannot load keypair %s : BlockChainType %s is invalid", appID, symbol))
		}

		wb := trustSigner.ConvertToWhiteBox(appID, wbBytes)

		publicKey := trustSigner.GetWBPublicKey(wb, bcType)
		if publicKey == "" {
			util.CheckAndDie(fmt.Errorf("cannot load keypair %s : empty publicKey", appID))
		}

		derivedAddress, err := trustSigner.DeriveAddress(bcType, publicKey)
		util.CheckAndDie(err)

		if derivedAddress != address {
			util.CheckAndDie(fmt.Errorf("cannot load keypair %s : address verification failed %s != %s", appID, address, derivedAddress))
		}

		ks.storage[keyID] = whiteBox{
			bcType:   bcType,
			address:  derivedAddress,
			whiteBox: wb,
		}
	}
}

func (ks *KeyStore) GetWhiteBoxData(keyID string, bcType trustSigner.BlockChainType) *trustSigner.WhiteBox {
	if wbData, found := ks.storage[keyID]; found && wbData.bcType == bcType {
		return wbData.whiteBox
	} else {
		return nil
	}
}

func (ks *KeyStore) LogKeyStoreEntries() {
	for keyID, kp := range ks.storage {
		logger.Info("KeyPair ", C.GoString((*C.char)(kp.whiteBox.AppID)), " : ", keyID, kp.bcType, kp.address)
	}
}

/*
KEYPAIR GENERATION
*/
func (ks *KeyStore) GenerateKeypair(appID string, symbol string) {
	if !ks.vc.IsConnected() {
		ks.vc.Connect()
	}

	bcType, found := trustSigner.BCTypes[symbol]
	if !found {
		fmt.Println("blockchain type not supported :", symbol)
		return
	}

	wbBytes := trustSigner.GetWBInitializeData(appID)

	wb := trustSigner.ConvertToWhiteBox(appID, wbBytes)

	key := trustSigner.GetWBPublicKey(wb, bcType)

	address, e := trustSigner.DeriveAddress(bcType, key)
	util.CheckAndDie(e)

	keyID := ks.appIDtoKeyID(appID)

	keyExists, e := ks.vc.Logical().Read(ks.config.whiteBoxPath + "/" + keyID)
	util.CheckAndDie(e)

	if keyExists != nil {
		util.Die("KeyPair already exists for appID " + appID)
	}

	vaultData := map[string]interface{}{
		"appID":   appID,
		"symbol":  symbol,
		"address": address,
		"wb":      base64.StdEncoding.EncodeToString(wbBytes),
	}
	_, e = ks.vc.Logical().Write(ks.config.whiteBoxPath+"/"+keyID, vaultData)
	util.CheckAndDie(e)

	fmt.Println("Whitebox Keypair Generated")
	fmt.Println("AppID :", appID)
	fmt.Println("KeyID :", keyID)
	fmt.Println("BlockChainType :", string(bcType))
	fmt.Println("Address :", address)
}

func (ks *KeyStore) ShowKeypairInfo(appID string) {
	if !ks.vc.IsConnected() {
		ks.vc.Connect()
	}

	keyID := ks.appIDtoKeyID(appID)

	secret, e := ks.vc.Logical().Read(ks.config.whiteBoxPath + "/" + keyID)
	util.CheckAndDie(e)

	if secret == nil {
		util.Die("KeyPair " + appID + " not exits")
	}

	symbol := secret.Data["symbol"].(string)
	address := secret.Data["address"].(string)

	fmt.Println("Whitebox Keypair Information")
	fmt.Println("AppID :", appID)
	fmt.Println("KeyID :", keyID)
	fmt.Println("BlockChainType :", symbol)
	fmt.Println("Address :", address)
}

func (ks *KeyStore) AddAppAuth(appName string, cidr string) {
	if !ks.vc.IsConnected() {
		ks.vc.Connect()
	}

	kp, e := stellarkp.Random()
	util.CheckAndDie(e)

	_, _, e = net.ParseCIDR(cidr)
	util.CheckAndDie(e)

	data := map[string]interface{}{
		"publicKey":  kp.Address(),
		"privateKey": kp.Seed(),
		"bind_cidr":  cidr,
	}

	_, e = ks.vc.Logical().Write(ks.config.authPath+"/"+appName, data)
	util.CheckAndDie(e)

	fmt.Println("SigningApp added")
	fmt.Println("AppName :", appName)
	fmt.Println("PublicKey :", kp.Address())
	fmt.Println("PrivateKey :", kp.Seed())
	fmt.Println("Bind CIDR :", cidr)
}

func (ks *KeyStore) appIDtoKeyID(appID string) string {
	return hex.EncodeToString(util.Crypto.Sha256Hash(appID))
}

func (ks *KeyStore) GetKeyMap() (map[string]string, error) {
	keymap := make(map[string]string)

	for keyID, wb := range ks.storage {
		keymap[keyID] = string(wb.bcType) + ":" + wb.address
	}

	return keymap, nil
}
