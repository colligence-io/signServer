package whitebox

import "C"
import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/colligence-io/signServer/trustSigner"
	"github.com/colligence-io/signServer/util"
	"github.com/colligence-io/signServer/vault"
	stellarkp "github.com/stellar/go/keypair"
	"log"
	"net"
)

type Config struct {
	WhiteBoxPath     string
	AuthPath         string
	SecretKeymapPath string
}

type KeyStore struct {
	config *Config

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

func NewKeyStore(config Config, vaultClient *vault.Client) *KeyStore {
	return &KeyStore{config: &config, vc: vaultClient}
}

func (ks *KeyStore) Load() {
	if !ks.vc.IsConnected() {
		ks.vc.Connect()
	}

	ks.storage = make(map[string]whiteBox)

	ksList, e := ks.vc.Logical().List(ks.config.WhiteBoxPath)
	util.CheckAndDie(e)

	if ksList == nil {
		log.Println("no whitebox data in storage")
		return
	}

	for _, ik := range ksList.Data["keys"].([]interface{}) {
		keyID := ik.(string)

		secret, e := ks.vc.Logical().Read(ks.config.WhiteBoxPath + "/" + keyID)
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
		log.Println("KeyPair", C.GoString((*C.char)(kp.whiteBox.AppID)), ":", keyID, kp.bcType, kp.address)
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

	vaultData := map[string]interface{}{
		"keyID":   keyID,
		"appID":   appID,
		"symbol":  symbol,
		"address": address,
		"wb":      base64.StdEncoding.EncodeToString(wbBytes),
	}
	_, e = ks.vc.Logical().Write(ks.config.WhiteBoxPath+"/"+keyID, vaultData)
	util.CheckAndDie(e)

	keymapSecret, e := ks.vc.Logical().Read(ks.config.SecretKeymapPath)
	util.CheckAndDie(e)

	var keymap map[string]interface{}
	if keymapSecret == nil || keymapSecret.Data == nil {
		keymap = make(map[string]interface{})
	} else {
		keymap = keymapSecret.Data
	}

	keymap[symbol+":"+address] = keyID

	_, e = ks.vc.Logical().Write(ks.config.SecretKeymapPath, keymap)
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

	secret, e := ks.vc.Logical().Read(ks.config.WhiteBoxPath + "/" + keyID)
	util.CheckAndDie(e)

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

	_, e = ks.vc.Logical().Write(ks.config.AuthPath+"/"+appName, data)
	util.CheckAndDie(e)

	fmt.Println("SigningApp added")
	fmt.Println("AppName :", appName)
	fmt.Println("PublicKey :", kp.Address())
	fmt.Println("PrivateKey :", kp.Seed())
	fmt.Println("Bind CIDR :", cidr)
}

func (ks *KeyStore) appIDtoKeyID(appID string) string {
	return hex.EncodeToString(util.Sha256Hash(appID))
}
