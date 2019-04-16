package whitebox

import "C"
import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/colligence-io/signServer/config"
	"github.com/colligence-io/signServer/trustSigner"
	"github.com/colligence-io/signServer/util"
	"github.com/colligence-io/signServer/vault"
	"github.com/sirupsen/logrus"
	stellarkp "github.com/stellar/go/keypair"
	"io/ioutil"
	"net"
	"os"
)

var logger = logrus.WithField("module", "WhiteBoxKeyStore")

type KeyStore struct {
	config *config.Configuration

	// vault client
	vc *vault.Client

	// KeyID - keyPair map
	storage map[string]keyPair
}

type keyPair struct {
	bcType   trustSigner.BlockChainType
	address  string
	whiteBox *trustSigner.WhiteBox
}

type backupData struct {
	AppID    string `json:"appID"`
	Symbol   string `json:"symbol"`
	Address  string `json:"address"`
	WhiteBox string `json:"whitebox"`
}

func NewKeyStore(cfg *config.Configuration, vaultClient *vault.Client) *KeyStore {
	return &KeyStore{
		config: cfg,
		vc:     vaultClient,
	}
}

func (ks *KeyStore) Load() {
	if !ks.vc.IsConnected() {
		ks.vc.Connect()
	}

	ks.storage = make(map[string]keyPair)

	ksList, e := ks.vc.Logical().List(ks.config.Vault.WhiteBoxPath)
	util.CheckAndDie(e)

	if ksList == nil {
		logger.Warn("no whitebox data in storage")
		return
	}

	for _, ik := range ksList.Data["keys"].([]interface{}) {
		keyID := ik.(string)

		secret, e := ks.vc.Logical().Read(ks.config.Vault.WhiteBoxPath + "/" + keyID)
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

		publicKey, e := trustSigner.GetWBPublicKey(wb, bcType)
		util.CheckAndDie(e)

		derivedAddress, err := trustSigner.DeriveAddress(bcType, publicKey, ks.config.Server.BlockChainNetwork)
		util.CheckAndDie(err)

		if derivedAddress != address {
			util.CheckAndDie(fmt.Errorf("cannot load keypair %s : address verification failed %s != %s", appID, address, derivedAddress))
		}

		ks.storage[keyID] = keyPair{
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

func (ks *KeyStore) GetKeyStoreListDescription() []string {
	kplist := make([]string, 0, len(ks.storage))

	for keyID, kp := range ks.storage {
		kplist = append(kplist, fmt.Sprint("KeyPair ", C.GoString((*C.char)(kp.whiteBox.AppID)), " : ", keyID, " ", kp.bcType, " ", kp.address))
	}

	return kplist
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

	wbBytes, e := trustSigner.GetWBInitializeData(appID)
	util.CheckAndDie(e)

	wb := trustSigner.ConvertToWhiteBox(appID, wbBytes)

	key, e := trustSigner.GetWBPublicKey(wb, bcType)
	util.CheckAndDie(e)

	address, e := trustSigner.DeriveAddress(bcType, key, ks.config.Server.BlockChainNetwork)
	util.CheckAndDie(e)

	keyID := ks.appIDtoKeyID(appID)

	keyExists, e := ks.vc.Logical().Read(ks.config.Vault.WhiteBoxPath + "/" + keyID)
	util.CheckAndDie(e)

	if keyExists != nil {
		util.Die("KeyPair already exists for appID " + appID)
	}

	// store to vault
	_, e = ks.vc.Logical().Write(ks.config.Vault.WhiteBoxPath+"/"+keyID, toVaultData(appID, symbol, address, base64.StdEncoding.EncodeToString(wbBytes)))
	util.CheckAndDie(e)

	fmt.Println("Whitebox Keypair Generated")
	fmt.Println("AppID :", appID)
	fmt.Println("KeyID :", keyID)
	fmt.Println("BlockChainType :", string(bcType))
	fmt.Println("Address :", address)
}

func toVaultData(appID string, symbol string, address string, wbBase64 string) map[string]interface{} {
	return map[string]interface{}{
		"appID":   appID,
		"symbol":  symbol,
		"address": address,
		"wb":      wbBase64,
	}
}

func (ks *KeyStore) ShowKeypairInfo(appID string) {
	if !ks.vc.IsConnected() {
		ks.vc.Connect()
	}

	keyID := ks.appIDtoKeyID(appID)

	secret, e := ks.vc.Logical().Read(ks.config.Vault.WhiteBoxPath + "/" + keyID)
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

	_, e = ks.vc.Logical().Write(ks.config.Vault.AuthPath+"/"+appName, data)
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

func (ks *KeyStore) BackupKeyPair(appID string) {
	if !ks.vc.IsConnected() {
		ks.vc.Connect()
	}

	keyID := ks.appIDtoKeyID(appID)
	secret, e := ks.vc.Logical().Read(ks.config.Vault.WhiteBoxPath + "/" + keyID)
	util.CheckAndDie(e)

	secretAppID, ok := secret.Data["appID"].(string)
	if !ok {
		util.Die("broken data, appID is not string")
	}
	secretSymbol, ok := secret.Data["symbol"].(string)
	if !ok {
		util.Die("broken data, symbol is not string")
	}
	secretAddress, ok := secret.Data["address"].(string)
	if !ok {
		util.Die("broken data, address is not string")
	}
	secretWbBase64, ok := secret.Data["wb"].(string)
	if !ok {
		util.Die("broken data, wb is not string")
	}

	_, found := trustSigner.BCTypes[secretSymbol]
	if !found {
		util.CheckAndDie(fmt.Errorf("cannot load keypair %s : BlockChainType %s is invalid", appID, secretSymbol))
	}

	jsonData, e := json.Marshal(backupData{
		AppID:    secretAppID,
		Symbol:   secretSymbol,
		Address:  secretAddress,
		WhiteBox: secretWbBase64,
	})
	util.CheckAndDie(e)

	e = ioutil.WriteFile("wb_"+keyID+".json", jsonData, 0600)
	util.CheckAndDie(e)

	fmt.Println("Whitebox data backup file : wb_" + keyID + ".json")
}

func (ks *KeyStore) RecoverKeyPair(filePath string) {
	if !ks.vc.IsConnected() {
		ks.vc.Connect()
	}

	jsonFile, e := os.Open(filePath)
	util.CheckAndDie(e)
	backupBytes, e := ioutil.ReadAll(jsonFile)
	util.CheckAndDie(e)

	var backup backupData
	e = json.Unmarshal(backupBytes, &backup)
	util.CheckAndDie(e)

	keyID := ks.appIDtoKeyID(backup.AppID)

	secret, e := ks.vc.Logical().Read(ks.config.Vault.WhiteBoxPath + "/" + keyID)
	util.CheckAndDie(e)

	if secret != nil && secret.Data != nil {
		fmt.Print(backup.AppID, " already stored in vault, overwrite? [YES/no] : ")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		yesno := scanner.Text()

		if yesno != "YES" {
			util.Die("Canceled")
		}
	}

	// check integrity
	bcType, found := trustSigner.BCTypes[backup.Symbol]
	if !found {
		fmt.Println("blockchain type not supported :", backup.Symbol)
		return
	}

	wbBytes, e := base64.StdEncoding.DecodeString(backup.WhiteBox)
	util.CheckAndDie(e)

	whitebox := trustSigner.ConvertToWhiteBox(backup.AppID, wbBytes)

	publicKey, e := trustSigner.GetWBPublicKey(whitebox, bcType)
	util.CheckAndDie(e)

	derivedAddress, e := trustSigner.DeriveAddress(bcType, publicKey, ks.config.Server.BlockChainNetwork)
	util.CheckAndDie(e)

	if backup.Address != derivedAddress {
		util.Die("backup data might be broken, address not match")
	}

	// store to vault
	_, e = ks.vc.Logical().Write(ks.config.Vault.WhiteBoxPath+"/"+keyID, toVaultData(backup.AppID, backup.Symbol, backup.Address, backup.WhiteBox))
	util.CheckAndDie(e)

	fmt.Println("Whitebox Keypair Recovered")
	fmt.Println("AppID :", backup.AppID)
	fmt.Println("KeyID :", keyID)
	fmt.Println("BlockChainType :", string(bcType))
	fmt.Println("Address :", backup.Address)
}
