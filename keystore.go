package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/colligence-io/signServer/trustSigner"
	stellarkp "github.com/stellar/go/keypair"
	"net"
)

type keyPair struct {
	bcType   trustSigner.BlockChainType
	address  string
	whiteBox *trustSigner.WhiteBox
}

/* KeyID - keyPair map */
var keyStore map[string]keyPair

func initKeyStore() {
	keyStore = make(map[string]keyPair)

	ksList, e := vks.client.Logical().List(serverConfig.Vault.WhiteBoxPath)
	checkAndDie(e)

	for _, ik := range ksList.Data["keys"].([]interface{}) {
		keyID := ik.(string)

		secret, e := vks.client.Logical().Read(serverConfig.Vault.WhiteBoxPath + "/" + keyID)
		checkAndDie(e)

		appID := secret.Data["appID"].(string)
		symbol := secret.Data["symbol"].(string)
		address := secret.Data["address"].(string)
		wbBytes, e := base64.StdEncoding.DecodeString(secret.Data["wb"].(string))
		checkAndDie(e)

		bcType, found := trustSigner.BCTypes[symbol]
		if !found {
			checkAndDie(fmt.Errorf("cannot load keypair %s : BlockChainType %s is invalid", appID, symbol))
		}

		wb := trustSigner.ConvertToWhiteBox(appID, wbBytes)

		publicKey := trustSigner.GetWBPublicKey(wb, bcType)
		if publicKey == "" {
			checkAndDie(fmt.Errorf("cannot load keypair %s : empty publicKey", appID))
		}

		derivedAddress, err := trustSigner.DeriveAddress(bcType, publicKey)
		checkAndDie(err)

		if derivedAddress != address {
			checkAndDie(fmt.Errorf("cannot load keypair %s : address verification failed %s != %s", appID, address, derivedAddress))
		}

		keyStore[keyID] = keyPair{
			bcType:   bcType,
			address:  derivedAddress,
			whiteBox: wb,
		}
	}
}

func getWhiteBoxData(keyID string, bcType trustSigner.BlockChainType) *trustSigner.WhiteBox {
	if wbData, found := keyStore[keyID]; found && wbData.bcType == bcType {
		return wbData.whiteBox
	} else {
		return nil
	}
}

/*
KEYPAIR GENERATION
*/
func generateKeypair(appID string, symbol string) {
	bcType, found := trustSigner.BCTypes[symbol]
	if !found {
		fmt.Println("blockchain type not supported :", symbol)
		return
	}

	wbBytes := trustSigner.GetWBInitializeData(appID)

	wb := trustSigner.ConvertToWhiteBox(appID, wbBytes)

	key := trustSigner.GetWBPublicKey(wb, bcType)

	address, e := trustSigner.DeriveAddress(bcType, key)
	checkAndDie(e)

	keyID := appIDtoKeyID(appID)

	vaultData := map[string]interface{}{
		"keyID":   keyID,
		"appID":   appID,
		"symbol":  symbol,
		"address": address,
		"wb":      base64.StdEncoding.EncodeToString(wbBytes),
	}
	_, e = vks.client.Logical().Write(serverConfig.Vault.WhiteBoxPath+"/"+keyID, vaultData)
	checkAndDie(e)

	keymapSecret, e := vks.client.Logical().Read(serverConfig.Vault.SecretKeymapPath)
	checkAndDie(e)

	var keymap map[string]interface{}
	if keymapSecret == nil || keymapSecret.Data == nil {
		keymap = make(map[string]interface{})
	} else {
		keymap = keymapSecret.Data
	}

	keymap[symbol+":"+address] = keyID

	_, e = vks.client.Logical().Write(serverConfig.Vault.SecretKeymapPath, keymap)
	checkAndDie(e)

	fmt.Println("Whitebox Keypair Generated")
	fmt.Println("AppID :", appID)
	fmt.Println("KeyID :", keyID)
	fmt.Println("BlockChainType :", string(bcType))
	fmt.Println("Address :", address)
}

func showKeypairInfo(appID string) {
	keyID := appIDtoKeyID(appID)

	secret, e := vks.client.Logical().Read(serverConfig.Vault.WhiteBoxPath + "/" + keyID)
	checkAndDie(e)

	symbol := secret.Data["symbol"].(string)
	address := secret.Data["address"].(string)

	fmt.Println("Whitebox Keypair Information")
	fmt.Println("AppID :", appID)
	fmt.Println("KeyID :", keyID)
	fmt.Println("BlockChainType :", symbol)
	fmt.Println("Address :", address)
}

func addAppAuth(appName string, cidr string) {
	kp, e := stellarkp.Random()
	checkAndDie(e)

	_, _, e = net.ParseCIDR(cidr)
	checkAndDie(e)

	data := map[string]interface{}{
		"publicKey":  kp.Address(),
		"privateKey": kp.Seed(),
		"bind_cidr":  cidr,
	}

	_, e = vks.client.Logical().Write(serverConfig.Vault.AuthPath+"/"+appName, data)
	checkAndDie(e)

	fmt.Println("SigningApp added")
	fmt.Println("AppName :", appName)
	fmt.Println("PublicKey :", kp.Address())
	fmt.Println("PrivateKey :", kp.Seed())
	fmt.Println("Bind CIDR :", cidr)
}

func appIDtoKeyID(appID string) string {
	return hex.EncodeToString(sha256Hash(appID))
}
