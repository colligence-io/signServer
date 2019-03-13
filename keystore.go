package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/colligence-io/signServer/trustSigner"
)

type keyPair struct {
	bcType   trustSigner.BlockChainType
	address  string
	whiteBox *trustSigner.WhiteBox
}

/* KeyID - keyPair map */
var keyStore map[string]keyPair

var vks *vaultConnection

func initKeyStore() {
	keyStore = make(map[string]keyPair)

	vks = connectVault()
	//vks.startAutoRenew()

	ksList, e := vks.client.Logical().List("bcks")
	checkAndDie(e)

	for _, ik := range ksList.Data["keys"].([]interface{}) {
		keyID := ik.(string)

		secret, e := vks.client.Logical().Read("bcks/" + keyID)
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

func getWhiteBoxData(keyID string, bcType trustSigner.BlockChainType) (*trustSigner.WhiteBox, error) {
	if wbData, found := keyStore[keyID]; found && wbData.bcType == bcType {
		return wbData.whiteBox, nil
	} else {
		return nil, fmt.Errorf("%s %s not found on keyStore", string(bcType), keyID)
	}
}

/*
KEYPAIR GENERATION
*/
func generateKeypair(appID string, symbol string) {
	vc := connectVault()

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
	_, e = vc.client.Logical().Write("bcks/"+keyID, vaultData)
	checkAndDie(e)

	fmt.Println("Whitebox Keypair Generated")
	fmt.Println("AppID :", appID)
	fmt.Println("KeyID :", keyID)
	fmt.Println("BlockChainType :", string(bcType))
	fmt.Println("Address :", address)
}

func appIDtoKeyID(appID string) string {
	hash := sha256.New()
	hash.Write([]byte(appID))
	return hex.EncodeToString(hash.Sum(nil))
}

func showKeypairInfo(appID string) {
	vc := connectVault()

	keyID := appIDtoKeyID(appID)

	secret, e := vc.client.Logical().Read("bcks/" + keyID)
	checkAndDie(e)

	symbol := secret.Data["symbol"].(string)
	address := secret.Data["address"].(string)

	fmt.Println("Whitebox Keypair Information")
	fmt.Println("AppID :", appID)
	fmt.Println("KeyID :", keyID)
	fmt.Println("BlockChainType :", symbol)
	fmt.Println("Address :", address)
}

func printVaultConfig() {
	initKeyStore()

	var result map[string]string
	result = make(map[string]string)

	for keyID, kp := range keyStore {
		result[string(kp.bcType)+":"+kp.address] = keyID
	}

	rb, err := json.MarshalIndent(result, "", "  ")
	checkAndDie(err)

	fmt.Println("VaultConfig data")
	fmt.Printf("\"signserver\": %s", string(rb))
}
