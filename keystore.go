package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/colligence-io/signServer/trustSigner"
	_ "github.com/mattn/go-sqlite3"
)

type keyPair struct {
	BcType   trustSigner.BlockChainType
	Address  string
	WhiteBox *trustSigner.WhiteBox
}

/* KeyID - keyPair map */
var keyStore map[string]keyPair

func openDB() *sql.DB {
	db, err := sql.Open("sqlite3", "./.keyStore")
	checkAndDie(err)

	ddl := `create table if not exists kp (id char(64) not null primary key, appID varchar(128) not null, bcType varchar(12) not null, address varchar(128) not null, wbData blob not null);`
	_, err = db.Exec(ddl)
	checkAndDie(err)

	return db
}

func initKeyStore() {
	keyStore = make(map[string]keyPair)

	db := openDB()
	defer closeOrDie(db)

	rows, err := db.Query("select id, appID, bcType, address, wbData from kp;")
	defer closeOrDie(rows)
	checkAndDie(err)

	for rows.Next() {
		var keyID string
		var appID string
		var symbol string
		var address string
		var wbBytes []byte

		err = rows.Scan(&keyID, &appID, &symbol, &address, &wbBytes)
		checkAndDie(err)

		bcType, found := trustSigner.BCTypes[symbol]
		if !found {
			checkAndDie(fmt.Errorf("cannot load keypair %s : BlockChainType %s is invalid", appID, symbol))
		}

		wb := trustSigner.ConvertToWhiteBox(appID, wbBytes)

		publicKey := trustSigner.GetWBPublicKey(wb, bcType)
		checkAndDie(err)

		derivedAddress, err := trustSigner.DeriveAddress(bcType, publicKey)
		checkAndDie(err)

		if derivedAddress != address {
			checkAndDie(fmt.Errorf("cannot load keypair %s : address verification failed %s != %s", appID, address, derivedAddress))
		}

		keyStore[keyID] = keyPair{
			BcType:   trustSigner.BTC,
			Address:  derivedAddress,
			WhiteBox: wb,
		}
	}
}

func getWhiteBoxData(keyID string, bcType trustSigner.BlockChainType) (*trustSigner.WhiteBox, error) {
	if wbData, found := keyStore[keyID]; found && wbData.BcType == bcType {
		return wbData.WhiteBox, nil
	} else {
		return nil, fmt.Errorf("%s %s not found on keyStore", string(bcType), keyID)
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

	db := openDB()
	defer closeOrDie(db)

	tx, err := db.Begin()
	checkAndDie(err)

	wbBytes := trustSigner.GetWBInitializeData(appID)

	wb := trustSigner.ConvertToWhiteBox(appID, wbBytes)

	key := trustSigner.GetWBPublicKey(wb, bcType)

	address, err := trustSigner.DeriveAddress(bcType, key)
	checkAndDie(err)

	hash := sha256.New()
	hash.Write([]byte(appID))
	keyID := hex.EncodeToString(hash.Sum(nil))

	stmt, err := tx.Prepare("insert into kp (id, appID, bcType, address, wbData) values (?,?,?,?,?)")
	defer closeOrDie(stmt)
	checkAndDie(err)

	_, err = stmt.Exec(keyID, appID, string(bcType), address, &wbBytes)
	checkAndDie(err)

	err = tx.Commit()
	checkAndDie(err)

	fmt.Println("Whitebox Keypair Generated")
	fmt.Println("AppID :", appID)
	fmt.Println("KeyID :", keyID)
	fmt.Println("BlockChainType :", string(bcType))
	fmt.Println("Address :", address)
}

func showKeypairInfo(appID string) {
	db := openDB()
	defer closeOrDie(db)

	stmt, err := db.Prepare("select id, bcType, address from kp where appID = ?")
	defer closeOrDie(stmt)
	checkAndDie(err)

	var keyID string
	var symbol string
	var address string

	err = stmt.QueryRow(appID).Scan(&keyID, &symbol, &address)
	checkAndDie(err)

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
		result[string(kp.BcType)+":"+kp.Address] = keyID
	}

	rb, err := json.MarshalIndent(result, "", "  ")
	checkAndDie(err)

	fmt.Println("VaultConfig data")
	fmt.Printf("\"signserver\": %s", string(rb))
}
