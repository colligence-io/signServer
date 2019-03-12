package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"github.com/colligence-io/signServer/hd"
	"github.com/colligence-io/signServer/trustSigner"
	_ "github.com/mattn/go-sqlite3"
	"log"
)

/* appID - WhiteBox map */
var wbStore map[string]*trustSigner.WhiteBox

/* BCType - PublicKey - WhiteBox map */
var keyStore map[trustSigner.BlockChainType]map[string]*trustSigner.WhiteBox

func openDB() *sql.DB {
	db, err := sql.Open("sqlite3", "./.keyStore")
	checkAndDie(err)

	ddl := `create table if not exists kp (id char(64) not null primary key, appID varchar(128) not null, wbData blob not null);`
	_, err = db.Exec(ddl)
	checkAndDie(err)

	return db
}

func initKeyStore() {
	log.Println("Initialize WhiteBox KeyStore")

	wbStore = make(map[string]*trustSigner.WhiteBox)
	keyStore = make(map[trustSigner.BlockChainType]map[string]*trustSigner.WhiteBox)

	for _, v := range trustSigner.BCTypes {
		keyStore[v] = make(map[string]*trustSigner.WhiteBox)
	}

	db := openDB()
	defer closeOrDie(db)

	rows, err := db.Query("select id, appID, wbData from kp;")
	defer closeOrDie(rows)
	checkAndDie(err)

	for rows.Next() {
		var id string
		var appID string
		var wbBytes []byte

		err = rows.Scan(&id, &appID, &wbBytes)
		checkAndDie(err)

		wb := trustSigner.ConvertToWhiteBox(appID, wbBytes)

		wbStore[appID] = wb

		log.Printf("%s : %s\n", appID, id)

		for _, bcType := range trustSigner.BCTypes {
			key := trustSigner.GetWBPublicKey(wb, bcType)
			checkAndDie(err)

			address, err := deriveAddress(key, bcType)
			checkAndDie(err)

			keyStore[bcType][address] = wb

			log.Printf(" %s : %s\n", string(bcType), address)
		}
	}
}

func getWhiteBoxData(bcType trustSigner.BlockChainType, publicKey string) (*trustSigner.WhiteBox, error) {
	if wbData, found := keyStore[bcType][publicKey]; found {
		return wbData, nil
	} else {
		return nil, fmt.Errorf("%s publicKey %s not found on keyStore", string(bcType), publicKey)
	}
}

/*
KEYPAIR GENERATION
*/
func generateKeypair(appID string) {
	db := openDB()
	defer closeOrDie(db)

	tx, err := db.Begin()
	checkAndDie(err)

	wbBytes := trustSigner.GetWBInitializeData(appID)

	hash := sha256.New()
	hash.Write([]byte(appID))
	dataID := hex.EncodeToString(hash.Sum(nil))

	stmt, err := tx.Prepare("insert into kp (id, appID, wbData) values (?,?,?)")
	defer closeOrDie(stmt)
	checkAndDie(err)

	_, err = stmt.Exec(dataID, appID, &wbBytes)
	checkAndDie(err)

	err = tx.Commit()
	checkAndDie(err)

	wb := trustSigner.ConvertToWhiteBox(appID, wbBytes)

	printBlockChainData(appID, dataID, wb)
}

func inspectWhiteBoxData(appID string) {
	db := openDB()
	defer closeOrDie(db)

	stmt, err := db.Prepare("select id, wbData from kp where appID = ?")
	defer closeOrDie(stmt)
	checkAndDie(err)

	var id string
	var wbBytes []byte

	err = stmt.QueryRow(appID).Scan(&id, &wbBytes)
	checkAndDie(err)

	wb := trustSigner.ConvertToWhiteBox(appID, wbBytes)

	printBlockChainData(appID, id, wb)
}

func printBlockChainData(appID string, id string, wb *trustSigner.WhiteBox) {
	fmt.Printf("AppID : %s\n", appID)
	fmt.Printf("ID : %s\n", id)

	for _, bcType := range trustSigner.BCTypes {
		key := trustSigner.GetWBPublicKey(wb, bcType)
		fmt.Printf(" - %s\n", string(bcType))
		fmt.Printf("   PublicKey : %s\n", key)

		address, err := deriveAddress(key, bcType)
		checkAndDie(err)

		fmt.Printf("   Address :  %s\n", address)
	}
}

func deriveAddress(publicKey string, bcType trustSigner.BlockChainType) (string, error) {
	switch bcType {
	case trustSigner.BTC:
		wallet, err := hd.FromBIP32ExtendedKey(publicKey)
		if err != nil {
			return "", err
		}
		return wallet.DeriveBTCAddress()
	case trustSigner.ETH:
		wallet, err := hd.FromBIP32ExtendedKey(publicKey)
		if err != nil {
			return "", err
		}
		return wallet.DeriveETHAddress()
	case trustSigner.XLM:
		return publicKey, nil
	default:
		return "", fmt.Errorf("cannot generate %s publicKey", string(bcType))
	}
}
