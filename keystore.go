package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/colligence-io/signServer/trustSigner"
	_ "github.com/mattn/go-sqlite3"
	"log"
)

type addressAndWhiteBox struct {
	Address  string
	WhiteBox *trustSigner.WhiteBox
}

/* KeyID - BlockChainType - addressAndWhiteBox map */
var keyStore map[string]map[trustSigner.BlockChainType]addressAndWhiteBox

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

	keyStore = make(map[string]map[trustSigner.BlockChainType]addressAndWhiteBox)

	db := openDB()
	defer closeOrDie(db)

	rows, err := db.Query("select id, appID, wbData from kp;")
	defer closeOrDie(rows)
	checkAndDie(err)

	for rows.Next() {
		var keyID string
		var appID string
		var wbBytes []byte

		err = rows.Scan(&keyID, &appID, &wbBytes)
		checkAndDie(err)

		wb := trustSigner.ConvertToWhiteBox(appID, wbBytes)

		keyStore[keyID] = make(map[trustSigner.BlockChainType]addressAndWhiteBox)

		log.Printf("%s : %s\n", appID, keyID)

		for _, bcType := range trustSigner.BCTypes {
			key := trustSigner.GetWBPublicKey(wb, bcType)
			checkAndDie(err)

			address, err := trustSigner.DeriveAddress(bcType, key)
			checkAndDie(err)

			keyStore[keyID][bcType] = addressAndWhiteBox{address, wb}

			log.Printf(" %s : %s\n", string(bcType), address)
		}
	}
}

func getWhiteBoxData(keyID string, bcType trustSigner.BlockChainType) (*trustSigner.WhiteBox, error) {
	if wbData, found := keyStore[keyID][bcType]; found {
		return wbData.WhiteBox, nil
	} else {
		return nil, fmt.Errorf("%s %s not found on keyStore", string(bcType), keyID)
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

		address, err := trustSigner.DeriveAddress(bcType, key)
		checkAndDie(err)

		fmt.Printf("   Address :  %s\n", address)
	}
}

func printVaultConfig() {
	initKeyStore()

	var result map[string]string
	result = make(map[string]string)

	for keyID, map2 := range keyStore {
		for bcType, anwb := range map2 {
			result[string(bcType)+":"+anwb.Address] = keyID
		}
	}

	rb, err := json.MarshalIndent(result, "", "  ")
	checkAndDie(err)

	fmt.Println("VaultConfig data")
	fmt.Printf("\"signserver\": %s", string(rb))
}
