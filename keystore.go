package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"github.com/colligence-io/signServer/trustSigner"
	_ "github.com/mattn/go-sqlite3"
	"log"
)

/* appID - WhiteBox map */
var wbStore map[string]*trustSigner.WhiteBox

/* BCType - PublicKey - WhiteBox map */
var keyStore map[trustSigner.BlockChainType]map[string]*trustSigner.WhiteBox

func getDB() *sql.DB {
	db, err := sql.Open("sqlite3", "./.keyStore")
	checkAndDie(err)

	sqlStmt := `create table if not exists kp (id char(64) not null primary key, appID varchar(128) not null, wbData blob not null);`

	_, err = db.Exec(sqlStmt)
	checkAndDie(err)

	return db
}

func initKeyStore() {
	wbStore = make(map[string]*trustSigner.WhiteBox)
	keyStore = make(map[trustSigner.BlockChainType]map[string]*trustSigner.WhiteBox)

	for _, v := range trustSigner.BCTypes {
		keyStore[v] = make(map[string]*trustSigner.WhiteBox)
	}

	db := getDB()
	rows, err := db.Query("select id, appID, wbData from kp;")
	checkAndDie(err)
	defer closeOrDie(rows)

	for rows.Next() {
		var id string
		var appID string
		var wbBytes []byte

		err = rows.Scan(&id, &appID, &wbBytes)
		checkAndDie(err)

		wb := trustSigner.ConvertToWhiteBox(appID, &wbBytes)

		wbStore[appID] = wb

		log.Printf("%s : %s\n", appID, id)

		for _, bcType := range trustSigner.BCTypes {
			key := trustSigner.GetWBPublicKey(wb, bcType)
			keyStore[bcType][key] = wb

			log.Printf(" %s : %s\n", string(bcType), key)
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
	db := getDB()
	defer closeOrDie(db)

	tx, err := db.Begin()
	checkAndDie(err)

	wbBytes := trustSigner.GetWBInitializeData(appID)

	hash := sha256.New()
	hash.Write([]byte(appID))
	dataID := hex.EncodeToString(hash.Sum(nil))

	stmt, err := tx.Prepare("insert into kp (id, appID, wbData) values (?,?,?)")
	checkAndDie(err)

	defer closeOrDie(stmt)

	_, err = stmt.Exec(dataID, appID, &wbBytes)
	checkAndDie(err)

	err = tx.Commit()
	checkAndDie(err)

	//box := trustSigner.ConvertToWhiteBox(appID, &wbBytes)
	//log.Printf("BTC %s",trustSigner.GetWBPublicKey(box, trustSigner.BTC))
	//log.Printf("ETH %s",trustSigner.GetWBPublicKey(box, trustSigner.ETH))
	//log.Printf("XLM %s",trustSigner.GetWBPublicKey(box, trustSigner.XLM))
}
