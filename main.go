package main

import (
	"fmt"
	"github.com/colligence-io/signServer/config"
	"github.com/colligence-io/signServer/util"
	"github.com/colligence-io/signServer/vault"
	"github.com/colligence-io/signServer/whitebox"
	"os"
	"strconv"
)

type Mode string

const (
	MODE_SERVER          Mode = "server"
	MODE_UNLOCK          Mode = "unlock"
	MODE_APPADD          Mode = "appadd"
	MODE_KEYPAIR_GEN     Mode = "kpgen"
	MODE_KEYPAIR_SHOW    Mode = "kpshow"
	MODE_KEYPAIR_LIST    Mode = "kplist"
	MODE_KEYPAIR_BACKUP  Mode = "kpbackup"
	MODE_KEYPAIR_RECOVER Mode = "kprecover"
)

var Modes = map[string]Mode{
	string(MODE_SERVER):          MODE_SERVER,
	string(MODE_UNLOCK):          MODE_UNLOCK,
	string(MODE_APPADD):          MODE_APPADD,
	string(MODE_KEYPAIR_GEN):     MODE_KEYPAIR_GEN,
	string(MODE_KEYPAIR_SHOW):    MODE_KEYPAIR_SHOW,
	string(MODE_KEYPAIR_LIST):    MODE_KEYPAIR_LIST,
	string(MODE_KEYPAIR_BACKUP):  MODE_KEYPAIR_BACKUP,
	string(MODE_KEYPAIR_RECOVER): MODE_KEYPAIR_RECOVER,
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	var mode Mode
	mode, found := Modes[os.Args[1]]
	if !found {
		usage()
	}

	if mode == MODE_SERVER || mode == MODE_UNLOCK {
		var port int
		if len(os.Args) > 2 {
			var err error
			port, err = strconv.Atoi(os.Args[2])
			if err != nil {
				usage()
			}
		} else {
			port = 3456
		}

		if mode == MODE_SERVER {
			startUnlockServer(port)
		} else { // unlock
			startUnlockClient(port)
		}
	} else {
		cfg, e := config.GetConfig(config.ReadKeyFromStdin())
		util.CheckAndDie(e)

		_, wbks := initModule(cfg)

		switch mode {
		case MODE_APPADD:
			if len(os.Args) < 4 {
				usage()
			}
			wbks.AddAppAuth(os.Args[2], os.Args[3])
		case MODE_KEYPAIR_GEN:
			if len(os.Args) < 4 {
				usage()
			}
			wbks.GenerateKeypair(os.Args[2], os.Args[3])
		case MODE_KEYPAIR_SHOW:
			if len(os.Args) < 3 {
				usage()
			}
			wbks.ShowKeypairInfo(os.Args[2])
		case MODE_KEYPAIR_LIST:
			wbks.Load()
			for _, _ksd := range wbks.GetKeyStoreListDescription() {
				fmt.Println(_ksd)
			}
		case MODE_KEYPAIR_BACKUP:
			if len(os.Args) < 3 {
				usage()
			}
			wbks.BackupKeyPair(os.Args[2])
		case MODE_KEYPAIR_RECOVER:
			if len(os.Args) < 3 {
				usage()
			}
			wbks.RecoverKeyPair(os.Args[2])
		default:
			usage()
		}
	}
}

func initModule(cfg *config.Configuration) (*vault.Client, *whitebox.KeyStore) {
	vc := vault.NewClient(cfg)
	wbks := whitebox.NewKeyStore(cfg, vc)
	return vc, wbks
}

func usage() {
	fmt.Printf("Usage : %s [mode] [option]\n\n", os.Args[0])
	fmt.Printf(" Server Administration\n")
	fmt.Printf(" server mode : %s %s [port]\n", os.Args[0], MODE_SERVER)
	fmt.Printf("    port : default 3456\n")
	fmt.Printf(" server unlock mode : %s %s [port]\n", os.Args[0], MODE_UNLOCK)
	fmt.Printf("    port : default 3456\n")
	fmt.Printf(" application add mode : %s %s [appName] [cidr]\n", os.Args[0], MODE_APPADD)
	fmt.Printf("    appName : application name\n")
	fmt.Printf("    cidr : application bind CIDR\n")
	fmt.Printf("\n KeyPair Administration\n")
	fmt.Printf(" generate mode : %s %s [kpID] [symbol]\n", os.Args[0], MODE_KEYPAIR_GEN)
	fmt.Printf("    kpID : keypair ID\n")
	fmt.Printf("    symbol : Blockchain symbol\n")
	fmt.Printf(" show mode : %s %s [kpID]\n", os.Args[0], MODE_KEYPAIR_SHOW)
	fmt.Printf("    kpID : keypair ID\n")
	fmt.Printf(" list mode : %s %s\n", os.Args[0], MODE_KEYPAIR_SHOW)
	fmt.Printf(" backup mode : %s %s [kpID]\n", os.Args[0], MODE_KEYPAIR_SHOW)
	fmt.Printf("    kpID : keypair ID\n")
	fmt.Printf(" recover mode : %s %s [filePath]\n", os.Args[0], MODE_KEYPAIR_SHOW)
	fmt.Printf("    filePath : recovery file path\n")

	os.Exit(-1)
}
