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
	MODE_SERVER      Mode = "server"
	MODE_UNLOCK      Mode = "unlock"
	MODE_KEYPAIRGEN  Mode = "kpgen"
	MODE_KEYPAIRSHOW Mode = "kpshow"
	MODE_KEYPAIRLIST Mode = "kplist"
	MODE_APPADD      Mode = "appadd"
)

var Modes = map[string]Mode{
	string(MODE_SERVER):      MODE_SERVER,
	string(MODE_UNLOCK):      MODE_UNLOCK,
	string(MODE_KEYPAIRGEN):  MODE_KEYPAIRGEN,
	string(MODE_KEYPAIRSHOW): MODE_KEYPAIRSHOW,
	string(MODE_KEYPAIRLIST): MODE_KEYPAIRLIST,
	string(MODE_APPADD):      MODE_APPADD,
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
		case MODE_KEYPAIRGEN:
			if len(os.Args) < 4 {
				usage()
			}
			wbks.GenerateKeypair(os.Args[2], os.Args[3])
		case MODE_KEYPAIRSHOW:
			if len(os.Args) < 3 {
				usage()
			}
			wbks.ShowKeypairInfo(os.Args[2])
		case MODE_APPADD:
			if len(os.Args) < 4 {
				usage()
			}
			wbks.AddAppAuth(os.Args[2], os.Args[3])
		case MODE_KEYPAIRLIST:
			wbks.Load()
			for _, _ksd := range wbks.GetKeyStoreListDescription() {
				fmt.Println(_ksd)
			}
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
	fmt.Printf(" server mode : %s %s [port]\n", os.Args[0], MODE_SERVER)
	fmt.Printf("    port : default 3456\n")
	fmt.Printf(" server unlock mode : %s %s [port]\n", os.Args[0], MODE_UNLOCK)
	fmt.Printf("    port : default 3456\n\n")
	fmt.Printf(" keypair generate mode : %s %s [kpID] [symbol]\n", os.Args[0], MODE_KEYPAIRGEN)
	fmt.Printf("    kpID : keypair ID\n")
	fmt.Printf("    symbol : Blockchain symbol\n")
	fmt.Printf(" keypair show mode : %s %s [kpID]\n", os.Args[0], MODE_KEYPAIRSHOW)
	fmt.Printf("    kpID : keypair ID\n\n")
	fmt.Printf(" application add mode : %s %s [appName] [cidr]\n", os.Args[0], MODE_APPADD)
	fmt.Printf("    appName : application name\n")
	fmt.Printf("    cidr : application bind CIDR\n")
	os.Exit(-1)
}
