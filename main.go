package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/colligence-io/signServer/server"
	"github.com/colligence-io/signServer/util"
	"github.com/colligence-io/signServer/vault"
	"github.com/colligence-io/signServer/whitebox"
	"io/ioutil"
	"log"
	"os"
	"strconv"
)

const CONFIGFILE = ".config"
const RAWCONFIGFILE = "config.json"
const RAWCONFIGFILEREMOVE = "config.json.REMOVE"

type Configuration struct {
	Auth  *AuthConfig  `json:"auth"`
	Vault *VaultConfig `json:"vault"`
}

type AuthConfig struct {
	JwtSecret       string `json:"jwtSecret"`
	JwtExpires      int    `json:"jwtExpires"`
	QuestionExpires int    `json:"questionExpires"`
}

type VaultConfig struct {
	Username         string `json:"username"`
	Password         string `json:"password"`
	Address          string `json:"address"`
	WhiteBoxPath     string `json:"whiteboxPath"`
	AuthPath         string `json:"authPath"`
	SecretKeymapPath string `json:"secretKeymapPath"`
}

func main() {
	var mode string

	config := getConfig()

	if len(os.Args) < 2 {
		usage()
	} else {
		mode = os.Args[1]
	}

	vc := vault.NewClient(vault.Config{
		Username: config.Vault.Username,
		Password: config.Vault.Password,
		Address:  config.Vault.Address,
	})

	wbks := whitebox.NewKeyStore(whitebox.Config{
		AuthPath:         config.Vault.AuthPath,
		SecretKeymapPath: config.Vault.SecretKeymapPath,
		WhiteBoxPath:     config.Vault.WhiteBoxPath,
	}, vc)

	switch mode {
	case "server":
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
		ss := server.NewInstance(server.Config{
			VaultAuthPath:   config.Vault.AuthPath,
			JwtSecret:       config.Auth.JwtSecret,
			JwtExpires:      config.Auth.JwtExpires,
			QuestionExpires: config.Auth.QuestionExpires,
		}, vc, wbks)
		ss.Launch(port)
	case "kpgen":
		if len(os.Args) < 4 {
			usage()
		}
		wbks.GenerateKeypair(os.Args[2], os.Args[3])
	case "kpshow":
		if len(os.Args) < 3 {
			usage()
		}
		wbks.ShowKeypairInfo(os.Args[2])
	case "addapp":
		if len(os.Args) < 4 {
			usage()
		}
		wbks.AddAppAuth(os.Args[2], os.Args[3])
	default:
		usage()
	}
}

func usage() {
	fmt.Printf("%s [server|kpgen|kpshow|addapp] [option]\n", os.Args[0])
	fmt.Printf(" server mode : %s server [port]\n", os.Args[0])
	fmt.Printf("    port : default 3456\n")
	fmt.Printf(" keypair generate mode : %s kpgen [kpID] [symbol]\n", os.Args[0])
	fmt.Printf("    kpID : keypair ID\n")
	fmt.Printf("    symbol : Blockchain symbol\n")
	fmt.Printf(" keypair show mode : %s kpshow [kpID]\n", os.Args[0])
	fmt.Printf("    kpID : keypair ID\n")
	fmt.Printf(" add application mode : %s addapp [appid] [cidr]\n", os.Args[0])
	fmt.Printf("    appid : application ID\n")
	fmt.Printf("    cidr : application bind CIDR\n")
	os.Exit(-1)
}

func getConfig() *Configuration {
	if util.FileExists(RAWCONFIGFILE) {
		fmt.Println("Initialize configuration")
		fmt.Print("Enter new launching key : ")
		key := getLaunchingKey()
		rcBytes, e := util.ReadFromFile(RAWCONFIGFILE)
		util.CheckAndDie(e)

		cBytes, e := util.Encrypt(key, rcBytes)
		util.CheckAndDie(e)

		if util.FileExists(CONFIGFILE) {
			fmt.Println(CONFIGFILE, "found, overwrite.")
		}

		e = ioutil.WriteFile(CONFIGFILE, cBytes, 0600)
		util.CheckAndDie(e)

		e = os.Rename(RAWCONFIGFILE, RAWCONFIGFILEREMOVE)
		util.CheckAndDie(e)

		fmt.Println(CONFIGFILE, "created,", RAWCONFIGFILE, "renamed to", RAWCONFIGFILEREMOVE)
		os.Exit(0)
	}

	if !util.FileExists(CONFIGFILE) {
		log.Fatalln("config not found")
	}

	fmt.Print("Enter new launching key : ")
	key := getLaunchingKey()

	cBytes, e := util.ReadFromFile(CONFIGFILE)
	util.CheckAndDie(e)

	cfg, e := util.Decrypt(key, cBytes)
	util.CheckAndDie(e)

	config := &Configuration{}

	e = json.Unmarshal(cfg, config)
	if e != nil {
		log.Fatalln("launching failed")
	}

	return config
}

func getLaunchingKey() []byte {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	key := scanner.Text()

	return util.Sha256Hash(key)
}
