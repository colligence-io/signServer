package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
)

const CONFIGFILE = ".config"
const RAWCONFIGFILE = "config.json"
const RAWCONFIGFILEREMOVE = "config.json.REMOVE"

type ServerConfig struct {
	Auth  *AuthConfig  `json:"auth"`
	Vault *VaultConfig `json:"vault"`
}

type AuthConfig struct {
	JwtSecret string `json:"jwtSecret"`
}

type VaultConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Address  string `json:"address"`
}

var serverConfig = &ServerConfig{}

func main() {
	var mode string

	checkConfig()

	if len(os.Args) < 2 {
		usage()
	} else {
		mode = os.Args[1]
	}

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
		launchServer(port)
	case "kpgen":
		if len(os.Args) < 4 {
			usage()
		}

		generateKeypair(os.Args[2], os.Args[3])
	case "kpshow":
		if len(os.Args) < 3 {
			usage()
		}

		showKeypairInfo(os.Args[2])
	case "kpvaultconfig":
		printVaultConfig()
	default:
		usage()
	}
}

func usage() {
	fmt.Printf("%s [server|kpgen|kpshow|kpvaultconfig] [option]\n", os.Args[0])
	fmt.Printf(" server mode : %s server [port]\n", os.Args[0])
	fmt.Printf("    port : default 3456\n")
	fmt.Printf(" keypair generate mode : %s kpgen [kpID] [symbol]\n", os.Args[0])
	fmt.Printf("    kpID : keypair ID\n")
	fmt.Printf(" keypair show mode : %s kpshow [kpID]\n", os.Args[0])
	fmt.Printf("    kpID : keypair ID\n")
	fmt.Printf(" vaultConfig generate mode : %s kpvaultconfig\n", os.Args[0])
	os.Exit(-1)
}

func checkConfig() {
	if fileExists(RAWCONFIGFILE) {
		fmt.Println("Initialize configuration")
		fmt.Print("Enter new launching key : ")
		key := getLaunchingKey()
		rcBytes, e := readFromFile(RAWCONFIGFILE)
		checkAndDie(e)

		cBytes, e := encrypt(key, rcBytes)
		checkAndDie(e)

		if fileExists(CONFIGFILE) {
			fmt.Println(CONFIGFILE, "found, overwrite.")
		}

		e = ioutil.WriteFile(CONFIGFILE, cBytes, 0600)
		checkAndDie(e)

		e = os.Rename(RAWCONFIGFILE, RAWCONFIGFILEREMOVE)
		checkAndDie(e)

		fmt.Println(CONFIGFILE, "created,", RAWCONFIGFILE, "renamed to", RAWCONFIGFILEREMOVE)
		os.Exit(0)
	}

	if !fileExists(CONFIGFILE) {
		log.Fatalln("config not found")
	}

	fmt.Print("Enter new launching key : ")
	key := getLaunchingKey()

	cBytes, e := readFromFile(CONFIGFILE)
	checkAndDie(e)

	cfg, e := decrypt(key, cBytes)
	checkAndDie(e)

	e = json.Unmarshal(cfg, serverConfig)
	if e != nil {
		log.Fatalln("launching failed")
	}
}

func getLaunchingKey() []byte {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	key := scanner.Text()

	hash := sha256.New()
	hash.Write([]byte(key))
	sum := hash.Sum(nil)

	return sum
}
