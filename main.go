package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/colligence-io/signServer/server"
	"github.com/colligence-io/signServer/util"
	"github.com/colligence-io/signServer/vault"
	"github.com/colligence-io/signServer/whitebox"
	"github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const CONFIGFILE = ".config"
const RAWCONFIGFILE = "config.json"
const RAWCONFIGFILEREMOVE = "config.json.REMOVE"

type Configuration struct {
	Log   LogConfig   `json:"log"`
	Auth  AuthConfig  `json:"auth"`
	Vault VaultConfig `json:"vault"`
}

type LogConfig struct {
	Path       string `json:"path"`
	AccessLog  string `json:"access"`
	ServiceLog string `json:"service"`
}

type AuthConfig struct {
	JwtSecret       string `json:"jwtSecret"`
	JwtExpires      int    `json:"jwtExpires"`
	QuestionExpires int    `json:"questionExpires"`
}

type VaultConfig struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	AppRole      string `json:"approle"`
	Address      string `json:"address"`
	WhiteBoxPath string `json:"whiteboxPath"`
	AuthPath     string `json:"authPath"`
}

func main() {
	var mode string

	config := getConfig()

	if len(os.Args) < 2 {
		usage()
	} else {
		mode = os.Args[1]
	}

	setLogger(config.Log)

	vc := vault.NewClient(vault.Config{
		Username: config.Vault.Username,
		Password: config.Vault.Password,
		AppRole:  config.Vault.AppRole,
		Address:  config.Vault.Address,
	})

	wbks := whitebox.NewKeyStore(whitebox.Config{
		AuthPath:     config.Vault.AuthPath,
		WhiteBoxPath: config.Vault.WhiteBoxPath,
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
			AccessLogWriter: getAccessLogWriter(config.Log),
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
	if util.File.Exists(RAWCONFIGFILE) {
		fmt.Println("Initialize configuration")
		fmt.Print("Enter new launching key : ")
		key := getLaunchingKey()
		rcBytes, e := util.File.Read(RAWCONFIGFILE)
		util.CheckAndDie(e)

		cBytes, e := util.Crypto.EncryptAES(key, rcBytes)
		util.CheckAndDie(e)

		if util.File.Exists(CONFIGFILE) {
			fmt.Println(CONFIGFILE, "found, overwrite.")
		}

		e = ioutil.WriteFile(CONFIGFILE, cBytes, 0600)
		util.CheckAndDie(e)

		e = os.Rename(RAWCONFIGFILE, RAWCONFIGFILEREMOVE)
		util.CheckAndDie(e)

		fmt.Println(CONFIGFILE, "created,", RAWCONFIGFILE, "renamed to", RAWCONFIGFILEREMOVE)
		os.Exit(0)
	}

	if !util.File.Exists(CONFIGFILE) {
		util.Die("config not found")
	}

	fmt.Print("Enter new launching key : ")
	key := getLaunchingKey()

	cBytes, e := util.File.Read(CONFIGFILE)
	util.CheckAndDie(e)

	cfg, e := util.Crypto.DecryptAES(key, cBytes)
	util.CheckAndDie(e)

	config := &Configuration{}

	e = json.Unmarshal(cfg, config)
	util.CheckAndDie(e)

	return config
}

func getLaunchingKey() []byte {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	key := scanner.Text()

	return util.Crypto.Sha256Hash(key)
}

func setLogger(cfg LogConfig) {
	logrus.SetOutput(os.Stdout)

	if cfg.ServiceLog != "" {
		path := getLogPath(cfg)
		if path != "" && cfg.ServiceLog != "" {
			if file, err := os.OpenFile(path+"/"+cfg.ServiceLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
				logrus.SetOutput(io.MultiWriter(file, os.Stdout))
			} else {
				logrus.Warn("Failed to open service log to file, using default stdout")
			}
		}
	}
}

func getAccessLogWriter(cfg LogConfig) io.Writer {
	if cfg.AccessLog != "" {
		path := getLogPath(cfg)
		if path != "" && cfg.AccessLog != "" {
			file, err := os.OpenFile(path+"/"+cfg.AccessLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
			if err == nil {
				return io.MultiWriter(file, os.Stdout)
			} else {
				logrus.Warn("Failed to open access log to file, using default stdout")
			}
		}
	}
	return nil
}

func getLogPath(cfg LogConfig) string {
	var path = cfg.Path

	if path == "" {
		path = "."
	}

	if !strings.HasPrefix(path, "/") {
		ex, err := os.Executable()
		util.CheckAndDie(err)

		path = filepath.Dir(ex) + "/" + path
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		err = os.Mkdir(path, 0755)
		if err != nil {
			logrus.Warn("Cannot make log directory")
			return ""
		}
	}

	return path
}
