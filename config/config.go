package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/colligence-io/signServer/util"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

var ROOTPATH = setEnv("TSS_PATH", ".")
var DOTCONFIGFILE = setEnv("TSS_CONFIGFILE", ROOTPATH+"/etc/.config")
var RAWCONFIGFILE = setEnv("TSS_RAWCONFIGFILE", ROOTPATH+"/etc/config.json")
var RAWCONFIGFILEREMOVE = setEnv("TSS_RAWCONFIGFILEREMOVE", ROOTPATH+"/etc/config.json.REMOVE")
var SECRETFILE = setEnv("TSS_SECRETFILE", "/run/secrets/tssLaunchingKey")

type Configuration struct {
	Server ServerConfig `json:"server"`
	Auth   AuthConfig   `json:"auth"`
	Vault  VaultConfig  `json:"vault"`
}

type ServerConfig struct {
	LogPath           string `json:"log_path"`
	LogAccess         string `json:"log_access"`
	LogService        string `json:"log_service"`
	BlockChainNetwork string `json:"bc_network"`
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

func setEnv(envName string, defaultValue string) string {
	if ev := os.Getenv(envName); ev != "" {
		return ev
	}
	return defaultValue
}

func init() {
	if util.File.Exists(RAWCONFIGFILE) {
		fmt.Println("Initialize configuration")

		key := ReadLaunchingKey()

		rcBytes, e := util.File.Read(RAWCONFIGFILE)
		util.CheckAndDie(e)

		cBytes, e := util.Crypto.EncryptAES(key, rcBytes)
		util.CheckAndDie(e)

		if util.File.Exists(DOTCONFIGFILE) {
			fmt.Println(DOTCONFIGFILE, "found, overwrite.")
		}

		e = ioutil.WriteFile(DOTCONFIGFILE, cBytes, 0600)
		util.CheckAndDie(e)

		e = os.Rename(RAWCONFIGFILE, RAWCONFIGFILEREMOVE)
		util.CheckAndDie(e)

		fmt.Println(DOTCONFIGFILE, "created,", RAWCONFIGFILE, "renamed to", RAWCONFIGFILEREMOVE)
		os.Exit(0)
	}
}

func ReadLaunchingKeyFromSecret() []byte {
	if util.File.Exists(SECRETFILE) {
		keyBytes, e := util.File.Read(SECRETFILE)
		util.CheckAndDie(e)
		fmt.Println("Secret initialized")

		keyString := strings.TrimRightFunc(string(keyBytes), func(c rune) bool {
			return c == '\r' || c == '\n'
		})

		return util.Crypto.Sha256Hash(keyString)
	} else {
		return nil
	}
}

func ReadLaunchingKey() []byte {
	keyBytes := ReadLaunchingKeyFromSecret()
	if keyBytes != nil {
		return keyBytes
	}

	fmt.Print("Enter launching key : ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	key := scanner.Text()

	return util.Crypto.Sha256Hash(key)
}

func GetConfig(key []byte) (*Configuration, error) {
	if !util.File.Exists(DOTCONFIGFILE) {
		util.Die("config not found")
	}

	cBytes, e := util.File.Read(DOTCONFIGFILE)
	if e != nil {
		return nil, e
	}

	cfg, e := util.Crypto.DecryptAES(key, cBytes)
	if e != nil {
		return nil, e
	}

	config := &Configuration{}

	e = json.Unmarshal(cfg, config)
	if e != nil {
		return nil, errors.New("incorrect unlock key")
	}

	setLogger(&config.Server)

	return config, nil
}

func setLogger(cfg *ServerConfig) {
	logrus.SetOutput(os.Stdout)

	if cfg.LogService != "" {
		path := getLogPath(cfg)
		if path != "" && cfg.LogService != "" {
			if file, err := os.OpenFile(path+"/"+cfg.LogService, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
				logrus.SetOutput(io.MultiWriter(file, os.Stdout))
			} else {
				logrus.Warn("Failed to open service log to file, using default stdout")
			}
		}
	}
}

func (cfg *ServerConfig) GetAccessLogWriter() io.Writer {
	if cfg.LogAccess != "" {
		path := getLogPath(cfg)
		if path != "" && cfg.LogAccess != "" {
			file, err := os.OpenFile(path+"/"+cfg.LogAccess, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
			if err == nil {
				return io.MultiWriter(file, os.Stdout)
			} else {
				logrus.Warn("Failed to open access log to file, using default stdout")
			}
		}
	}
	return nil
}

func getLogPath(cfg *ServerConfig) string {
	var path = cfg.LogPath

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
