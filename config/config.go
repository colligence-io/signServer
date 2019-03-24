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

func init() {
	if util.File.Exists(RAWCONFIGFILE) {
		fmt.Println("Initialize configuration")

		key := ReadKeyFromStdin()

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
}

func ReadKeyFromStdin() []byte {
	fmt.Print("Enter launching key : ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	key := scanner.Text()

	return util.Crypto.Sha256Hash(key)
}

func GetConfig(key []byte) (*Configuration, error) {
	if !util.File.Exists(CONFIGFILE) {
		util.Die("config not found")
	}

	cBytes, e := util.File.Read(CONFIGFILE)
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

	setLogger(&config.Log)

	return config, nil
}

func setLogger(cfg *LogConfig) {
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

func (cfg *LogConfig) GetAccessLogWriter() io.Writer {
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

func getLogPath(cfg *LogConfig) string {
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
