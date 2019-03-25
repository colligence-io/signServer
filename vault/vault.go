package vault

import (
	"errors"
	"github.com/colligence-io/signServer/config"
	"github.com/colligence-io/signServer/util"
	vault "github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	"time"
)

var logger = logrus.WithField("module", "VaultClient")

type _config struct {
	address  string
	username string
	password string
	appRole  string
}

type Client struct {
	config    *_config
	client    *vault.Client
	connected bool
	auth      *vault.SecretAuth
}

func NewClient(cfg *config.Configuration) *Client {
	return &Client{
		config: &_config{
			address:  cfg.Vault.Address,
			username: cfg.Vault.Username,
			password: cfg.Vault.Password,
			appRole:  cfg.Vault.AppRole,
		},
	}
}

func (vc *Client) Connect() {
	client, e := vault.NewClient(&vault.Config{
		Address: vc.config.address,
	})
	util.CheckAndPanic(e)

	logger.Info("Connected to vault : ", vc.config.address)

	password := map[string]interface{}{"password": vc.config.password}

	userpassAuth, e := client.Logical().Write("auth/userpass/login/"+vc.config.username, password)
	util.CheckAndPanic(e)

	client.SetToken(userpassAuth.Auth.ClientToken)
	roleIDsecret, e := client.Logical().Read("auth/approle/role/" + vc.config.appRole + "/role-id")
	util.CheckAndPanic(e)

	roleID, found := roleIDsecret.Data["role_id"]
	if !found {
		util.CheckAndPanic(errors.New("role id check failed"))
	}

	secretIDsecret, e := client.Logical().Write("auth/approle/role/"+vc.config.appRole+"/secret-id", nil)
	util.CheckAndPanic(e)

	secretID, found := secretIDsecret.Data["secret_id"]
	if !found {
		util.CheckAndPanic(errors.New("role secret check failed"))
	}

	approleSecret := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}

	approleAuth, e := client.Logical().Write("auth/approle/login", approleSecret)
	util.CheckAndPanic(e)

	vc.client = client
	vc.setAuth(approleAuth.Auth)
}

func (vc *Client) setAuth(auth *vault.SecretAuth) {
	vc.auth = auth
	vc.client.SetToken(auth.ClientToken)
	vc.connected = true
}

func (vc *Client) Logical() *vault.Logical {
	return vc.client.Logical()
}

func (vc *Client) IsConnected() bool {
	return vc.connected
}

func (vc *Client) StartAutoRenew() {
	// automatic renew
	go func() {
		for {
			sleep := vc.auth.LeaseDuration * 80 / 100
			logger.Debugf("Vault token will be renewed in %d seconds", sleep)
			time.Sleep(time.Second * time.Duration(sleep))

			newAppRoleAuth, e := vc.client.Auth().Token().RenewSelf(0)
			if e != nil {
				logger.Error("Vault token renewal failed ", e)

				// retry 5 times or die
				for i := 0; i < 6; i++ {
					func(vcr *Client) {
						defer func() {
							if r := recover(); r != nil {
								logger.Info("Wait 10 seconds for next reconnect trial...")
								time.Sleep(time.Second * 10)
							}
						}()
						logger.Info("Trying to reconnect, count = ", i+1)
						vcr.Connect()
					}(vc)
				}

				util.Die("Cannot connect vault, Shutdown.")
			} else {
				vc.setAuth(newAppRoleAuth.Auth)
			}

			// TODO : add WithCancel Context to graceful shutdown
		}
	}()
}
