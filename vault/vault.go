package vault

import (
	"errors"
	vault "github.com/hashicorp/vault/api"
	"log"
	"time"
)

type Config struct {
	Username string
	Password string
	AppRole  string
	Address  string
}

type Client struct {
	config    *Config
	client    *vault.Client
	connected bool
	auth      *vault.SecretAuth
}

func NewClient(config Config) *Client {
	return &Client{config: &config}
}

func (vc *Client) Connect() {
	client, e := vault.NewClient(&vault.Config{
		Address: vc.config.Address,
	})
	checkAndPanic(e)

	log.Println("Connected to vault :", vc.config.Address)

	password := map[string]interface{}{"password": vc.config.Password}

	userpassAuth, e := client.Logical().Write("auth/userpass/login/"+vc.config.Username, password)
	checkAndPanic(e)

	client.SetToken(userpassAuth.Auth.ClientToken)
	roleIDsecret, e := client.Logical().Read("auth/approle/role/" + vc.config.AppRole + "/role-id")
	checkAndPanic(e)

	roleID, found := roleIDsecret.Data["role_id"]
	if !found {
		checkAndPanic(errors.New("role id check failed"))
	}

	secretIDsecret, e := client.Logical().Write("auth/approle/role/"+vc.config.AppRole+"/secret-id", nil)
	checkAndPanic(e)

	secretID, found := secretIDsecret.Data["secret_id"]
	if !found {
		checkAndPanic(errors.New("role secret check failed"))
	}

	approleSecret := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}

	approleAuth, e := client.Logical().Write("auth/approle/login", approleSecret)
	checkAndPanic(e)

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
			log.Printf("Vault token will be renewed in %d seconds\n", sleep)
			time.Sleep(time.Second * time.Duration(sleep))

			newAppRoleAuth, e := vc.client.Auth().Token().RenewSelf(0)
			if e != nil {
				log.Println("Vault token renewal failed", e)

				// retry 5 times or die
				for i := 0; i < 6; i++ {
					func(vcr *Client) {
						defer func() {
							if r := recover(); r != nil {
								log.Println("Wait 10 seconds for next reconnect trial...")
								time.Sleep(time.Second * 10)
							}
						}()
						log.Println("Trying to reconnect, count =", i+1)
						vcr.Connect()
					}(vc)
				}

				log.Fatalln("Cannot connect vault, Shutdown.")
			} else {
				vc.setAuth(newAppRoleAuth.Auth)
			}
		}
	}()
}

func checkAndPanic(err error) {
	if err != nil {
		log.Panicln(err)
	}
}
