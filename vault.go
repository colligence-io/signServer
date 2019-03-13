package main

import (
	"errors"
	vault "github.com/hashicorp/vault/api"
	"log"
	"time"
)

type vaultConfig struct {
	username string
	password string
	address  string
}

type vaultConnection struct {
	client *vault.Client
}

func connectVault() (vc *vaultConnection) {
	vaultConfig := vaultConfig{
		username: "signserver",
		password: "ss1234",
		address:  "http://127.0.0.1:8200",
	}

	client, e := vault.NewClient(&vault.Config{
		Address: vaultConfig.address,
	})
	checkAndDie(e)
	log.Println("Connected to vault :", vaultConfig.address)

	password := map[string]interface{}{"password": vaultConfig.password}

	userpassAuth, e := client.Logical().Write("auth/userpass/login/"+vaultConfig.username, password)
	checkAndDie(e)

	client.SetToken(userpassAuth.Auth.ClientToken)
	roleIDsecret, e := client.Logical().Read("auth/approle/role/" + vaultConfig.username + "/role-id")
	checkAndDie(e)

	roleID, found := roleIDsecret.Data["role_id"]
	if !found {
		checkAndDie(errors.New("role id check failed"))
	}

	secretIDsecret, e := client.Logical().Write("auth/approle/role/"+vaultConfig.username+"/secret-id", nil)
	checkAndDie(e)

	secretID, found := secretIDsecret.Data["secret_id"]
	if !found {
		checkAndDie(errors.New("role secret check failed"))
	}

	approleSecret := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}

	approleAuth, e := client.Logical().Write("auth/approle/login", approleSecret)
	checkAndDie(e)

	client.SetToken(approleAuth.Auth.ClientToken)

	return &vaultConnection{
		client: client,
	}
}

func (vc *vaultConnection) startAutoRenew() {
	// automatic renew
	go func() {
		for {
			secret, e := vc.client.Auth().Token().RenewSelf(0)
			if e != nil {
				log.Println("Vault token renewal failed", e)
				break
			}

			sleep := secret.Auth.LeaseDuration * 80 / 100

			vc.client.SetToken(secret.Auth.ClientToken)

			log.Printf("Vault token will be renewed in %d seconds\n", sleep)
			time.Sleep(time.Second * time.Duration(sleep))
		}
		log.Println("Try reconnect to vault")
		vc := connectVault()
		vc.startAutoRenew()
	}()
}
