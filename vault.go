package main

import (
	"errors"
	vault "github.com/hashicorp/vault/api"
	"log"
	"time"
)

type vaultConnection struct {
	client *vault.Client
}

func connectVault() (vc *vaultConnection) {
	vaultConfig := serverConfig.Vault

	client, e := vault.NewClient(&vault.Config{
		Address: vaultConfig.Address,
	})
	checkAndDie(e)
	log.Println("Connected to vault :", vaultConfig.Address)

	password := map[string]interface{}{"password": vaultConfig.Password}

	userpassAuth, e := client.Logical().Write("auth/userpass/login/"+vaultConfig.Username, password)
	checkAndDie(e)

	client.SetToken(userpassAuth.Auth.ClientToken)
	roleIDsecret, e := client.Logical().Read("auth/approle/role/" + vaultConfig.Username + "/role-id")
	checkAndDie(e)

	roleID, found := roleIDsecret.Data["role_id"]
	if !found {
		checkAndDie(errors.New("role id check failed"))
	}

	secretIDsecret, e := client.Logical().Write("auth/approle/role/"+vaultConfig.Username+"/secret-id", nil)
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
		vks = connectVault()
		vks.startAutoRenew()
	}()
}
