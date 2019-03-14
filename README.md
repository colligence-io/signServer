# signServer

### Vault Config
<pre><code>
vault secrets enable -path=ss kv


vault policy write dedicated-signserver-policy -<<EOF
path "ss/*" {
  capabilities = ["read", "update", "delete", "create", "list"]
}
path "ss/auth/*" {
  capabilities = ["read", "update", "delete", "create", "list"]
}
path "ss/whitebox/*" {
  capabilities = ["read", "update", "delete", "create", "list"]
}
path "secret/credentials/signserver-keymap" {
  capabilities = ["read", "update", "delete", "create", "list"]
}
EOF



vault write auth/approle/role/signserver secret_id_ttl=10s secret_id_num_uses=1 period=300s policies=dedicated-signserver-policy


vault policy write dedicated-signserver-keygen-policy -<<EOF
path "auth/approle/role/signserver/role-id" {
  capabilities = ["read"]
}
path "auth/approle/role/signserver/secret-id" {
  capabilities = ["read", "create", "update", "delete"]
}
EOF


vault write auth/userpass/users/signserver password=ss1234 policies=dedicated-signserver-keygen-policy ttl="5s" max_ttl="5s"
</code></pre>


### Server Initialize
1. create config.json
    <pre><code>config.json
    
    {
      "auth": {
        "jwtSecret": "secret",
        "jwtExpires": 3600,
        "questionExpires": 10
      },
      "vault": {
        "username": "signserver",
        "password": "ss1234",
        "address": "http://127.0.0.1:8200",
        "whiteboxPath": "ss/whitebox",
        "authPath": "ss/auth",
        "secretKeymapPath": "secret/credentials/signserver-keymap"
      }
    }</code></pre>
2. run signServer
3. enter initial launching key
4. remove config.json.REMOVE
