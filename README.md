# signServer

Vault Config
<pre><code>
vault secrets enable -path=bcks kv

vault policy write signserver-bcks-policy -&lt&ltEOF
path "bcks/*" {
  capabilities = ["read", "update", "delete", "create", "list"]
}
EOF

vault write auth/approle/role/signserver secret_id_ttl=10s secret_id_num_uses=1 period=300s policies=signserver-bcks-policy

vault policy write signserver-keygen-policy -&lt&ltEOF
path "auth/approle/role/signserver/role-id" {
  capabilities = ["read"]
}
path "auth/approle/role/signserver/secret-id" {
  capabilities = ["read", "create", "update", "delete"]
}
EOF

vault write auth/userpass/users/signserver password=ss1234 policies=signserver-keygen-policy ttl="5s" max_ttl="5s"
</code></pre>
