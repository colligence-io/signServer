unsigned char *TrustSigner_getWBInitializeData(char *app_id);
char *TrustSigner_getWBPublicKey(char *app_id, unsigned char *wb_data, int wb_data_len, char *coin_symbol, int hd_depth, int hd_change, int hd_index);
unsigned char *TrustSigner_getWBSignatureData(char *app_id, unsigned char *wb_data, int wb_data_len, char *coin_symbol, int hd_depth, int hd_change, int hd_index, char *hash_message, int hash_len);
//char *TrustSigner_getWBRecoveryData(char *app_id, unsigned char *wb_data, int wb_data_len, char *user_key, int user_key_len, char *server_key, int server_key_len);
//unsigned char *TrustSigner_setWBRecoveryData(char *app_id, char *user_key, int user_key_len, char *recovery_data, int recovery_data_len);
