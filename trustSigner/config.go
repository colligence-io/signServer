package trustSigner

import (
	"bytes"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/colligence-io/signServer/hd"
	"github.com/ethereum/go-ethereum/crypto"
)

type BlockChainType string

const (
	BTC BlockChainType = "BTC"
	ETH BlockChainType = "ETH"
	XLM BlockChainType = "XLM"
)

var BCTypes = map[string]BlockChainType{
	string(BTC): BTC,
	string(ETH): ETH,
	string(XLM): XLM,
}

var bcConfig = map[BlockChainType]struct {
	PublicKeyLength int
	SignatureLength int
	HDDepth         int
	Address         func(publicKey string) (string, error)
}{
	BTC: {
		PublicKeyLength: 111,
		SignatureLength: 65,
		HDDepth:         5,
		Address: func(publicKey string) (string, error) {
			wallet, err := hd.FromBIP32ExtendedKey(publicKey)
			if err != nil {
				return "", nil
			}

			var netParam *chaincfg.Params
			if bytes.Compare(wallet.Vbytes[:], chaincfg.TestNet3Params.HDPublicKeyID[:]) == 0 || bytes.Compare(wallet.Vbytes[:], chaincfg.TestNet3Params.HDPrivateKeyID[:]) == 0 {
				netParam = &chaincfg.TestNet3Params
			} else {
				netParam = &chaincfg.MainNetParams
			}

			address, err := btcutil.NewAddressPubKey(wallet.Key, netParam)
			if err != nil {
				return "", err
			} else {
				return address.EncodeAddress(), nil
			}
		},
	},
	ETH: {
		PublicKeyLength: 111,
		SignatureLength: 65,
		HDDepth:         5,
		Address: func(publicKey string) (string, error) {
			wallet, err := hd.FromBIP32ExtendedKey(publicKey)
			if err != nil {
				return "", err
			}

			key, err := crypto.DecompressPubkey(wallet.Key)

			if err != nil {
				return "", err
			}

			return crypto.PubkeyToAddress(*key).Hex(), nil
		},
	},
	XLM: {
		PublicKeyLength: 56,
		SignatureLength: 64,
		HDDepth:         3,
		Address: func(publicKey string) (string, error) {
			return publicKey, nil
		},
	},
}
