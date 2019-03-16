package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

type cryptoUtil struct{}

// EncryptAES
// key must be 16, 24, 32 (for 128, 192, 256 each)
func (*cryptoUtil) EncryptAES(key []byte, plainText []byte) ([]byte, error) {
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))

	iv := cipherText[:aes.BlockSize]

	_, e = io.ReadFull(rand.Reader, iv)
	if e != nil {
		return nil, e
	}

	encrypter := cipher.NewCFBEncrypter(block, iv)
	encrypter.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	return cipherText, nil
}

// DecryptAES
// key must be 16, 24, 32 (for 128, 192, 256 each)
func (*cryptoUtil) DecryptAES(key []byte, cipherText []byte) ([]byte, error) {
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}

	if len(cipherText) < aes.BlockSize {
		return nil, errors.New("too short")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	decrypter := cipher.NewCFBDecrypter(block, iv)
	decrypter.XORKeyStream(cipherText, cipherText)

	return cipherText, nil
}

// Sha256Hash
// sha256 hash bytes for string
func (*cryptoUtil) Sha256Hash(appID string) []byte {
	hash := sha256.New()
	hash.Write([]byte(appID))
	return hash.Sum(nil)
}
