package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
)

func CloseOrDie(entity io.Closer) {
	CheckAndDie(entity.Close())
}

func CheckAndDie(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func CheckAndPanic(err error) {
	if err != nil {
		log.Panicln(err)
	}
}

func ReadFromFile(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}

	bytes, e := ioutil.ReadAll(f)
	if e != nil {
		_ = f.Close()
		return nil, e
	}

	return bytes, nil
}

func Encrypt(key []byte, plainText []byte) ([]byte, error) {
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

func Decrypt(key []byte, cipherText []byte) ([]byte, error) {
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

func Sha256Hash(appID string) []byte {
	hash := sha256.New()
	hash.Write([]byte(appID))
	return hash.Sum(nil)
}

func FileExists(name string) bool {
	_, err := os.Stat(name)
	return !os.IsNotExist(err)
}

func GetIP(addr string) net.IP {
	host, _, e := net.SplitHostPort(addr)
	if e != nil {
		return nil
	}
	if host != "" {
		return net.ParseIP(host)
	} else {
		return net.ParseIP(addr)
	}
}
