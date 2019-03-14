package main

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

func closeOrDie(entity io.Closer) {
	checkAndDie(entity.Close())
}

func checkAndDie(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func readFromFile(path string) ([]byte, error) {
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

func encrypt(key []byte, plainText []byte) ([]byte, error) {
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

func decrypt(key []byte, cipherText []byte) ([]byte, error) {
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

func sha256Hash(appID string) []byte {
	hash := sha256.New()
	hash.Write([]byte(appID))
	return hash.Sum(nil)
}

func fileExists(name string) bool {
	_, err := os.Stat(name)
	return !os.IsNotExist(err)
}

func getIP(addr string) net.IP {
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
