package util

import (
	"io"
	"log"
)

var (
	Crypto = &cryptoUtil{}
	File   = &fileUtil{}
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
