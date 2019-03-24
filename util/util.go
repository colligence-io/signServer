package util

import (
	"github.com/sirupsen/logrus"
	"io"
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
		logrus.Fatalln(err)
	}
}

func CheckAndPanic(err error) {
	if err != nil {
		logrus.Panicln(err)
	}
}

func Die(message string) {
	logrus.Fatalln(message)
}
