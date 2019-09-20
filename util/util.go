package util

import (
	"github.com/sirupsen/logrus"
	"io"
	"net"
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

// GetIPFromAddress returns net.IP from IP:PORT string
func GetIPFromAddress(addr string) net.IP {
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
