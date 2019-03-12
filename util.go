package main

import (
	"io"
	"log"
)

func closeOrDie(entity io.Closer) {
	checkAndDie(entity.Close())
}

func checkAndDie(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
