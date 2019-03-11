package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
)

func main() {
	var mode string

	if len(os.Args) < 2 {
		usage()
	} else {
		mode = os.Args[1]
	}

	switch mode {
	case "server":
		var port int
		if len(os.Args) > 2 {
			var err error
			port, err = strconv.Atoi(os.Args[2])
			if err != nil {
				usage()
			}
		} else {
			port = 3456
		}
		initKeyStore()
		launchServer(port)
	case "kpgen":
		if len(os.Args) < 3 {
			usage()
		}

		generateKeypair(os.Args[2])
	default:
		usage()
	}
}

func usage() {
	fmt.Printf("%s [server|kpgen] [option]\n", os.Args[0])
	fmt.Printf(" server mode : %s server [port]\n", os.Args[0])
	fmt.Printf("    port : default 3456\n")
	fmt.Printf(" kpgen mode : %s kpgen [kpID]\n", os.Args[0])
	fmt.Printf("    kpID : keypair ID\n")
	os.Exit(-1)
}

func closeOrDie(entity io.Closer) {
	checkAndDie(entity.Close())
}

func checkAndDie(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
