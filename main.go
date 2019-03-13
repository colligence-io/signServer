package main

import (
	"fmt"
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
		launchServer(port)
	case "kpgen":
		if len(os.Args) < 4 {
			usage()
		}

		generateKeypair(os.Args[2], os.Args[3])
	case "kpshow":
		if len(os.Args) < 3 {
			usage()
		}

		showKeypairInfo(os.Args[2])
	case "kpvaultconfig":
		printVaultConfig()
	default:
		usage()
	}
}

func usage() {
	fmt.Printf("%s [server|kpgen|kpshow|kpvaultconfig] [option]\n", os.Args[0])
	fmt.Printf(" server mode : %s server [port]\n", os.Args[0])
	fmt.Printf("    port : default 3456\n")
	fmt.Printf(" keypair generate mode : %s kpgen [kpID] [symbol]\n", os.Args[0])
	fmt.Printf("    kpID : keypair ID\n")
	fmt.Printf(" keypair show mode : %s kpshow [kpID]\n", os.Args[0])
	fmt.Printf("    kpID : keypair ID\n")
	fmt.Printf(" vaultConfig generate mode : %s kpvaultconfig\n", os.Args[0])
	os.Exit(-1)
}
