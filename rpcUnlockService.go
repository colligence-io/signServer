package main

import (
	"fmt"
	"github.com/colligence-io/signServer/config"
	"github.com/colligence-io/signServer/server"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"strconv"
)

type UnlockServiceRPC struct {
	srv      *http.Server
	port     int
	cfg      *config.Configuration
	unlocked chan bool
	attempt  int
}

type UnlockRequest struct {
	UnlockKey []byte
}
type UnlockResponse struct {
	Message string
}

func (su *UnlockServiceRPC) Unlock(request UnlockRequest, response *UnlockResponse) error {
	su.attempt++
	log.Println("Incoming Unlock attempt", su.attempt)

	// try unlock configuration
	cfg, e := config.GetConfig(request.UnlockKey)
	if e != nil {
		log.Println("Unlock failed :", e)
		response.Message = "Unlock failed."

		if su.attempt >= 5 {
			defer func() {
				// send false to ack channel after 5 failed attempts
				su.unlocked <- false
			}()
		}
	} else {
		log.Println("Unlock succeed")
		response.Message = "OK"
		su.cfg = cfg

		defer func() {
			// send true to ack channel if unlocked
			su.unlocked <- true
		}()
	}

	return nil
}

func launchServer(cfg *config.Configuration, port int) {
	// start signServer
	log.Println("Launching SignServer")
	vc, wbks := initModule(cfg)
	ss := server.NewInstance(cfg, vc, wbks)
	ss.Launch(port)
}

func startServer(port int) {
	keyBytes := config.ReadLaunchingKeyFromSecret()
	if keyBytes != nil {
		cfg, e := config.GetConfig(keyBytes)
		if e != nil {
			log.Fatal("Unlock with secret failed :", e)
		}

		launchServer(cfg, port)
	} else {
		startUnlockServer(port)
	}
}

func startUnlockServer(port int) {
	su := &UnlockServiceRPC{
		port:     port,
		unlocked: make(chan bool),
		attempt:  0,
	}

	e := rpc.Register(su)
	if e != nil {
		log.Fatal("UnlockServiceRPC is not formed as rpc.", e)
	}

	// Register a HTTP handler
	rpc.HandleHTTP()

	// Listen to TPC connections on port 1234
	listener, e := net.Listen("tcp", ":"+strconv.Itoa(port))
	if e != nil {
		log.Fatal("Listen error: ", e)
	}
	log.Printf("Server is waiting for unlock on %d", port)

	// prepare shutdown ack channel
	var serverDown = make(chan bool)

	// GO (RPC server)
	go func() {
		srv := &http.Server{}
		su.srv = srv

		// Start accept incoming HTTP connections, this blocks further execution until srv shutdown
		// after shutdown e will be returned (mostly)
		// (**UNLOCK SERVICE RPC SERVER**)
		e = srv.Serve(listener)
		if e != nil {
			log.Println("Unlock Service down :", e)
		}

		// send unlock server shutdown finished ack
		serverDown <- true
	}()

	// waiting for unlocking
	if unlockSuccess := <-su.unlocked; !unlockSuccess {
		log.Fatalln("Unlocking SignServer is failed.")
	}

	// shutdown unlock service (Started at **UNLOCK SERVICE RPC SERVER**)
	log.Println("Shutting down Unlock Service")
	e = su.srv.Shutdown(nil)
	if e != nil {
		// die if shutdown failed
		log.Fatalln(e)
	}

	// waiting for unlock server shutdown finished ack
	<-serverDown

	launchServer(su.cfg, su.port)
}

func startUnlockClient(port int) {
	client, err := rpc.DialHTTP("tcp", "localhost:"+strconv.Itoa(port))
	if err != nil {
		log.Fatal("Connection error:", err)
	}
	defer func() {
		_ = client.Close()
	}()

	key := config.ReadLaunchingKey()
	var request = UnlockRequest{UnlockKey: key}
	var response UnlockResponse

	err = client.Call("UnlockServiceRPC.Unlock", request, &response)
	if err != nil {
		fmt.Println("Unlock Error :", err)
	} else {
		fmt.Println(response.Message)
	}
}
