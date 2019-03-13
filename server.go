package main

import "C"
import (
	"github.com/colligence-io/signServer/rr"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"log"
	"net/http"
	"strconv"
	"time"
)

func launchServer(port int) {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.NoCache)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(middleware.SetHeader("Content-type", "application/json; charset=utf8"))

	log.Printf("SignServer started : listen %d", port)

	r.Post("/sign", rr.WrapHandler(signHandler))
	r.Get("/reload", rr.WrapHandler(reloadHandler))

	initKeyStore()
	logKeyStore()

	err := http.ListenAndServe(":"+strconv.Itoa(port), r)
	checkAndDie(err)
}

func logKeyStore() {
	for keyID, kp := range keyStore {
		log.Println("KeyPair", C.GoString((*C.char)(kp.WhiteBox.AppID)), ":", keyID, kp.BcType, kp.Address)
	}
}
