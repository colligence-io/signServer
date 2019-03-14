package main

import "C"
import (
	"fmt"
	"github.com/colligence-io/signServer/rr"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/jwtauth"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"time"
)

func launchServer(port int) {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.NoCache)
	r.Use(dontPanic)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(middleware.SetHeader("Content-type", "application/json; charset=utf8"))

	authService := &AuthService{}
	authService.Initialize()
	protectedService := &ProtectedService{authService}
	protectedService.Initialize()

	// Public Group
	r.Group(func(r chi.Router) {
		r.Post("/introduce", authService.Introduce())
		r.Post("/answer", authService.Answer())
	})

	// Protected Group
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(authService.TokenAuth))
		r.Use(authService.JwtAuthenticator)

		r.Post("/knock", protectedService.Knock())
		r.Post("/sign", protectedService.Sign())

		// FIXME : this should be sealed, dangerous to reveal
		r.Get("/reload", protectedService.Reload())
	})

	initKeyStore()
	logKeyStore()

	log.Printf("SignServer started : listen %d", port)
	err := http.ListenAndServe(":"+strconv.Itoa(port), r)
	checkAndDie(err)
}

// logKeyStore
func logKeyStore() {
	for keyID, kp := range keyStore {
		log.Println("KeyPair", C.GoString((*C.char)(kp.whiteBox.AppID)), ":", keyID, kp.bcType, kp.address)
	}
}

// dontPanic
func dontPanic(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rvr := recover(); rvr != nil {
				logEntry := middleware.GetLogEntry(r)
				if logEntry != nil {
					logEntry.Panic(rvr, debug.Stack())
				} else {
					_, _ = fmt.Fprintf(os.Stderr, "Panic: %+v\n", rvr)
					debug.PrintStack()
				}

				rr.WriteResponseEntity(w, rr.InternalServerErrorResponse)
			}
		}()

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}
