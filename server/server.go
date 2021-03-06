package server

import "C"
import (
	"fmt"
	"github.com/colligence-io/signServer/config"
	"github.com/colligence-io/signServer/server/rr"
	"github.com/colligence-io/signServer/util"
	"github.com/colligence-io/signServer/vault"
	"github.com/colligence-io/signServer/whitebox"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/sirupsen/logrus"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"time"
)

var logger = logrus.WithField("module", "Server")

type Instance struct {
	config *config.Configuration
	vc     *vault.Client
	ks     *whitebox.KeyStore
}

func NewInstance(cfg *config.Configuration, vaultClient *vault.Client, keyStore *whitebox.KeyStore) *Instance {
	return &Instance{
		config: cfg,
		vc:     vaultClient,
		ks:     keyStore,
	}
}

func (instance *Instance) Launch(port int) {
	if !instance.vc.IsConnected() {
		instance.vc.Connect()
		instance.vc.StartAutoRenew()
	}

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)

	accessLogWriter := instance.config.Server.GetAccessLogWriter()

	if accessLogWriter != nil {
		r.Use(middleware.RequestLogger(&middleware.DefaultLogFormatter{Logger: log.New(accessLogWriter, "", log.LstdFlags), NoColor: false}))
	} else {
		r.Use(middleware.Logger)
	}
	r.Use(middleware.NoCache)
	r.Use(instance.dontPanic)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(middleware.SetHeader("Content-type", "application/json; charset=utf8"))

	authService := NewAuthService(instance)
	protectedService := NewProtectedService(instance, authService)

	// Public Group
	r.Group(func(r chi.Router) {
		r.Post("/introduce", authService.IntroduceHandler)
		r.Post("/answer", authService.AnswerHandler)
	})

	// Protected Group
	r.Group(func(r chi.Router) {
		r.Use(authService.JwtVerifier)
		r.Use(authService.JwtAuthenticator)

		r.Post("/knock", protectedService.KnockHandler)
		r.Post("/sign", protectedService.SignHandler)
		//
		//// FIXME : this should be sealed, dangerous to reveal
		//r.Get("/reload", protectedService.Reload)
	})

	instance.ks.Load()
	for _, _ksd := range instance.ks.GetKeyStoreListDescription() {
		logger.Info(_ksd)
	}

	logger.Info("SignServer ", instance.config.Server.BlockChainNetwork, " started : listen ", port)
	err := http.ListenAndServe(":"+strconv.Itoa(port), r)
	util.CheckAndDie(err)
}

// dontPanic
func (instance *Instance) dontPanic(next http.Handler) http.Handler {
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
