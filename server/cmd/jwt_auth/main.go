package main

import (
	"net/http"
	"os"

	"jwt-auth/server/internal/config"
	"jwt-auth/server/internal/repository"
	"jwt-auth/server/internal/routes"
	"jwt-auth/server/internal/service"
	"jwt-auth/server/internal/utils"

	"github.com/go-chi/chi/v5"
	"github.com/sirupsen/logrus"
)

var log = logrus.New()

func main() {
	// TODO: init config

	cfg := config.MustLoad()

	// TODO: init storage

	storage, err := repository.InitDB(repository.Config(cfg.Storage))
	if err != nil {
		log.Error("failed to init storage", err)
		os.Exit(1)
	}

	log.Info("starting storage")

	// TODO: init router
	tokenManager, err := utils.NewToken(cfg.JWT_ACCESS_SECRET, cfg.JWT_REFRESH_SECRET)
	if err != nil {
		log.Error("failed to init auth: ", err)
		os.Exit(1)
	}

	service, _ := service.New(cfg, storage, tokenManager)
	router := chi.NewRouter()
	routes.RegisterUserRoutes(router, storage, service)

	// TODO: run server

	log.Info("starting server, address: http://", cfg.Address)

	srv := &http.Server{
		Addr:         cfg.Address,
		Handler:      router,
		ReadTimeout:  cfg.HTTPServer.Timeout,
		WriteTimeout: cfg.HTTPServer.Timeout,
		IdleTimeout:  cfg.HTTPServer.IdleTimeout,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal("failed to start server")
	}

	log.Info("server stopped")
}
