package main

import (
	"fmt"
	"net/http"

	"jwt-auth/server/internal/config"

	"github.com/go-chi/chi/v5"
	"github.com/sirupsen/logrus"
)

var log = logrus.New()

func main() {
	// TODO: init config

	cfg := config.MustLoad()

	// TODO: init storage

	// TODO: init router

	router := chi.NewRouter()
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, you've requested: %s\n", r.URL.Path)
	})
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
