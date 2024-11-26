package routes

import (
	"fmt"
	"net/http"

	"jwt-auth/server/internal/repository"
	"jwt-auth/server/internal/utils/handlers"

	"github.com/go-chi/chi/v5"
)

var RegisterUserRoutes = func(router *chi.Mux, storage *repository.Storage) {
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, you've requested: %s\n", r.URL.Path)
	})

	router.Get("/user", handlers.GetUser(storage))
}
