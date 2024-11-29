package routes

import (
	"fmt"
	"net/http"

	"jwt-auth/server/internal/repository"
	"jwt-auth/server/internal/routes/handlers"
	"jwt-auth/server/internal/service"

	"github.com/go-chi/chi/v5"
)

var RegisterUserRoutes = func(router *chi.Mux, storage *repository.Storage, service *service.Auth) {
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, you've requested: %s\n", r.URL.Path)
	})

	router.Get("/user", handlers.GetUser(service))

	router.Route("/api", func(r chi.Router) {
		r.Post("/SignUp", handlers.Registration(service))
		r.Post("/Auth", handlers.SignIn(service))
		r.Post("/Recieve", handlers.ReceiveTokens(service))
	})

}
