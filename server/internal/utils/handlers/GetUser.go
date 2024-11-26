package handlers

import (
	"encoding/json"
	"jwt-auth/server/internal/repository"
	"net/http"

	"github.com/sirupsen/logrus"
)

var log = logrus.New()

type UserGetter interface {
	Select() ([]repository.User, error)
}

func GetUser(user UserGetter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		users, err := user.Select()
		if err != nil {
			log.Error("Failed to get users", err)
			return
		}
		log.Info(users)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)
	}
}
