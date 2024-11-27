package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"github.com/sirupsen/logrus"

	"jwt-auth/server/internal/repository"
	resp "jwt-auth/server/internal/utils"
)

var log = logrus.New()

type Request struct {
	Email    string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type Response struct {
	resp.Response
}

type IUser interface {
	Select() ([]repository.User, error)
	Registration(user repository.User) (string, error)
}

func GetUser(user IUser) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "Handler.Select.Users "

		users, err := user.Select()
		if err != nil {
			log.Error("Failed to get users", op, err)
			return
		}
		log.Info(users)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)
	}
}

func Registration(user IUser) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "Handler.Registration.Users"

		log.Info("op", op)
		var req Request
		err := render.DecodeJSON(r.Body, &req)

		if errors.Is(err, io.EOF) {
			log.Error("request body is empty")
			render.JSON(w, r, resp.Error("empty request"))
			return
		}

		if err != nil {
			log.Error("failed to decode request body", err)
			render.JSON(w, r, resp.Error("failed to decode request"))
			return
		}

		log.Info("request body decoded ", req)

		if err := validator.New().Struct(req); err != nil {
			validateErr := err.(validator.ValidationErrors)
			log.Error("invalid request", err)
			render.JSON(w, r, resp.ValidationError(validateErr))
			return
		}

		usr := repository.User{Email: req.Email, Password: req.Password}
		email, err := user.Registration(usr)

		if errors.Is(err, repository.ErrExists) {
			log.Info("Email already exists: ", req.Email)
			render.JSON(w, r, resp.Error("Email already exists"))
			return
		}

		if err != nil {
			log.Error("failed to add user ", err)
			render.JSON(w, r, resp.Error("failed to add user "))
			return
		}
		log.Info("user added, Email", email)

		responseOK(w, r)
	}
}

func responseOK(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, Response{
		Response: resp.OK(),
	})
}
