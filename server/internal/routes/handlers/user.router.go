package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"github.com/sirupsen/logrus"

	"jwt-auth/server/internal/config"
	"jwt-auth/server/internal/repository"
	"jwt-auth/server/internal/utils"
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

type Auth interface {
	InsertToken(refreshToken string, email string) error
	GetRefreshToken(data utils.Data) (string, error)
	GetAccessToken(data utils.Data) (string, error)
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

func Registration(user IUser, auth Auth) http.HandlerFunc {
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

		ip := r.RemoteAddr
		refreshToken, err := auth.GetRefreshToken(resp.Data{
			Email: req.Email,
			Ip:    ip,
		})
		if err != nil {
			log.Error("failed to generate refresh token: ", err)
			render.JSON(w, r, resp.Error("failed to generate refhresh token"))
			return
		}
		accessToken, err := auth.GetRefreshToken(resp.Data{
			Email: req.Email,
			Ip:    ip,
		})

		if err != nil {
			log.Error("failed to generate access token: ", err)
			render.JSON(w, r, resp.Error("failed to generate access token"))
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
		log.Info("user added, Email: ", email)

		err = auth.InsertToken(refreshToken, email)
		if err != nil {
			log.Error("failed to add token ", err)
			render.JSON(w, r, resp.Error("failed to add token "))
			return
		}

		render.JSON(w, r, map[string]interface{}{
			"status":        "success",
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
	}
}

func SignIn(auth Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "Handler.Auth.Users"

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

		ip := r.RemoteAddr
		refreshToken, err := auth.GetRefreshToken(resp.Data{
			Email: req.Email,
			Ip:    ip,
		})
		if err != nil {
			log.Error("failed to generate refresh token: ", err)
			render.JSON(w, r, resp.Error("failed to generate refhresh token"))
			return
		}

		err = auth.InsertToken(refreshToken, req.Email)
		if err != nil {
			log.Error("failed to add token ", err)
			render.JSON(w, r, resp.Error("failed to add token "))
			return
		}

		accessToken, err := auth.GetRefreshToken(resp.Data{
			Email: req.Email,
			Ip:    ip,
		})

		if err != nil {
			log.Error("failed to generate access token: ", err)
			render.JSON(w, r, resp.Error("failed to generate access token"))
			return
		}
		cfg := config.MustLoad()

		setCookies(w, refreshToken, accessToken, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)

		render.JSON(w, r, map[string]interface{}{
			"status":        "success",
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
	}
}

func setCookies(w http.ResponseWriter, refreshToken string, accessToken string, refreshTokenTTL time.Duration, accessTokenTTL time.Duration) {
	httpOnlyCookie := http.Cookie{
		Name:     "httpOnly_cookie",
		Value:    refreshToken,
		Expires:  time.Now().Add(refreshTokenTTL),
		Path:     "/api/auth",
		HttpOnly: true,
	}
	http.SetCookie(w, &httpOnlyCookie)

	regularCookie := http.Cookie{
		Name:    "regular_cookie",
		Value:   accessToken,
		Expires: time.Now().Add(accessTokenTTL),
		Path:    "/api/auth",
	}
	http.SetCookie(w, &regularCookie)
}
