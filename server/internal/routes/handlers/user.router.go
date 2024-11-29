package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
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

type Auth interface {
	InsertToken(guid, refreshToken, email string) error
	GetRefreshToken(data utils.Data) (string, error)
	GetAccessToken(data utils.Data) (string, error)
	GetToken(email string) (string, error)
	DeleteToken(Email string) error

	SelectUsers() ([]repository.User, error)
	Registration(user repository.User) (string, error)
	ExistsUser(email string) (bool, error)

	GetClaimField(tokenString, flag string) (string, error)
}

func GetUser(auth Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "Handler.Select.Users "

		users, err := auth.SelectUsers()
		if err != nil {
			log.Error("Failed to get users", op, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)
	}
}

func ReceiveTokens(auth Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "Handler.Receive.Tokens"
		log.Info("op", op)

		Email := r.URL.Query().Get("Email")
		if Email == "" {
			http.Error(w, "Email parameter is required", http.StatusBadRequest)
			return
		}

		exist, _ := auth.ExistsUser(Email)
		ip := r.RemoteAddr
		if exist && r.RequestURI != "/api/SignUp" {
			auth.DeleteToken(Email)
		}

		guid := uuid.NewString()
		data := resp.Data{Guid: guid, Email: Email, Ip: ip}
		refreshToken, err := auth.GetRefreshToken(data)
		if err != nil {
			log.Error("failed to generate refresh token: ", err)
			render.JSON(w, r, resp.Error("failed to generate refhresh token"))
			return
		}

		err = auth.InsertToken(guid, refreshToken, Email)
		if err != nil {
			log.Error("failed to add token ", err)
			render.JSON(w, r, resp.Error("failed to add token "))
			return
		}

		accessToken, err := auth.GetAccessToken(data)

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

func Registration(auth Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "Handler.Registration.Users"
		log.Info("op", op)

		var req Request
		if err := render.DecodeJSON(r.Body, &req); err != nil {
			log.Error("failed to decode request body", err)
			render.JSON(w, r, resp.Error("invalid request"))
			return
		}

		if err := validator.New().Struct(req); err != nil {
			validateErr := err.(validator.ValidationErrors)
			log.Error("invalid request", err)
			render.JSON(w, r, resp.ValidationError(validateErr))
			return
		}

		usr := repository.User{Email: req.Email, Password: req.Password}
		email, err := auth.Registration(usr)
		if errors.Is(err, repository.ErrExists) {
			log.Info("Email already exists: ", req.Email)
			render.JSON(w, r, resp.Error("Email already exists"))
			return
		}

		if err != nil {
			log.Error("failed to add user", err)
			render.JSON(w, r, resp.Error("failed to add user"))
			return
		}

		log.Info("user registered: ", email)

		query := r.URL.Query()
		query.Set("Email", req.Email)
		r.URL.RawQuery = query.Encode()
		ReceiveTokens(auth)(w, r)
	}
}

func SignIn(auth Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "Handler.Auth.Users"
		log.Info("op", op)

		var req Request
		if err := render.DecodeJSON(r.Body, &req); err != nil {
			log.Error("failed to decode request body", err)
			render.JSON(w, r, resp.Error("invalid request"))
			return
		}

		exist, _ := auth.ExistsUser(req.Email)
		if !exist {
			render.JSON(w, r, resp.Error("User does not exist"))
			return
		}

		query := r.URL.Query()
		query.Set("Email", req.Email)
		r.URL.RawQuery = query.Encode()
		ReceiveTokens(auth)(w, r)
	}
}

func setCookies(w http.ResponseWriter, refreshToken string, accessToken string, refreshTokenTTL time.Duration, accessTokenTTL time.Duration) {
	httpOnlyCookie := http.Cookie{
		Name:     "httpOnly_cookie",
		Value:    refreshToken,
		Expires:  time.Now().Add(refreshTokenTTL),
		Path:     "/api",
		HttpOnly: true,
	}
	http.SetCookie(w, &httpOnlyCookie)

	regularCookie := http.Cookie{
		Name:    "regular_cookie",
		Value:   accessToken,
		Expires: time.Now().Add(accessTokenTTL),
		Path:    "/api",
	}
	http.SetCookie(w, &regularCookie)
}

func checkIp(currentIP, IP string) bool {
	return currentIP == IP
}

func SendWarningEmail(email string) error {
	fmt.Println("В ваш аккаунт зашли с нового устройства")
	return nil
}
