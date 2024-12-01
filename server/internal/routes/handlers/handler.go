package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt"
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
	GetToken(GUID string) (string, error)
	DeleteToken(Email string) error

	SelectUsers() ([]repository.User, error)
	Registration(user repository.User) (string, error)
	ExistsUser(email string) (bool, error)

	GetClaimField(tokenString string) (jwt.MapClaims, error)
	CompareTokens(providedToken string, hashedToken string) bool
	ValidToken(refreshToken string, rtClaims jwt.MapClaims) bool
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
			log.Error("Email parameter is required")
			render.JSON(w, r, resp.Error("Email parameter is required"))
			return
		}

		exist, _ := auth.ExistsUser(Email)
		ip := r.RemoteAddr
		if exist && r.RequestURI != "/api/SignUp" {
			auth.DeleteToken(Email)
		} else {
			log.Error("Email parameter is required")
			render.JSON(w, r, resp.Error("Email parameter is required"))
			return
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

func RefreshTokens(auth Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "Handler.Refresh.Tokens"
		log.Info("op", op)

		refreshToken := r.URL.Query().Get("RefreshToken")
		if refreshToken == "" {
			log.Error("RefreshToken parameter is required")
			render.JSON(w, r, resp.Error("RefreshToken parameter is required"))
			return
		}

		rtClaims, err := auth.GetClaimField(refreshToken)
		if err != nil {
			log.Error("Failed to get Claim")
			render.JSON(w, r, resp.Error("Failed to get Claim"))
			return
		}

		accessToken, err := r.Cookie("regular_cookie")
		if err != nil {
			log.Error("Failed to get regular_cookie")
			render.JSON(w, r, resp.Error("Failed to get cookie"))
			return
		}

		atClaims, err := auth.GetClaimField(accessToken.Value)
		if err != nil {
			log.Error("Failed to get Claim")
			render.JSON(w, r, resp.Error("Failed to get Claim"))
			return
		}

		// Насколько я понял, regresh token должен быть привязан к клиенту,
		// но не к access токену, так что странно так делать,
		// тем более что куки умирают в то же время, что и токены
		if rtClaims["GUID"] != atClaims["GUID"] {
			log.Error("Токены должны быть обоюдно связаны")
			render.JSON(w, r, resp.Error("Токены должны быть обоюдно связаны"))
			return
		}

		Subject := fmt.Sprintf("%s", rtClaims["sub"])
		ip := strings.Fields(Subject)[1]
		Email := strings.Fields(Subject)[0]
		if ip != r.RemoteAddr {
			log.Warning("В аккаунт вошли с неизвестного устройства")
			SendWarningEmail(Email)
		}

		if ok := auth.ValidToken(refreshToken, rtClaims); !ok {
			log.Error("Токен не прошёл валидацию")
			render.JSON(w, r, resp.Error("Токен не прошёл валидацию"))
			return
		}

		query := r.URL.Query()
		query.Set("Email", Email)
		r.URL.RawQuery = query.Encode()
		ReceiveTokens(auth)(w, r)
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
		Expires:  time.Now().Add(refreshTokenTTL * 2),
		Path:     "/api",
		HttpOnly: true,
	}
	http.SetCookie(w, &httpOnlyCookie)

	regularCookie := http.Cookie{
		Name:    "regular_cookie",
		Value:   accessToken,
		Expires: time.Now().Add(accessTokenTTL * 2),
		Path:    "/api",
	}
	http.SetCookie(w, &regularCookie)
}

func SendWarningEmail(email string) error {
	fmt.Println("В ваш аккаунт зашли с нового устройства")
	return nil
}
