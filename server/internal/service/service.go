package service

import (
	"fmt"
	"jwt-auth/server/internal/config"
	"jwt-auth/server/internal/repository"
	"jwt-auth/server/internal/utils"

	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
)

type Storage interface {
	InsertToken(guid, refreshToken, email string) error
	GetToken(GUID string) (string, error)
	DeleteToken(refreshToken string) error

	Select() ([]repository.User, error)
	Registration(user repository.User) (string, error)
	CheckExistsUser(email string) (bool, error)
}

type TokenManager interface {
	GenerateToken(data utils.Data, secretKey string) (string, error)
	HashToken(token string) ([]byte, error)
	CompareTokens(providedToken string, hashedToken string) bool
	GetClaims(tokenStr string) (jwt.MapClaims, error)
}

type Auth struct {
	cfg          *config.Config
	storage      Storage
	tokenManager TokenManager
}

func New(cfg *config.Config, storage Storage, tokenManager TokenManager) (*Auth, error) {
	return &Auth{
		cfg:          cfg,
		storage:      storage,
		tokenManager: tokenManager}, nil
}

func (a *Auth) InsertToken(guid, refreshToken, email string) error {
	const op = "service.InsertToken"

	hashToken, err := a.tokenManager.HashToken(refreshToken)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := a.storage.InsertToken(guid, string(hashToken), email); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (a *Auth) GetRefreshToken(data utils.Data) (string, error) {
	const op = "service.GetRefreshToken"

	data.TTL = a.cfg.RefreshTokenTTL
	refreshToken, err := a.tokenManager.GenerateToken(data, a.cfg.JWT_REFRESH_SECRET)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return refreshToken, nil
}

func (a *Auth) GetAccessToken(data utils.Data) (string, error) {
	const op = "service.GetAccessToken"

	data.TTL = a.cfg.AccessTokenTTL
	accessToken, err := a.tokenManager.GenerateToken(data, a.cfg.JWT_ACCESS_SECRET)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return accessToken, nil
}

func (a *Auth) DeleteToken(Email string) error {
	const op = "service.DeleteToken"

	err := a.storage.DeleteToken(Email)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (a *Auth) GetToken(GUID string) (string, error) {
	const op = "service.GetToken"

	token, err := a.storage.GetToken(GUID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return token, nil
}

func (a *Auth) SelectUsers() ([]repository.User, error) {
	return a.storage.Select()
}

func (a *Auth) Registration(user repository.User) (string, error) {
	return a.storage.Registration(user)
}

func (a *Auth) ExistsUser(email string) (bool, error) {
	return a.storage.CheckExistsUser(email)
}

func (a *Auth) GetClaimField(tokenString string) (jwt.MapClaims, error) {
	const op = "service.GetClaimField"

	tokenField, err := a.tokenManager.GetClaims(tokenString)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return tokenField, err
}

func (a *Auth) CompareTokens(providedToken string, hashedToken string) bool {
	ok := a.tokenManager.CompareTokens(providedToken, hashedToken)
	return ok
}

var log = logrus.New()

func (a *Auth) ValidToken(refreshToken string, rtClaims jwt.MapClaims) bool {
	refreshTokenStr := fmt.Sprintf("%s", rtClaims["GUID"])
	tokenFromBD, err := a.GetToken(refreshTokenStr)
	if err != nil {
		return false
	}
	if !a.CompareTokens(refreshToken, tokenFromBD) {
		return false
	}

	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(a.cfg.JWT_REFRESH_SECRET), nil
	})
	if token.Valid {
		return true
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			log.Error("That's not even a token")
			return false
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			log.Error("Timing is everything")
			return false
		} else {
			log.Error("Couldn't handle this token:", err)
			return false
		}
	} else {
		log.Error("Couldn't handle this token:", err)
		return false
	}
}
