package service

import (
	"fmt"
	"jwt-auth/server/internal/config"
	"jwt-auth/server/internal/repository"
	"jwt-auth/server/internal/utils"
)

type Storage interface {
	InsertToken(refreshToken string, email, ip string) error
	GetToken(email string) (string, error)
	GetTokenIP(email, ip string) (string, string, error)
	DeleteToken(refreshToken string) error

	Select() ([]repository.User, error)
	Registration(user repository.User) (string, error)
	CheckExistsUser(email string) (bool, error)
}

type TokenManager interface {
	GenerateToken(data utils.Data, secretKey string) (string, error)
	HashToken(token string) ([]byte, error)
	CompareTokens(providedToken string, hashedToken []byte) bool
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

func (a *Auth) InsertToken(refreshToken string, email, ip string) error {
	const op = "service.InsertToken"

	hashToken, err := a.tokenManager.HashToken(refreshToken)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := a.storage.InsertToken(string(hashToken), email, ip); err != nil {
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

func (a *Auth) DeleteToken(refreshToken string) error {
	const op = "service.DeleteToken"

	err := a.storage.DeleteToken(refreshToken)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (a *Auth) GetTokenIP(email, ip string) (string, string, error) {
	const op = "service.GetTokenIP"

	token, ip, err := a.storage.GetTokenIP(email, ip)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	return token, ip, nil
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
