package service

import (
	"fmt"
	"jwt-auth/server/internal/config"
	"jwt-auth/server/internal/utils"
)

type Storage interface {
	InsertToken(refreshToken string, email string) error
	GetRefreshToken(data utils.Data) (string, error)
	GetAccessToken(data utils.Data) (string, error)
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

func (a *Auth) InsertToken(refreshToken string, email string) error {
	const op = "service.InsertToken"

	hashToken, err := a.tokenManager.HashToken(refreshToken)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := a.storage.InsertToken(string(hashToken), email); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (a *Auth) GetRefreshToken(data utils.Data) (string, error) {
	const op = "service.GetRefreshToken"

	refreshToken, err := a.tokenManager.GenerateToken(data, a.cfg.JWT_REFRESH_SECRET)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return refreshToken, nil
}

func (a *Auth) GetAccessToken(data utils.Data) (string, error) {
	const op = "service.GetRefreshToken"

	refreshToken, err := a.tokenManager.GenerateToken(data, a.cfg.JWT_ACCESS_SECRET)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return refreshToken, nil
}
