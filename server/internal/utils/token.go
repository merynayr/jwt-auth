package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

type Manager struct {
	JWT_ACCESS_SECRET  string
	JWT_REFRESH_SECRET string
}

func NewToken(JWT_REFRESH_SECRET, JWT_ACCESS_SECRET string) (*Manager, error) {
	const op = "utils.manager.NewManager"

	if JWT_ACCESS_SECRET == "" && JWT_REFRESH_SECRET != "" {
		return nil, fmt.Errorf("%s: %s", op, "empty secret string")
	}

	return &Manager{JWT_ACCESS_SECRET: JWT_ACCESS_SECRET, JWT_REFRESH_SECRET: JWT_REFRESH_SECRET}, nil
}

type Token struct {
	Email string
	jwt.StandardClaims
}

type Data struct {
	Email string
	Ip    string
	TTL   time.Duration
}

func (m *Manager) GenerateToken(data Data, secretKey string) (string, error) {
	claims := Token{
		Email: data.Email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(data.TTL).Unix(),
			IssuedAt:  time.Now().Unix(),
			Subject:   data.Ip,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (m *Manager) HashToken(token string) ([]byte, error) {
	// const op = "auth.manager.HashToken"

	// hashedToken, err := bcrypt.GenerateFromPassword([]byte(token), 3)
	// if err != nil {
	// 	return []byte{}, fmt.Errorf("%s: %w", op, err)
	// }

	// return hashedToken, nil

	// Хешируем токен с использованием SHA-256, так как токен получается больше 72 байт
	hash := sha256.Sum256([]byte(token))
	hashedToken := hex.EncodeToString(hash[:])

	return []byte(hashedToken), nil
}

func (m *Manager) CompareTokens(providedToken string, hashedToken []byte) bool {
	err := bcrypt.CompareHashAndPassword(hashedToken, []byte(providedToken))

	return err == nil
}
