package utils

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

type Token struct {
	Email string
	jwt.StandardClaims
}

type Data struct {
	Email string
	Ip    string
	TTL   time.Duration
}

func GenerateToken(data Data, secretKey string) (string, error) {
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

func HashToken(token string) ([]byte, error) {
	const op = "auth.manager.HashToken"

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return []byte{}, fmt.Errorf("%s: %w", op, err)
	}

	return hashedToken, nil
}

func CompareTokens(providedToken string, hashedToken []byte) bool {
	err := bcrypt.CompareHashAndPassword(hashedToken, []byte(providedToken))

	return err == nil
}
