package model

import "github.com/golang-jwt/jwt"

type Token struct {
	UserId uint
	jwt.StandardClaims
}
type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
