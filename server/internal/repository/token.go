package repository

import (
	"fmt"
)

type Token struct {
	Email string `json:"email" db:"email"`
	Token string `json:"token" db:"token"`
}

func (db *Storage) InsertToken(token Token) error {
	const op = "Add.Token"
	query := `INSERT INTO "Token" (email, token) VALUES ($1, $2)`
	_, err := db.db.Exec(query, token.Email, token.Token)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return err
}

func (db *Storage) GetToken(email string) (*Token, error) {
	query := `SELECT email, token FROM "Token" WHERE email = $1`
	row := db.db.QueryRow(query, email)

	var token Token
	err := row.Scan(&token.Email, &token.Token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (db *Storage) DeleteToken(refreshToken string) error {
	_, err := db.db.Exec(`DELETE FROM "Token" WHERE token = $1`, refreshToken)
	return err
}
