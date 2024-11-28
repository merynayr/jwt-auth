package repository

import (
	"fmt"
)

func (db *Storage) InsertToken(refreshToken string, email string) error {
	const op = "Add.Token"
	query := `INSERT INTO "Token" (email, token) VALUES ($1, $2)`
	_, err := db.db.Exec(query, email, refreshToken)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return err
}

func (db *Storage) GetToken(email string) (string, error) {
	query := `SELECT email, token FROM "Token" WHERE email = $1`
	row := db.db.QueryRow(query, email)

	var token string
	err := row.Scan(&token)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (db *Storage) DeleteToken(refreshToken string) error {
	_, err := db.db.Exec(`DELETE FROM "Token" WHERE token = $1`, refreshToken)
	return err
}
