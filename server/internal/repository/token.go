package repository

import (
	"fmt"
)

func (db *Storage) InsertToken(guid, refreshToken, email string) error {
	const op = "Add.Token"
	query := `INSERT INTO "Token" (guid, email, token) VALUES ($1, $2, $3)`
	_, err := db.db.Exec(query, guid, email, refreshToken)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return err
}

func (db *Storage) GetToken(email string) (string, error) {
	const op = "Get.Token"
	query := `SELECT token FROM "Token" WHERE email = $1`
	row := db.db.QueryRow(query, email)

	var token string
	err := row.Scan(&token)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return token, nil
}

func (db *Storage) DeleteToken(email string) error {
	const op = "Delete.Token.IP"
	_, err := db.db.Exec(`DELETE FROM "Token" WHERE email = $1`, email)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}
