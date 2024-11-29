package repository

import (
	"database/sql"
	"fmt"
)

func (db *Storage) InsertToken(refreshToken string, email string, ip string) error {
	const op = "Add.Token"
	query := `INSERT INTO "Token" (email, token, ip) VALUES ($1, $2, $3)`
	_, err := db.db.Exec(query, email, refreshToken, ip)
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

func (db *Storage) DeleteToken(refreshToken string) error {
	const op = "Delete.Token.IP"
	_, err := db.db.Exec(`DELETE FROM "Token" WHERE token = $1`, refreshToken)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (db *Storage) GetTokenIP(email, ip string) (string, string, error) {
	const op = "Get.Token.IP"
	query := `SELECT token, ip FROM "Token" WHERE email = $1 AND ip = $2`
	row := db.db.QueryRow(query, email, ip)

	var token, oldIP string
	err := row.Scan(&token, &oldIP)
	if err == sql.ErrNoRows {
		return "", "", nil
	} else if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	fmt.Println(token, oldIP)
	return token, oldIP, nil
}
