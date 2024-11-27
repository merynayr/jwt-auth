package repository

import (
	"fmt"
)

type User struct {
	Email    string
	Password string
}

func (db *Storage) Select() ([]User, error) {
	const op = "Repository.Select.Users"
	users := []User{}
	log.Info("Select")
	query := `SELECT * FROM "Users"`
	rows, err := db.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	for rows.Next() {
		var user User
		if err := rows.Scan(&user.Email, &user.Password); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return users, nil
}

func (db *Storage) Registration(user User) (string, error) {
	const op = "Registration.User"
	query := `INSERT INTO "Users" ("Email", "Password") VALUES ($1, $2) RETURNING "Email";`

	var email string
	err := db.db.QueryRow(query, user.Email, user.Password).Scan(&email)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, ErrExists)
	}

	return email, nil
}
