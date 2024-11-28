package repository

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
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
		return nil, fmt.Errorf("%s: %w", op, ErrExists)
	}

	return users, nil
}

func (db *Storage) Registration(user User) (string, error) {
	const op = "Registration.User"
	query := `INSERT INTO "Users" ("email", "password") VALUES ($1, $2) RETURNING "email";`

	var email string
	hashPassword, _ := HashPassword(user.Password)
	err := db.db.QueryRow(query, user.Email, hashPassword).Scan(&email)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return email, nil
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 3)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (db *Storage) SignIn(user User) {

}
