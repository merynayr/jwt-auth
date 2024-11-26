package repository

import "fmt"

type User struct {
	Email    string
	Password string
}

func (db *Storage) Select() ([]User, error) {
	const op = "Select Users"
	users := []User{}
	log.Info("Select")
	query := "SELECT * FROM \"Users\""
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
