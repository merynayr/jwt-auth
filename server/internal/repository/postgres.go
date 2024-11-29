package repository

import (
	"fmt"

	"database/sql"

	"errors"

	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
)

var (
	ErrNotFound = errors.New("object not found")
	ErrExists   = errors.New("ogject exists")
)

var log = logrus.New()

type Config struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

type Storage struct {
	db *sql.DB
}

func InitDB(cfg Config) (*Storage, error) {

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s", cfg.Host, cfg.User, cfg.Password, cfg.DBName, cfg.Port, cfg.SSLMode)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("Error: Unable to connect to database: %s", err)
	}
	err = createTable(db)
	if err != nil {
		log.Fatalf("Error: Unable to create tables : %s", err)
	}
	return &Storage{db: db}, nil
}

func createTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS "Users" (
			email VARCHAR(256) PRIMARY KEY,
			password VARCHAR(256) NOT NULL
		);
	`)
	if err != nil {
		return fmt.Errorf("error creating table Users: %s", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS "Token" (
			id SERIAL PRIMARY KEY,
			email VARCHAR(256) NOT NULL,
			token VARCHAR(255) NOT NULL,
			ip VARCHAR(33) NOT NULL,
			FOREIGN KEY (email) REFERENCES "Users"(email)
		);
	`)
	if err != nil {
		return fmt.Errorf("error creating table Token: %s", err)
	}
	return nil
}
