package repository

import (
	"fmt"

	"database/sql"

	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
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

	return &Storage{db: db}, nil
}
