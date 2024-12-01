package config

import (
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

var log = logrus.New()

type Config struct {
	Storage    `yaml:"storage"`
	HTTPServer `yaml:"http_server"`
	JWT        `yaml:"jwt"`
}

type Storage struct {
	Host     string `yaml:"Host" env-default:"localhost"`
	Port     string `yaml:"Port" env-default:"5432"`
	User     string `yaml:"User" env-default:"postgres"`
	Password string `yaml:"Password" env-default:"1"`
	DBName   string `yaml:"DBName" env-default:"User"`
	SSLMode  string `yaml:"SSLMode"  env-default:"disable"`
}
type HTTPServer struct {
	Address     string        `yaml:"address" env-default:"localhost:8088"`
	Timeout     time.Duration `yaml:"timeout" env-default:"4s"`
	IdleTimeout time.Duration `yaml:"idle_timeout" env-default:"60s"`
}

type JWT struct {
	AccessTokenTTL     time.Duration `yaml:"access_token_ttl"`
	RefreshTokenTTL    time.Duration `yaml:"refresh_token_ttl"`
	JWT_ACCESS_SECRET  string        `yaml:"JWT_ACCESS_SECRET"`
	JWT_REFRESH_SECRET string        `yaml:"JWT_REFRESH_SECRET"`
}

func MustLoad() *Config {
	configPath := os.Getenv("CONFIG_PATH")
	file, err := os.Open(configPath)
	if err != nil {
		log.Fatalf("Config file does not exist: %s", configPath)
	}
	defer file.Close()

	var cfg Config

	d := yaml.NewDecoder(file)

	if err := d.Decode(&cfg); err != nil {
		log.Fatalf("Cannot read config: %s", err)
	}

	return &cfg
}
