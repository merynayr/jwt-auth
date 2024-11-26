package config

import (
	"log"
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

type Config struct {
	StoragePath string `yaml:"storage_path" env-required:"false"`
	HTTPServer  `yaml:"http_server"`
}

type HTTPServer struct {
	Address     string        `yaml:"address" env-default:"localhost:8088"`
	Timeout     time.Duration `yaml:"timeout" env-default:"4s"`
	IdleTimeout time.Duration `yaml:"idle_timeout" env-default:"60s"`
}

func MustLoad() *Config {
	configPath := "./server/config/local.yaml"
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
