package config

import (
	"fmt"
	"log"

	"github.com/spf13/viper"
)

// It represents the configuration
type Config struct {
	Server   ServerConfig
	Keycloak KeycloakConfig
	Secrets  SecretsConfig
	RabbitMQ RabbitMQConfig
}

// It represents the property port for the API server
type ServerConfig struct {
	Port int `mapstructure:"port"`
}

// It represents keycloak configuration
type KeycloakConfig struct {
	URL                string `mapstructure:"url"`
	Realm              string `mapstructure:"realm"`
	ClientID           string `mapstructure:"client_id"`
	ClientSecret       string `mapstructure:"client_secret"`
	AdminUser          string `mapstructure:"admin_user"`
	AdminPassword      string `mapstructure:"admin_password"`
	AdminTokenLifetime int    `mapstructure:"admin_token_lifetime"`
}

// It represent RabbitMQ configuration
type RabbitMQConfig struct {
	URL string `mapstructure:"url"`
}

// It represents secrets configuration
type SecretsConfig struct {
	UserVerificationKey string `mapstructure:"user_ver_scrt_key"`
}

// It loads configuration from files and environment variables
func LoadConfig() (*Config, error) {
	viper.SetConfigName(fmt.Sprintf("config.%s", getEnv()))
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config/") // config.yaml file path
	viper.AutomaticEnv()             // Also reads from ENV

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error reading the configuration file: %w", err)
	}

	// Parse config file
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error parsing the configuration: %w", err)
	}

	log.Println("Configuration loaded successfully")
	return &config, nil
}

func getEnv() string {
	env_str := "APP_ENV"

	viper.BindEnv(env_str)
	env := viper.GetString(env_str) // Read the APP_ENV environment variable

	if env == "" {
		log.Printf("APP_ENV empty. Using default.")
		env = "dev" // Default to dev if not set
	}

	log.Printf("Using ENV [%s]", env)

	return env
}
