package config

import (
	"fmt"
	"log"

	"github.com/spf13/viper"
)

// Config struttura che rappresenta la configurazione
type Config struct {
	Server   ServerConfig
	Keycloak KeycloakConfig
}

// ServerConfig configura il server API
type ServerConfig struct {
	Port int
}

// KeycloakConfig configura Keycloak
type KeycloakConfig struct {
	URL           string `mapstructure:"url"`
	Realm         string `mapstructure:"realm"`
	ClientID      string `mapstructure:"client_id"`
	ClientSecret  string `mapstructure:"client_secret"`
	AdminUser     string `mapstructure:"admin_user"`
	AdminPassword string `mapstructure:"admin_password"`
}

// LoadConfig carica la configurazione da file e variabili d'ambiente
func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("config/") // Percorso del file
	viper.AutomaticEnv()           // Legge anche da ENV

	// Leggiamo il file
	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("errore nel leggere il file di configurazione: %w", err)
	}

	// Parse della configurazione
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("errore nel parsing della configurazione: %w", err)
	}

	log.Println("Configurazione caricata correttamente")
	return &config, nil
}
