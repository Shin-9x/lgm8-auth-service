package main

import (
	"log"

	"github.com/lgm8-auth-service/config"
	"github.com/lgm8-auth-service/internal/keycloak"
)

func main() {
	// Carichiamo la configurazione
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Errore nel caricamento della configurazione: %s", err)
	}

	// Inizializziamo Keycloak
	_, err = keycloak.NewKeycloakClient(&cfg.Keycloak)
	if err != nil {
		log.Fatalf("Errore nella connessione a Keycloak: %s", err)
	}

	log.Println("Il microservizio è pronto!")
}
