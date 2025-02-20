package keycloak

import (
	"context"
	"fmt"
	"log"

	"github.com/Nerzal/gocloak/v13"
	"github.com/lgm8-auth-service/config"
)

// KeycloakClient struttura per interagire con Keycloak
type KeycloakClient struct {
	client *gocloak.GoCloak
	cfg    *config.KeycloakConfig
	ctx    context.Context
	token  *gocloak.JWT
}

// NewKeycloakClient inizializza il client Keycloak
func NewKeycloakClient(cfg *config.KeycloakConfig) (*KeycloakClient, error) {
	client := gocloak.NewClient(cfg.URL)

	ctx := context.Background()

	// Effettua il login con l'utente admin
	token, err := client.LoginAdmin(ctx, cfg.AdminUser, cfg.AdminPassword, cfg.Realm)
	if err != nil {
		return nil, fmt.Errorf("errore nel login admin su Keycloak: %w", err)
	}

	log.Println("Connessione a Keycloak riuscita!")

	return &KeycloakClient{
		client: client,
		cfg:    cfg,
		ctx:    ctx,
		token:  token,
	}, nil
}

// RefreshToken aggiorna il token admin se scade
func (kc *KeycloakClient) RefreshToken() error {
	token, err := kc.client.LoginAdmin(kc.ctx, kc.cfg.AdminUser, kc.cfg.AdminPassword, kc.cfg.Realm)
	if err != nil {
		return fmt.Errorf("errore nel refresh del token: %w", err)
	}
	kc.token = token
	return nil
}
