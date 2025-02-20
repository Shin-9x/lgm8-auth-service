package clients

import (
	"context"
	"fmt"
	"log"

	"github.com/Nerzal/gocloak/v13"
	"github.com/lgm8-auth-service/config"
)

// KeycloakClient structure for interacting with Keycloak
type KeycloakClient struct {
	Client *gocloak.GoCloak
	Cfg    *config.KeycloakConfig
	Ctx    context.Context
	Token  *gocloak.JWT
}

// NewKeycloakClient initializes the Keycloak client
func NewKeycloakClient(cfg *config.KeycloakConfig) (*KeycloakClient, error) {
	client := gocloak.NewClient(cfg.URL)

	ctx := context.Background()

	// Log in with the admin user
	token, err := client.LoginAdmin(ctx, cfg.AdminUser, cfg.AdminPassword, cfg.Realm)
	if err != nil {
		return nil, fmt.Errorf("error in admin login on Keycloak: %w", err)
	}

	log.Println("Successful connection to Keycloak!")

	return &KeycloakClient{
		Client: client,
		Cfg:    cfg,
		Ctx:    ctx,
		Token:  token,
	}, nil
}

// RefreshToken refreshes the admin token if it expires
func (kc *KeycloakClient) RefreshToken() error {
	token, err := kc.Client.LoginAdmin(kc.Ctx, kc.Cfg.AdminUser, kc.Cfg.AdminPassword, kc.Cfg.Realm)
	if err != nil {
		return fmt.Errorf("Error refreshing token: %w", err)
	}
	kc.Token = token
	return nil
}
