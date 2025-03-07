package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/lgm8-auth-service/config"
)

// KeycloakClient structure for interacting with Keycloak
type KeycloakClient struct {
	Client      *gocloak.GoCloak
	Cfg         *config.KeycloakConfig
	Ctx         context.Context
	Token       *gocloak.JWT
	TokenExpiry time.Time
	JWKS        []map[string]any
}

// NewKeycloakClient initializes the Keycloak client
func NewKeycloakClient(cfg *config.KeycloakConfig) (*KeycloakClient, error) {
	client := gocloak.NewClient(cfg.URL)
	ctx := context.Background()

	// Log in with the admin user
	token, err := client.LoginAdmin(ctx, cfg.AdminUser, cfg.AdminPassword, cfg.Realm)
	if err != nil {
		return nil, fmt.Errorf("error in admin login on Keycloak: [%w]", err)
	}
	log.Println("Successful connection to Keycloak!")

	expiryTime := time.Now().Add(time.Duration(cfg.AdminTokenLifetime) * time.Second)

	kc := &KeycloakClient{
		Client:      client,
		Cfg:         cfg,
		Ctx:         ctx,
		Token:       token,
		TokenExpiry: expiryTime,
	}

	if err := kc.FetchJWKS(); err != nil {
		return nil, fmt.Errorf("error fetching JWKS: [%w]", err)
	}

	go kc.startJWKSUpdater()
	go kc.scheduleTokenRefresh()

	return kc, nil
}

// scheduleTokenRefresh waits until the token is about to expire and refreshes it
func (kc *KeycloakClient) scheduleTokenRefresh() {
	for {
		timeRemaining := time.Until(kc.TokenExpiry)
		refreshAfter := timeRemaining - 10*time.Second // Renew 10 seconds before expiration

		if refreshAfter <= 0 {
			refreshAfter = 1 * time.Second
		}

		log.Printf("Scheduling admin token refresh in: [%v]", refreshAfter)
		time.Sleep(refreshAfter)

		log.Println("Admin token is expired or about to expire, refreshing...")
		if err := kc.RefreshToken(); err != nil {
			log.Printf("Failed to refresh admin token: [%v]", err)
		}
	}
}

// RefreshToken refreshes the admin token
func (kc *KeycloakClient) RefreshToken() error {
	token, err := kc.Client.LoginAdmin(kc.Ctx, kc.Cfg.AdminUser, kc.Cfg.AdminPassword, kc.Cfg.Realm)
	if err != nil {
		return fmt.Errorf("error refreshing token: [%w]", err)
	}
	kc.Token = token
	kc.TokenExpiry = time.Now().Add(time.Duration(kc.Cfg.AdminTokenLifetime) * time.Second)
	log.Printf("Admin token refreshed! New expiry at: [%v]", kc.TokenExpiry)
	return nil
}

// startJWKSUpdater updates JWKS keys periodically
func (kc *KeycloakClient) startJWKSUpdater() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		if err := kc.FetchJWKS(); err != nil {
			log.Printf("Error fetching JWKS: [%v]", err)
		} else {
			log.Println("JWKS updated successfully!")
		}
	}
}

// FetchJWKS fetches JSON Web Key Set from Keycloak
func (kc *KeycloakClient) FetchJWKS() error {
	jwksURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", kc.Cfg.URL, kc.Cfg.Realm)

	resp, err := kc.Client.RestyClient().R().Get(jwksURL)
	if err != nil {
		return fmt.Errorf("error fetching JWKS: [%w]", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("failed to fetch JWKS: received status [%d]", resp.StatusCode())
	}

	var result map[string][]map[string]any
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return fmt.Errorf("error unmarshalling JWKS response: [%w]", err)
	}

	kc.JWKS = result["keys"]
	log.Println("Successfully fetched JWKS!")
	return nil
}
