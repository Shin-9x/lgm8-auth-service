package services

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Nerzal/gocloak/v13"
	"github.com/lgm8-auth-service/internal/clients"
)

type UserService struct {
	Kc *clients.KeycloakClient
}

func NewUserService(kc *clients.KeycloakClient) *UserService {
	return &UserService{Kc: kc}
}

func (s *UserService) CreateUser(user gocloak.User) (string, error) {
	userID, err := s.Kc.Client.CreateUser(s.Kc.Ctx, s.Kc.Token.AccessToken, s.Kc.Cfg.Realm, user)
	if err != nil {
		return "", fmt.Errorf("Error during user creation: [%w]", err)
	}
	return userID, nil
}

func (s *UserService) DeleteUser(userID string) error {
	err := s.Kc.Client.DeleteUser(s.Kc.Ctx, s.Kc.Token.AccessToken, s.Kc.Cfg.Realm, userID)
	if err != nil {
		return fmt.Errorf("Error during user deletion: [%w]", err)
	}
	return nil
}

func (s *UserService) GetUser(userID string) (*gocloak.User, error) {
	user, err := s.Kc.Client.GetUserByID(s.Kc.Ctx, s.Kc.Token.AccessToken, s.Kc.Cfg.Realm, userID)
	if err != nil {
		return nil, fmt.Errorf("Error during user retrieving: [%w]", err)
	}
	return user, nil
}

func (s *UserService) UpdateUserPassword(userID string, credential gocloak.CredentialRepresentation) error {
	err := s.Kc.Client.SetPassword(s.Kc.Ctx, s.Kc.Token.AccessToken, userID, s.Kc.Cfg.Realm, *credential.Value, false)
	if err != nil {
		return fmt.Errorf("error updating password for user [%s]: %w", userID, err)
	}
	return nil
}

func (s *UserService) Login(username, password string) (string, string, error) {
	token, err := s.Kc.Client.Login(
		s.Kc.Ctx, s.Kc.Cfg.ClientID, s.Kc.Cfg.ClientSecret, s.Kc.Cfg.Realm, username, password,
	)
	if err != nil {
		return "", "", fmt.Errorf("Error during login: [%w]", err)
	}
	return token.AccessToken, token.RefreshToken, nil
}

func (s *UserService) Logout(userID string) error {
	err := s.Kc.Client.LogoutAllSessions(s.Kc.Ctx, s.Kc.Token.AccessToken, s.Kc.Cfg.Realm, userID)
	if err != nil {
		return fmt.Errorf("Error during logout: [%w]", err)
	}
	return nil
}

func (s *UserService) RefreshToken(refreshToken string) (string, string, error) {
	token, err := s.Kc.Client.RefreshToken(
		s.Kc.Ctx, refreshToken, s.Kc.Cfg.ClientID, s.Kc.Cfg.ClientSecret, s.Kc.Cfg.Realm,
	)
	if err != nil {
		return "", "", fmt.Errorf("Error during token refresh: [%w]", err)
	}
	return token.AccessToken, token.RefreshToken, nil
}

func (s *UserService) GetJWKS() ([]map[string]any, error) {
	jwksURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", s.Kc.Cfg.URL, s.Kc.Cfg.Realm)

	resp, err := s.Kc.Client.RestyClient().R().Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("Error fetching JWKS: [%w]", err)
	}

	respStatusCode := resp.StatusCode()
	if respStatusCode != http.StatusOK {
		return nil, fmt.Errorf("Failed to fetch JWKS: received status [%d]", respStatusCode)
	}

	var result map[string][]map[string]any
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, fmt.Errorf("Error unmarshalling JWKS response: [%w]", err)
	}

	return result["keys"], nil
}
