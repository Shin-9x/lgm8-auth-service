package services

import (
	"fmt"

	"maps"

	"github.com/Nerzal/gocloak/v13"
	"github.com/golang-jwt/jwt"
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
		return "", fmt.Errorf("error during user creation: [%w]", err)
	}
	return userID, nil
}

func (s *UserService) DeleteUser(userID string) error {
	err := s.Kc.Client.DeleteUser(s.Kc.Ctx, s.Kc.Token.AccessToken, s.Kc.Cfg.Realm, userID)
	if err != nil {
		return fmt.Errorf("error during user deletion: [%w]", err)
	}
	return nil
}

func (s *UserService) GetUser(userID string) (*gocloak.User, error) {
	user, err := s.Kc.Client.GetUserByID(s.Kc.Ctx, s.Kc.Token.AccessToken, s.Kc.Cfg.Realm, userID)
	if err != nil {
		return nil, fmt.Errorf("error during user retrieving: [%w]", err)
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

func (s *UserService) UpdateUser(user gocloak.User) error {
	err := s.Kc.Client.UpdateUser(s.Kc.Ctx, s.Kc.Token.AccessToken, s.Kc.Cfg.Realm, user)
	if err != nil {
		return fmt.Errorf("error updating user: [%w]", err)
	}
	return nil
}

func (s *UserService) UpdateUserAttributes(userID string, attributes map[string][]string) error {
	user, err := s.GetUser(userID)
	if err != nil {
		return fmt.Errorf("failed to fetch user before update: [%w]", err)
	}

	// If the user already has attributes, we keep them and update only the specified ones
	if user.Attributes == nil {
		user.Attributes = &attributes
	} else {
		maps.Copy((*user.Attributes), attributes)
	}

	err = s.Kc.Client.UpdateUser(s.Kc.Ctx, s.Kc.Token.AccessToken, s.Kc.Cfg.Realm, *user)
	if err != nil {
		return fmt.Errorf("error updating user attributes: [%w]", err)
	}
	return nil
}

func (s *UserService) Login(username, password string) (string, string, string, error) {
	token, err := s.Kc.Client.Login(
		s.Kc.Ctx, s.Kc.Cfg.ClientID, s.Kc.Cfg.ClientSecret, s.Kc.Cfg.Realm, username, password,
	)
	if err != nil {
		return "", "", "", fmt.Errorf("error during login: [%w]", err)
	}

	// Extract user ID from JWT token
	parsedToken, _, err := new(jwt.Parser).ParseUnverified(token.AccessToken, jwt.MapClaims{})
	if err != nil {
		return "", "", "", fmt.Errorf("error parsing access token: [%w]", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", "", fmt.Errorf("invalid token claims")
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		return "", "", "", fmt.Errorf("user ID not found in token")
	}

	return token.AccessToken, token.RefreshToken, userID, nil
}

func (s *UserService) Logout(userID string) error {
	err := s.Kc.Client.LogoutAllSessions(s.Kc.Ctx, s.Kc.Token.AccessToken, s.Kc.Cfg.Realm, userID)
	if err != nil {
		return fmt.Errorf("error during logout: [%w]", err)
	}
	return nil
}

func (s *UserService) RefreshToken(refreshToken string) (string, string, error) {
	token, err := s.Kc.Client.RefreshToken(
		s.Kc.Ctx, refreshToken, s.Kc.Cfg.ClientID, s.Kc.Cfg.ClientSecret, s.Kc.Cfg.Realm,
	)
	if err != nil {
		return "", "", fmt.Errorf("error during token refresh: [%w]", err)
	}
	return token.AccessToken, token.RefreshToken, nil
}
