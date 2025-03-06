package handlers

import (
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lgm8-auth-service/config"
	"github.com/lgm8-auth-service/internal/clients"
	"github.com/lgm8-auth-service/internal/services"
	"github.com/lgm8-auth-service/security"
)

const EMAIL_VERIFICATION_TOKEN_LABEL = "email_verification_token"
const EMAIL_VERIFIED_CUSTOM_LABEL = "email_verified_custom"

type UserHandler struct {
	UserService    *services.UserService
	Secrets        *config.SecretsConfig
	EventPublisher *clients.RMQPublisher
}

// CreateUser registers a new user in the system.
//
// @Summary Create a new user
// @Description Creates a new user in Keycloak with the provided credentials.
// @Tags users
// @Accept json
// @Produce json
// @Param request body UserPostRequest true "User registration details"
// @Success 201 {object} UserCreatedResponse "User successfully created"
// @Failure 400 {object} ErrorResponse "Invalid request format"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /v1/users [post]
func (uh *UserHandler) CreateUser(c *gin.Context) {
	var req UserPostRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// User creation
	user := gocloak.User{
		Username:      gocloak.StringP(req.Username),
		Email:         gocloak.StringP(req.Email),
		Enabled:       gocloak.BoolP(true),
		EmailVerified: gocloak.BoolP(false),
		Credentials: &[]gocloak.CredentialRepresentation{
			{
				Type:      gocloak.StringP("password"),
				Value:     gocloak.StringP(req.Password),
				Temporary: gocloak.BoolP(false),
			},
		},
	}

	userID, err := uh.UserService.CreateUser(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	log.Printf("User created with ID: [%s]", userID)

	// User verification token creation
	verificationToken := userID + ":" + uuid.New().String()
	encryptedToken, err := security.EncryptAES(verificationToken, uh.Secrets.UserVerificationKey)
	if err != nil {
		_ = uh.UserService.DeleteUser(userID) // Delete user if something fail
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	// Updating user attributes with verification token
	err = uh.UserService.UpdateUserAttributes(userID, map[string][]string{
		EMAIL_VERIFIED_CUSTOM_LABEL:    {"false"},
		EMAIL_VERIFICATION_TOKEN_LABEL: {encryptedToken},
	})
	if err != nil {
		_ = uh.UserService.DeleteUser(userID) // Delete user if something fail
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	// Send RabbitMQ notification to notifier microservice
	uh.EventPublisher.Publish(map[string]any{
		"email":    req.Email,
		"username": req.Username,
		"token":    encryptedToken,
	})

	c.JSON(http.StatusCreated, UserCreatedResponse{
		Message: "User Created",
		UserID:  userID,
	})
}

// VerifyUser verifies the user's email using a verification token.
//
// @Summary Verify user email
// @Description This endpoint verifies a user's email by decrypting the provided verification token
// and updating the user's status in Keycloak.
// @Tags users
// @Accept json
// @Produce json
// @Param token query string true "Encrypted verification token"
// @Success 200 {object} map[string]string "User verification successful!"
// @Failure 400 {object} ErrorResponse "Bad request (e.g., missing or invalid token)"
// @Failure 401 {object} ErrorResponse "Unauthorized (e.g., token decryption failed, malformed token)"
// @Failure 500 {object} ErrorResponse "Internal server error (e.g., Keycloak user retrieval or update failure)"
// @Router /users/verify [get]
func (uh *UserHandler) VerifyUser(c *gin.Context) {
	token, err := url.QueryUnescape(c.Query("token"))
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	if token == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Token missing"})
		return
	}
	token = strings.ReplaceAll(token, " ", "+") // Restores the + that have been transformed into spaces

	decrypted, err := security.DecryptAES(token, uh.Secrets.UserVerificationKey)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: err.Error()})
		return
	}
	log.Printf("decrypted token -> [%s]", decrypted)

	// Extract UserID from decrypted token
	parts := strings.Split(decrypted, ":")
	if len(parts) != 2 {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Malformed Token"})
		return
	}
	userID := parts[0]
	log.Printf("UserID part -> [%s]", userID)

	// Get the user from Keycloak
	user, err := uh.UserService.GetUser(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	// Check if the saved token is equal to the decrypted token
	if user.Attributes == nil || (*user.Attributes)[EMAIL_VERIFICATION_TOKEN_LABEL][0] != token {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid token."})
		return
	}

	// Update email verification attributes
	(*user.Attributes)[EMAIL_VERIFIED_CUSTOM_LABEL] = []string{"true"}
	delete((*user.Attributes), EMAIL_VERIFICATION_TOKEN_LABEL)

	err = uh.UserService.UpdateUser(*user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "User update error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User verification successful!"})
}

// SendVerificationNotify resends the email verification notification to a user.
//
// @Summary Resend user verification email
// @Description This endpoint retrieves a user from Keycloak, verifies that the user still requires email validation,
// and resends the verification email using RabbitMQ.
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} map[string]string "Notification sent successfully!"
// @Failure 400 {object} ErrorResponse "Bad request (e.g., missing attributes or verification token)"
// @Failure 409 {object} ErrorResponse "Conflict (e.g., user does not need verification)"
// @Failure 500 {object} ErrorResponse "Internal server error (e.g., failed to retrieve user or send notification)"
// @Router /users/{id}/resend-verification [post]
func (uh *UserHandler) SendVerificationNotify(c *gin.Context) {
	userID := c.Param("id")

	// Get the user from Keycloak
	user, err := uh.UserService.GetUser(userID)
	if err != nil {
		log.Printf("Error retrieving user [%s]: [%v]", userID, err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to retrieve user"})
		return
	}

	// Check if user has attributes
	if user.Attributes == nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "User does not have custom attributes"})
		return
	}

	// Extract and validate email_verified_custom
	verifiedAttr, exists := (*user.Attributes)[EMAIL_VERIFIED_CUSTOM_LABEL]
	if !exists || len(verifiedAttr) == 0 || verifiedAttr[0] != "false" {
		c.JSON(http.StatusConflict, ErrorResponse{Error: "User does not need validation"})
		return
	}

	// Extract and validate email_verification_token
	tokenAttr, exists := (*user.Attributes)[EMAIL_VERIFICATION_TOKEN_LABEL]
	if !exists || len(tokenAttr) == 0 || tokenAttr[0] == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Verification token does not exist"})
		return
	}

	token := tokenAttr[0]

	// Send RabbitMQ notification to notifier microservice
	err = uh.EventPublisher.Publish(map[string]any{
		"email":    *user.Email,
		"username": *user.Username,
		"token":    token,
	})
	if err != nil {
		log.Printf("Error publishing event for user [%s]: %v", userID, err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to send notification"})
		return
	}

	log.Printf("Verification email resent for user [%s]", userID)
	c.JSON(http.StatusOK, gin.H{"message": "Notification sent successfully!"})
}

// DeleteUser removes a user by ID.
//
// @Summary Delete user
// @Description Deletes a user from the system based on their ID.
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} UserDeletedResponse "User deleted successfully"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /v1/users/{id} [delete]
func (uh *UserHandler) DeleteUser(c *gin.Context) {
	userID := c.Param("id")

	err := uh.UserService.DeleteUser(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, UserDeletedResponse{Message: "User deleted"})
}

// GetUser retrieves user details by ID.
//
// @Summary Get user details
// @Description Retrieves basic information about a user.
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} UserGetResponse "User details"
// @Failure 404 {object} ErrorResponse "User not found"
// @Router /v1/users/{id} [get]
func (uh *UserHandler) GetUser(c *gin.Context) {
	userID := c.Param("id")

	user, err := uh.UserService.GetUser(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "User not found"})
		return
	}

	var verified string

	if user.Attributes != nil {
		verifiedAttr, exists := (*user.Attributes)[EMAIL_VERIFIED_CUSTOM_LABEL]
		if exists && len(verifiedAttr) > 0 {
			verified = verifiedAttr[0]
		}
	}

	response := UserGetResponse{
		ID:       *user.ID,
		Username: *user.Username,
		First:    *user.FirstName,
		Last:     *user.LastName,
		Email:    *user.Email,
		Verified: verified,
	}

	c.JSON(http.StatusOK, response)
}

// UpdateUserPassword updates a user's password.
//
// @Summary Update user password
// @Description Updates the password of a specific user identified by ID.
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param body body PasswordUpdateRequest true "New password data"
// @Success 200 {object} UserPasswordUpdatedResponse "Password updated successfully"
// @Failure 400 {object} ErrorResponse "Invalid request payload"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /v1/users/{id}/password [patch]
func (uh *UserHandler) UpdateUserPassword(c *gin.Context) {
	var req PasswordUpdateRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	credential := gocloak.CredentialRepresentation{
		Type:      gocloak.StringP("password"),
		Value:     gocloak.StringP(req.NewPassword),
		Temporary: gocloak.BoolP(false),
	}

	userID := c.Param("id")

	err := uh.UserService.UpdateUserPassword(userID, credential)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	log.Printf("Password updated for user ID [%s]", userID)
	c.JSON(http.StatusOK, UserPasswordUpdatedResponse{Message: "Password updated successfully"})
}

// Login handles user authentication and returns an access token and refresh token.
//
// @Summary User login
// @Description Authenticates a user and returns JWT tokens for session management.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Login credentials"
// @Success 200 {object} LoginResponse "JWT tokens"
// @Failure 400 {object} ErrorResponse "Invalid request format"
// @Failure 401 {object} ErrorResponse "Invalid credentials"
// @Router /v1/session/login [post]
func (uh *UserHandler) Login(c *gin.Context) {
	var creds LoginRequest

	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request"})
		return
	}

	accessToken, refreshToken, userID, err := uh.UserService.Login(creds.Username, creds.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid credentials"})
		return
	}

	c.JSON(http.StatusOK, LoginResponse{
		UserID:       userID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

// RefreshToken generates a new access token using a valid refresh token.
//
// @Summary Refresh access token
// @Description Generates a new access token and refresh token using a valid refresh token.
// @Tags Token
// @Accept json
// @Produce json
// @Param request body RefreshTokenRequest true "Refresh token"
// @Success 200 {object} LoginResponse "New JWT tokens"
// @Failure 400 {object} ErrorResponse "Invalid request format"
// @Failure 401 {object} ErrorResponse "Invalid refresh token"
// @Router /v1/token/refresh [post]
func (uh *UserHandler) RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request"})
		return
	}

	accessToken, newRefreshToken, err := uh.UserService.RefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid refresh token"})
		return
	}

	c.JSON(http.StatusOK, LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
	})
}

// Logout terminates all active sessions for a user.
//
// @Summary Logout user
// @Description Logs out a user from all active sessions by invalidating their session in Keycloak.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body LogoutRequest true "User ID to logout"
// @Success 200 {object} LogoutResponse "User logged out successfully"
// @Failure 400 {object} ErrorResponse "Invalid request format"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /v1/session/logout [post]
func (uh *UserHandler) Logout(c *gin.Context) {
	var req LogoutRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request"})
		return
	}

	err := uh.UserService.Logout(req.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, LogoutResponse{Message: "User logged out from all sessions"})
}

// GetJWKS retrieves the JSON Web Key Set (JWKS) from Keycloak.
//
// @Summary Retrieves JWKS for token verification
// @Description Fetches the public keys from Keycloak's JWKS endpoint, used to verify the signatures of JWTs issued by Keycloak.
// @Tags Token
// @Accept json
// @Produce json
// @Success 200 {object} JWKSResponse "JWKS containing public keys for JWT verification"
// @Failure 500 {object} ErrorResponse "Internal server error while retrieving JWKS"
// @Router /v1/token/jwks [get]
func (uh *UserHandler) GetJWKS(c *gin.Context) {
	jwks := uh.UserService.Kc.JWKS
	if jwks == nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to retrieve JWKS."})
		return
	}
	c.JSON(http.StatusOK, JWKSResponse{Keys: jwks})
}
