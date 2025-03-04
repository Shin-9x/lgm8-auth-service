package handlers

import (
	"log"
	"net/http"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gin-gonic/gin"
	"github.com/lgm8-auth-service/internal/services"
)

type UserHandler struct {
	UserService *services.UserService
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
	c.JSON(http.StatusCreated, UserCreatedResponse{
		Message: "User Created",
		UserID:  userID,
	})
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

	response := UserGetResponse{
		ID:    *user.ID,
		First: *user.FirstName,
		Last:  *user.LastName,
		Email: *user.Email,
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

	accessToken, refreshToken, err := uh.UserService.Login(creds.Username, creds.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid credentials"})
		return
	}

	c.JSON(http.StatusOK, LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

// RefreshToken generates a new access token using a valid refresh token.
//
// @Summary Refresh access token
// @Description Generates a new access token and refresh token using a valid refresh token.
// @Tags auth
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
// @Tags Authentication
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{} "JWKS containing public keys for JWT verification"
// @Failure 500 {object} ErrorResponse "Internal server error while retrieving JWKS"
// @Router /v1/jwks [get]
func (uh *UserHandler) GetJWKS(c *gin.Context) {
	jwks, err := uh.UserService.GetJWKS()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to retrieve JWKS."})
	}

	c.JSON(http.StatusOK, gin.H{"keys": jwks})
}
