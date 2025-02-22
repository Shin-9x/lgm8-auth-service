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

type UserRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

// PasswordUpdateRequest represents the payload for updating a user's password
type PasswordUpdateRequest struct {
	ID          string `json:"id" binding:"required"`                // User ID (required)
	NewPassword string `json:"newPassword" binding:"required,min=8"` // New password (required, min 8 chars)
}

// CreateUser handles the registration of a new user
func (uh *UserHandler) CreateUser(c *gin.Context) {
	var req UserRequest

	// Binding with automatic validation
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create user structure for Keycloak
	user := gocloak.User{
		Username:      gocloak.StringP(req.Username),
		Email:         gocloak.StringP(req.Email),
		Enabled:       gocloak.BoolP(true), // The user is enabled by default
		EmailVerified: gocloak.BoolP(false),
		Credentials: &[]gocloak.CredentialRepresentation{
			{
				Type:      gocloak.StringP("password"),
				Value:     gocloak.StringP(req.Password),
				Temporary: gocloak.BoolP(false), // If `true`, the user will have to change the password at first login
			},
		},
	}

	// Create the user on Keycloak
	userID, err := uh.UserService.CreateUser(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	log.Printf("User created with ID: [%s]", userID)
	c.JSON(http.StatusCreated, gin.H{
		"message": "User Created",
		"user_id": userID,
	})
}

func (uh *UserHandler) DeleteUser(c *gin.Context) {
	userID := c.Param("id")

	err := uh.UserService.DeleteUser(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted"})
}

func (uh *UserHandler) GetUser(c *gin.Context) {
	userID := c.Param("id")

	user, err := uh.UserService.GetUser(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
	}

	c.JSON(http.StatusOK, user)
}

// UpdateUserPassword handles user password update
func (uh *UserHandler) UpdateUserPassword(c *gin.Context) {
	var req PasswordUpdateRequest

	// Validate request payload
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create password credential object
	credential := gocloak.CredentialRepresentation{
		Type:      gocloak.StringP("password"),
		Value:     gocloak.StringP(req.NewPassword),
		Temporary: gocloak.BoolP(false), // Permanent password change
	}

	// Call service to update the password
	err := uh.UserService.UpdateUserPassword(req.ID, credential)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	log.Printf("Password updated for user ID [%s]", req.ID)
	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
}

func (uh *UserHandler) Login(c *gin.Context) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	accessToken, refreshToken, err := uh.UserService.Login(creds.Username, creds.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func (uh *UserHandler) RefreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	accessToken, newRefreshToken, err := uh.UserService.RefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
	})
}

func (uh *UserHandler) Logout(c *gin.Context) {
	var req struct {
		UserID string `json:"user_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	err := uh.UserService.Logout(req.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User logged out from all sessions"})
}
