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

func (uh *UserHandler) CreateUser(c *gin.Context) {
	var user gocloak.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user.Enabled = gocloak.BoolP(true)

	userID, err := uh.UserService.CreateUser(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	log.Printf("User created with ID: [%s]", userID)
	c.JSON(
		http.StatusCreated,
		gin.H{
			"message": "User Created",
			"user_id": userID,
		},
	)
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

func (uh *UserHandler) UpdateUser(c *gin.Context) {
	var user gocloak.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := uh.UserService.UpdateUser(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated"})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Logout failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User logged out from all sessions"})
}
