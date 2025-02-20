package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lgm8-auth-service/api/handlers"
	"github.com/lgm8-auth-service/api/middleware"
)

func SetupRouter(userHandler *handlers.UserHandler) *gin.Engine {
	r := gin.Default()

	r.Use(middleware.Logger())

	api := r.Group("/api/v1")
	{
		// User management
		api.POST("/users", userHandler.CreateUser)
		api.DELETE("/users/:id", userHandler.DeleteUser)
		api.GET("/users/:id", userHandler.GetUser)
		api.PUT("/users", userHandler.UpdateUser)

		// Authentication
		api.POST("/login", userHandler.Login)
		api.POST("/refresh", userHandler.RefreshToken)
		api.POST("/logout", userHandler.Logout)
	}

	return r
}
