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
		// Public routes (NO AUTH)
		api.POST("/users", userHandler.CreateUser)
		api.POST("/login", userHandler.Login)
		api.POST("/refresh", userHandler.RefreshToken)

		// Protected routes (WITH AUTH)
		protected := api.Group("/")
		protected.Use(middleware.Authenticate(userHandler.UserService.Kc))
		{
			protected.POST("/logout", userHandler.Logout)
			protected.DELETE("/users/:id", userHandler.DeleteUser)
			protected.GET("/users/:id", userHandler.GetUser)
			protected.PUT("/users", userHandler.UpdateUser)
		}
	}

	return r
}
