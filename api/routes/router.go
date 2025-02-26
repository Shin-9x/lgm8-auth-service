package routes

import (
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lgm8-auth-service/api/handlers"
	"github.com/lgm8-auth-service/api/middleware"
)

func SetupRouter(userHandler *handlers.UserHandler) *gin.Engine {
	r := gin.Default()

	trustedProxies := getTrustedProxiesFromEnv()
	if trustedProxies != nil {
		r.SetTrustedProxies(trustedProxies)
	}

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
			protected.PUT("/users", userHandler.UpdateUserPassword)
		}
	}

	return r
}

func getTrustedProxiesFromEnv() []string {
	trustedProxiesStr := os.Getenv("GIN_TRUSTED_PROXIES")

	if len(trustedProxiesStr) > 0 && trustedProxiesStr != "" {
		proxies := strings.Split(trustedProxiesStr, ",")

		var res []string
		res = append(res, proxies...)
		return res
	}

	return nil
}
