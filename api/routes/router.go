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

	api := r.Group("/v1")
	{
		// Public routes (NO AUTH)
		api.POST("/users", userHandler.CreateUser)
		api.GET("/users/verification", userHandler.VerifyUser)
		api.POST("/session/login", userHandler.Login)
		api.POST("/token/refresh", userHandler.RefreshToken)
		api.GET("/token/jwks", userHandler.GetJWKS)

		// Protected routes (WITH AUTH)
		protected := api.Group("/")
		protected.Use(middleware.Authenticate(userHandler.UserService.Kc))
		{
			protected.POST("/session/logout", userHandler.Logout)
			protected.GET("/users/:id", userHandler.GetUser)
			protected.DELETE("/users/:id", userHandler.DeleteUser)
			protected.PATCH("/users/:id/password", userHandler.UpdateUserPassword)
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
