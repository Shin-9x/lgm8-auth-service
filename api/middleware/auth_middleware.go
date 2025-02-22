package middleware

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lgm8-auth-service/internal/clients"
)

// Authenticate verifies and validates the JWT token with Keycloak
func Authenticate(kc *clients.KeycloakClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			log.Println("Missing Authorization header")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
			c.Abort()
			return
		}

		// Extract the token from the "Bearer <token>" format
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			log.Println("Invalid Authorization header format")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header format"})
			c.Abort()
			return
		}
		token := tokenParts[1]

		// Verify the token with Keycloak
		tokenInfo, err := kc.Client.RetrospectToken(c, token, kc.Cfg.ClientID, kc.Cfg.ClientSecret, kc.Cfg.Realm)
		if err != nil {
			log.Printf("Error introspecting token: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		// Check tokenInfo
		if tokenInfo == nil {
			log.Println("Keycloak returned nil token info")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token response"})
			c.Abort()
			return
		}

		// Check if the token is active
		if tokenInfo.Active == nil || !*tokenInfo.Active {
			log.Println("Token is not active")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is inactive or expired"})
			c.Abort()
			return
		}

		// Check token expiration (exp)
		if tokenInfo.Exp == nil {
			log.Println("Token missing expiration (exp)")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing expiration"})
			c.Abort()
			return
		}
		expTime := time.Unix(int64(*tokenInfo.Exp), 0)
		if time.Now().After(expTime) {
			log.Println("Token is expired")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is expired"})
			c.Abort()
			return
		}

		// Check Not Before (nbf) → The token is not valid before this time
		if tokenInfo.Nbf != nil {
			nbfTime := time.Unix(int64(*tokenInfo.Nbf), 0)
			if time.Now().Before(nbfTime) {
				log.Println("Token is not valid yet (nbf check failed)")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is not yet valid"})
				c.Abort()
				return
			}
		}

		// Check Issued At (iat) → Token issuance time
		if tokenInfo.Iat == nil {
			log.Println("Token missing issued at (iat)")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing issued at"})
			c.Abort()
			return
		}
		iatTime := time.Unix(int64(*tokenInfo.Iat), 0)
		if time.Now().Before(iatTime) {
			log.Println("Token issued in the future, possible clock skew issue")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: incorrect issued time"})
			c.Abort()
			return
		}

		// Check that the token is of type "Bearer"
		if tokenInfo.Type == nil || *tokenInfo.Type != "Bearer" {
			log.Printf("Invalid token type: expected 'Bearer', got '%s'", *tokenInfo.Type)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: incorrect type"})
			c.Abort()
			return
		}

		// If the token is valid, continue with the request
		c.Next()
	}
}
