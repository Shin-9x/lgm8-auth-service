package middleware

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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
		tokenString := tokenParts[1]

		token, err := parseAndValidateToken(tokenString, kc)
		if err != nil {
			log.Printf("Error parsing or validating token: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Verify claims (exp, nbf, iat)
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			log.Println("Invalid token claims")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		// Verify exp (expiration time)
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().After(time.Unix(int64(exp), 0)) {
				log.Println("Token is expired")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is expired"})
				c.Abort()
				return
			}
		} else {
			log.Println("Missing or invalid exp claim")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid exp claim"})
			c.Abort()
			return
		}

		// Verify nbf (not before)
		if nbf, ok := claims["nbf"].(float64); ok {
			if time.Now().Before(time.Unix(int64(nbf), 0)) {
				log.Println("Token is not yet valid")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is not yet valid"})
				c.Abort()
				return
			}
		}

		// Verify iat (issued at)
		if iat, ok := claims["iat"].(float64); ok {
			if time.Now().Before(time.Unix(int64(iat), 0)) {
				log.Println("Token issued in the future, possible clock skew issue")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: incorrect issued time"})
				c.Abort()
				return
			}
		} else {
			log.Println("Missing or invalid iat claim")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid iat claim"})
			c.Abort()
			return
		}

		// Verify that the token is of type "Bearer" (optional, if needed)
		if typ, ok := claims["typ"].(string); ok {
			if typ != "Bearer" {
				log.Printf("Invalid token type: expected 'Bearer', got '%s'", typ)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: incorrect type"})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// parseAndValidateToken parses and validates the JWT token using JWKS
func parseAndValidateToken(tokenString string, kc *clients.KeycloakClient) (*jwt.Token, error) {
	const maxRetries = 3

	for retry := 0; retry <= maxRetries; retry++ {
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
			return verifyKey(token, kc.JWKS)
		})

		if err == nil && token.Valid {
			return token, nil // Valid token, exit the loop
		}

		// Check if the error is due to a key not found or an invalid signature
		if errors.Is(err, jwt.ErrSignatureInvalid) || errors.Is(err, jwt.ErrTokenUnverifiable) {
			// Update JWKS and retry
			if err := kc.FetchJWKS(); err != nil {
				return nil, err
			}
			time.Sleep(time.Duration(retry) * time.Second) // Exponential backoff
			continue
		}

		return nil, err
	}

	return nil, fmt.Errorf("failed to validate token after [%d] retries", maxRetries)
}

// verifyKey verifies the JWT token key using JWKS
func verifyKey(token *jwt.Token, jwks []map[string]any) (any, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}

	// Find the corresponding key in JWKS
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("missing kid in token header")
	}

	for _, key := range jwks {
		if key["kid"] == kid {
			// Verify that x5c is an array and has at least one element
			x5c, ok := key["x5c"].([]any)
			if !ok || len(x5c) == 0 {
				return nil, fmt.Errorf("invalid x5c format in JWKS")
			}

			// Verify that the first element of x5c is a string
			x5cString, ok := x5c[0].(string)
			if !ok {
				return nil, fmt.Errorf("invalid x5c value in JWKS")
			}

			// Decode the Base64 string
			certBytes, err := base64.StdEncoding.DecodeString(x5cString)
			if err != nil {
				return nil, fmt.Errorf("failed to decode base64 certificate: %w", err)
			}

			// Parse the X.509 certificate
			cert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}

			// Extract the RSA public key
			rsaPublicKey, ok := cert.PublicKey.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("public key is not RSA")
			}

			// Convert the public key to PEM format
			publicKeyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(rsaPublicKey),
			})

			return jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
		}
	}

	return nil, fmt.Errorf("key not found in JWKS")
}
