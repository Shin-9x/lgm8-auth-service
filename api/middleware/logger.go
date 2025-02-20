package middleware

import (
	"log"
	"time"

	"github.com/gin-gonic/gin"
)

func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		t := time.Now()

		c.Next()

		latency := time.Since(t)
		status := c.Writer.Status()
		clientIP := c.ClientIP()
		userAgent := c.Request.UserAgent()
		method := c.Request.Method
		referer := c.Request.Referer()
		path := c.Request.URL.Path
		responseSize := c.Writer.Size()

		log.Printf("Status: %d | Latency: %v | ClientIP: %s | User-Agent: %s | Method: %s | Referer: %s | Path: %s | ResponseSize: %dB",
			status, latency, clientIP, userAgent, method, referer, path, responseSize)
	}
}
