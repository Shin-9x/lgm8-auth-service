package main

import (
	"log"
	"strconv"

	"github.com/lgm8-auth-service/api/handlers"
	"github.com/lgm8-auth-service/api/routes"
	"github.com/lgm8-auth-service/config"
	"github.com/lgm8-auth-service/internal/clients"
	"github.com/lgm8-auth-service/internal/services"
)

func main() {
	// Load the configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error loading configuration: [%s]", err)
	}

	// RabbitMQ publisher initialization
	publisher, err := clients.NewPublisher(&cfg.RabbitMQ)
	if err != nil {
		log.Fatalf("Error initializing RabbitMQ Publisher: [%s]", err)
	}
	defer publisher.Close()

	// Keycloak client initialization
	kcClient, err := clients.NewKeycloakClient(&cfg.Keycloak)
	if err != nil {
		log.Fatalf("Error connecting to Keycloak: [%s]", err)
	}

	// Handlers initialization
	userHandler := &handlers.UserHandler{
		UserService:    services.NewUserService(kcClient),
		Secrets:        &cfg.Secrets,
		EventPublisher: publisher,
	}

	// Router setup
	r := routes.SetupRouter(userHandler)

	// Server startup
	port := strconv.Itoa(cfg.Server.Port)
	log.Printf("Server started on port: [%s]", port)
	r.Run(":" + port)
}
