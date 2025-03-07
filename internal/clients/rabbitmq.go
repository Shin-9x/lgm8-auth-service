package clients

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/lgm8-auth-service/config"
	amqp "github.com/rabbitmq/amqp091-go"
)

// RabbitMQClient manages the connection and channel to RabbitMQ
// It provides methods to declare queues and publish messages.
type RabbitMQClient struct {
	connection *amqp.Connection
	channel    *amqp.Channel
}

// NewRabbitMQClient initializes a connection to RabbitMQ and opens a channel.
func NewRabbitMQClient(cfg *config.RabbitMQConfig) (*RabbitMQClient, error) {
	conn, err := amqp.Dial(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RabbitMQ: %w", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to open channel: %w", err)
	}

	log.Println("RabbitMQ Client initialized successfully!")
	return &RabbitMQClient{
		connection: conn,
		channel:    ch,
	}, nil
}

// DeclareQueue ensures that the specified queue exists before publishing messages.
func (r *RabbitMQClient) DeclareQueue(queueName string) error {
	_, err := r.channel.QueueDeclare(
		queueName,
		true,  // Durable (messages persist across broker restarts)
		false, // Auto-delete (queue is not deleted when unused)
		false, // Exclusive (queue can be accessed by other connections)
		false, // No-wait (do not wait for confirmation)
		nil,   // Arguments
	)
	if err != nil {
		return fmt.Errorf("failed to declare queue [%s]: %w", queueName, err)
	}
	log.Printf("Queue [%s] declared successfully", queueName)
	return nil
}

// PublishMessage sends a message to the specified queue.
func (r *RabbitMQClient) PublishMessage(queueName string, message any) error {
	// Ensure the queue exists before publishing
	if err := r.DeclareQueue(queueName); err != nil {
		return err
	}

	// Convert the message to JSON
	jsonBody, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	err = r.channel.Publish(
		"", // Default exchange
		queueName,
		false,
		false,
		amqp.Publishing{
			ContentType: "application/json",
			Body:        jsonBody,
			Timestamp:   time.Now(),
		},
	)
	if err != nil {
		return fmt.Errorf("failed to publish message to queue [%s]: %w", queueName, err)
	}

	log.Printf("Published message to Queue [%s]", queueName)
	return nil
}

// Close closes the RabbitMQ channel and connection.
func (r *RabbitMQClient) Close() {
	if r.channel != nil {
		r.channel.Close()
	}
	if r.connection != nil {
		r.connection.Close()
	}
	log.Println("RabbitMQ connection closed.")
}
