package clients

import (
	"encoding/json"
	"log"
	"time"

	"github.com/lgm8-auth-service/config"
	amqp "github.com/rabbitmq/amqp091-go"
)

type RMQPublisher struct {
	connection *amqp.Connection
	channel    *amqp.Channel
	queueName  string
}

const queueName = "user-verification-email"

// NewPublisher creates a new RabbitMQ publisher
func NewPublisher(cfg *config.RabbitMQConfig) (*RMQPublisher, error) {
	conn, err := amqp.Dial(cfg.URL)
	if err != nil {
		return nil, err
	}

	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Queue declaration (just in case it doesn't exist)
	_, err = ch.QueueDeclare(
		queueName,
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		ch.Close()
		conn.Close()
		return nil, err
	}

	log.Println("RabbitMQ Publisher initialized successfully!")
	return &RMQPublisher{
		connection: conn,
		channel:    ch,
		queueName:  queueName,
	}, nil
}

// Publish sends a message to the queue
func (rmqp *RMQPublisher) Publish(message any) error {
	// Convert message to JSON
	jsonBody, err := json.Marshal(message)
	if err != nil {
		return err
	}

	err = rmqp.channel.Publish(
		"",
		rmqp.queueName,
		false,
		false,
		amqp.Publishing{
			ContentType: "application/json",
			Body:        jsonBody,
			Timestamp:   time.Now(),
		},
	)
	if err != nil {
		return err
	}

	log.Printf("Published message on Queue [%s]", rmqp.queueName)
	return nil
}

// Close closes the connection and the RabbitMQ channel
func (rmqp *RMQPublisher) Close() {
	if rmqp.channel != nil {
		rmqp.channel.Close()
	}
	if rmqp.connection != nil {
		rmqp.connection.Close()
	}
}
