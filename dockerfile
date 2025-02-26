# Stage 1: Build the Go application
FROM golang:1.24-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go mod and sum files from the microservice directory
COPY ../microservices/lgm8-auth-service/go.mod ../microservices/lgm8-auth-service/go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source from the microservice directory to the container
COPY ../microservices/lgm8-auth-service/ .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o lgm8-auth-service ./cmd/main.go

# Stage 2: Create a minimal runtime image
FROM alpine:latest

# Copy the built binary from the builder stage
COPY --from=builder /app/lgm8-auth-service /app/lgm8-auth-service

# Copy the config file from the microservice directory
COPY ../microservices/lgm8-auth-service/config/config.yaml /app/config/config.yaml

# Set the working directory
WORKDIR /app

# Expose the port your application listens on (as defined in config.yaml)
EXPOSE 8081

# Run the application
CMD ["./lgm8-auth-service"]