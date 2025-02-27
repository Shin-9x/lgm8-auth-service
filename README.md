# lgm8-auth-service

This is the LGM8 authentication microservice built using Go, Gin, and designed to integrate with Keycloak for user management and authentication. It operates behind an NGINX reverse proxy.

## Overview

The `lgm8-auth-service` provides a RESTful API for user registration, authentication, and session management. It leverages Keycloak as the identity provider, ensuring secure and scalable user authentication.

## Features

* **User Registration:** Allows new users to register via a public API endpoint.
* **User Authentication:** Provides login functionality, returning JWT access and refresh tokens.
* **Token Refresh:** Enables clients to refresh access tokens using a valid refresh token.
* **Protected Routes:** Offers protected API endpoints requiring valid JWT authentication for access.
* **User Management:** Provides functionality to retrieve, delete, and update user passwords.
* **Session Logout:** Allows users to invalidate their active sessions.
* **Keycloak Integration:** Seamlessly integrates with Keycloak for user identity management.
* **NGINX Proxy:** Runs behind an NGINX reverse proxy for improved security and load balancing.
* **Swagger Documentation:** API documentation is generated using `gin-swagger`, providing interactive API exploration.


## API Endpoints

### Public Endpoints (No Authentication Required)

* `POST /v1/users`: Create a new user.
* `POST /v1/session/login`: Authenticate a user and obtain JWT tokens.
* `POST /v1/token/refresh`: Refresh an access token.

### Protected Endpoints (Authentication Required)

* `POST /v1/session/logout`: Logout a user from all sessions.
* `GET /v1/users/:id`: Retrieve user details.
* `DELETE /v1/users/:id`: Delete a user.
* `PATCH /v1/users/:id/password`: Update a user's password.


## Technology Stack

* **Go:** Programming language.
* **Gin:** Web framework.
* **Keycloak:** Identity and access management.
* **NGINX:** Reverse proxy.
* **gin-swagger:** API Documentation.


## Swagger Documentation

To generate and update the Swagger documentation, ensure you have `swag` installed. Then, navigate to the root directory of the `lgm8-auth-service` and run the following command:

```bash
swag init -g ./cmd/main.go -o ./docs
```


## Keycloak Configuration

Before running the `lgm8-auth-service`, you must configure Keycloak with the appropriate settings. Update the `./config/config.yaml` file with the values corresponding to your Keycloak installation. Follow these steps:

1.  **Create a Realm:**
    * In your Keycloak instance, create a new realm (e.g., `lgm8`). This realm will isolate the users and clients specific to this service.
    * Update the `realm` field in `config.yaml` with the name of your created realm.

2.  **Create a Client:**
    * Within the newly created realm, create a new client (e.g., `lgm8-auth-service`). This client represents the authentication service itself.
    * Update the `client_id` field in `config.yaml` with the client ID of your created client.

3.  **Retrieve Client Secret:**
    * Navigate to the "Credentials" tab of your client (`lgm8-auth-service`).
    * Copy the "Client Secret" and paste it into the `client_secret` field in `config.yaml`.

4.  **Create an Admin User:**
    * Create a new user within the realm.
    * Assign the `admin` role to this user, providing necessary permissions for administrative tasks.
    * Update the `admin_user` field in `config.yaml` with the username of this admin user.

5.  **Set Admin Password:**
    * Set a password for the admin user.
    * Update the `admin_password` field in `config.yaml` with the admin user's password.

By completing these steps, you ensure that the `lgm8-auth-service` can successfully authenticate and manage users through your Keycloak instance.