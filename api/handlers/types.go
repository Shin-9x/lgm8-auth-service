package handlers

type UserPostRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type PasswordUpdateRequest struct {
	NewPassword string `json:"newPassword" binding:"required,min=8"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type UserGetResponse struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	First    string `json:"first_name"`
	Last     string `json:"last_name"`
	Email    string `json:"email"`
	Verified string `json:"verified"`
}

type UserCreatedResponse struct {
	Message string `json:"message"`
	UserID  string `json:"user_id"`
}

type UserDeletedResponse struct {
	Message string `json:"message"`
}

type UserPasswordUpdatedResponse struct {
	Message string `json:"message"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	UserID       string `json:"user_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type LogoutRequest struct {
	UserID string `json:"user_id"`
}

type LogoutResponse struct {
	Message string `json:"message"`
}

type JWKSResponse struct {
	Keys JWK `json:"keys"`
}

type JWK []map[string]any
