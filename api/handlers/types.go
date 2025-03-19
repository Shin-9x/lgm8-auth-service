package handlers

type UserPostRequest struct {
	Username    string `json:"username" binding:"required,min=3,max=50"`
	Email       string `json:"email" binding:"required,email"`
	Password    string `json:"password" binding:"required,min=8"`
	FirstName   string `json:"first_name" binding:"required,min=2,max=50"`
	LastName    string `json:"last_name" binding:"required,min=2,max=50"`
	DateOfBirth string `json:"date_of_birth" binding:"required"` // Format dd/MM/yyyy
}

type PasswordUpdateRequest struct {
	NewPassword string `json:"newPassword" binding:"required,min=8"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type UserGetResponse struct {
	ID        string  `json:"id"`
	Username  string  `json:"username"`
	First     string  `json:"first_name"`
	Last      string  `json:"last_name"`
	Email     string  `json:"email"`
	Verified  string  `json:"verified"`
	Weight    float64 `json:"weight,omitempty"`     // Weight in kg (optional)
	Height    float64 `json:"height,omitempty"`     // Height in cm (optional)
	BirthDate string  `json:"birth_date,omitempty"` // Birthdate in dd/MM/yyyy (optional)
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
