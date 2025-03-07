package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var (
	ErrInvalidToken    = errors.New("invalid token")
	ErrTokenExpired    = errors.New("token expired")
	ErrMissingToken    = errors.New("missing token")
	ErrInvalidClientID = errors.New("invalid client ID")
)

// Config holds authentication configuration.
type Config struct {
	// Secret key used to sign tokens
	Secret string
	// Token validity duration
	TokenValidity time.Duration
	// Enable authentication (if false, all requests are allowed)
	Enabled bool
}

// Authenticator handles authentication.
type Authenticator struct {
	config Config
}

// NewAuthenticator creates a new authenticator.
func NewAuthenticator(config Config) *Authenticator {
	// Default token validity to 24 hours if not specified
	if config.TokenValidity == 0 {
		config.TokenValidity = 24 * time.Hour
	}

	return &Authenticator{
		config: config,
	}
}

// GenerateToken generates a token for the given client ID.
func (a *Authenticator) GenerateToken(clientID string) (string, error) {
	if clientID == "" {
		return "", ErrInvalidClientID
	}

	// Create token with expiration time
	now := time.Now().Unix()
	expiry := now + int64(a.config.TokenValidity.Seconds())

	// Format: clientID:timestamp:expiry
	payload := fmt.Sprintf("%s:%d:%d", clientID, now, expiry)

	// Sign the payload
	h := hmac.New(sha256.New, []byte(a.config.Secret))
	h.Write([]byte(payload))
	signature := h.Sum(nil)

	// Encode the token: base64(payload):base64(signature)
	token := fmt.Sprintf("%s:%s",
		base64.StdEncoding.EncodeToString([]byte(payload)),
		base64.StdEncoding.EncodeToString(signature))

	return token, nil
}

// VerifyToken verifies a token.
func (a *Authenticator) VerifyToken(token string) (string, error) {
	if !a.config.Enabled {
		// Authentication is disabled, accept any token
		return "anonymous", nil
	}

	if token == "" {
		return "", ErrMissingToken
	}

	// Split token into payload and signature
	parts := strings.Split(token, ":")
	if len(parts) != 2 {
		return "", ErrInvalidToken
	}

	// Decode payload and signature
	payloadBytes, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", ErrInvalidToken
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ErrInvalidToken
	}

	// Verify signature
	h := hmac.New(sha256.New, []byte(a.config.Secret))
	h.Write(payloadBytes)
	expectedSignature := h.Sum(nil)

	if !hmac.Equal(signatureBytes, expectedSignature) {
		return "", ErrInvalidToken
	}

	// Parse payload
	payloadParts := strings.Split(string(payloadBytes), ":")
	if len(payloadParts) != 3 {
		return "", ErrInvalidToken
	}

	clientID := payloadParts[0]
	expiry, err := time.Parse(time.RFC3339, payloadParts[2])
	if err != nil {
		return "", ErrInvalidToken
	}

	// Check expiration
	if time.Now().After(expiry) {
		return "", ErrTokenExpired
	}

	return clientID, nil
}

// ExtractTokenFromRequest extracts a token from an HTTP request.
func (a *Authenticator) ExtractTokenFromRequest(r *http.Request) string {
	// Try to get token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	// Try to get token from query parameter
	return r.URL.Query().Get("token")
}

// AuthenticateRequest authenticates an HTTP request.
func (a *Authenticator) AuthenticateRequest(r *http.Request) (string, error) {
	if !a.config.Enabled {
		// Authentication is disabled, accept any request
		return "anonymous", nil
	}

	token := a.ExtractTokenFromRequest(r)
	return a.VerifyToken(token)
}
