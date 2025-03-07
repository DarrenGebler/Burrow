// pkg/auth/auth_test.go
package auth

import (
	"net/http"
	"testing"
	"time"
)

func TestAuthenticator_GenerateAndVerifyToken(t *testing.T) {
	// Initialize authenticator with a test secret
	auth := NewAuthenticator(Config{
		Secret:        "test-secret",
		TokenValidity: 1 * time.Hour,
		Enabled:       true,
	})

	// Test cases
	tests := []struct {
		name     string
		clientID string
		wantErr  bool
	}{
		{
			name:     "Valid client ID",
			clientID: "test-client",
			wantErr:  false,
		},
		{
			name:     "Empty client ID",
			clientID: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate token
			token, err := auth.GenerateToken(tt.clientID)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateToken() error = %v", err)
				return
			}

			// Verify token
			clientID, err := auth.VerifyToken(token)
			if err != nil {
				t.Errorf("VerifyToken() error = %v", err)
				return
			}

			if clientID != tt.clientID {
				t.Errorf("VerifyToken() clientID = %v, want %v", clientID, tt.clientID)
			}
		})
	}
}

func TestAuthenticator_AuthenticateRequest(t *testing.T) {
	// Initialize authenticator with a test secret
	auth := NewAuthenticator(Config{
		Secret:        "test-secret",
		TokenValidity: 1 * time.Hour,
		Enabled:       true,
	})

	// Generate a valid token
	token, err := auth.GenerateToken("test-client")
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Test cases
	tests := []struct {
		name         string
		setupReq     func() *http.Request
		wantClientID string
		wantErr      bool
	}{
		{
			name: "Valid token in Authorization header",
			setupReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			wantClientID: "test-client",
			wantErr:      false,
		},
		{
			name: "Valid token in query parameter",
			setupReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com?token="+token, nil)
				return req
			},
			wantClientID: "test-client",
			wantErr:      false,
		},
		{
			name: "No token",
			setupReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				return req
			},
			wantClientID: "",
			wantErr:      true,
		},
		{
			name: "Invalid token",
			setupReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("Authorization", "Bearer invalid-token")
				return req
			},
			wantClientID: "",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()

			clientID, err := auth.AuthenticateRequest(req)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("AuthenticateRequest() error = %v", err)
				return
			}

			if clientID != tt.wantClientID {
				t.Errorf("AuthenticateRequest() clientID = %v, want %v", clientID, tt.wantClientID)
			}
		})
	}
}

func TestAuthenticator_AuthDisabled(t *testing.T) {
	// Initialize authenticator with authentication disabled
	auth := NewAuthenticator(Config{
		Secret:        "test-secret",
		TokenValidity: 1 * time.Hour,
		Enabled:       false,
	})

	// Create a request with no token
	req, _ := http.NewRequest("GET", "http://example.com", nil)

	// Authentication should pass with "anonymous" client ID
	clientID, err := auth.AuthenticateRequest(req)
	if err != nil {
		t.Errorf("AuthenticateRequest() error = %v", err)
		return
	}

	if clientID != "anonymous" {
		t.Errorf("AuthenticateRequest() clientID = %v, want %v", clientID, "anonymous")
	}
}
