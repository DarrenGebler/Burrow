package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/DarrenGebler/burrow/pkg/tunnel"
	"github.com/gorilla/websocket"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ShutdownTimeout is the time to wait for the client to disconnect gracefully.
const ShutdownTimeout = 5 * time.Second

type Config struct {
	ServerAddr string
	LocalAddr  string
	Subdomain  string
	Secure     bool
	AuthToken  string
}

type Client struct {
	config       *Config
	conn         *websocket.Conn
	tunnelURL    string
	localClient  *http.Client
	done         chan struct{}
	reconnecting bool
	mu           sync.RWMutex
}

func New(config *Config) (*Client, error) {
	return &Client{
		config:      config,
		localClient: &http.Client{Timeout: 30 * time.Second},
		done:        make(chan struct{}),
	}, nil
}

// Connect connects to the Burrow server
func (c *Client) Connect() (string, error) {
	serverURL := c.config.ServerAddr
	if !strings.Contains(serverURL, "://") {
		scheme := "ws"
		if c.config.Secure {
			scheme = "wss"
		}
		serverURL = fmt.Sprintf("%s://%s", scheme, serverURL)
	}

	wsURL, err := url.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("invalid server address: %v", err)
	}
	wsURL.Path = "/tunnel"

	q := wsURL.Query()
	if c.config.Subdomain != "" {
		q.Set("subdomain", c.config.Subdomain)
	}
	if c.config.AuthToken != "" {
		q.Set("token", c.config.AuthToken)
	}
	wsURL.RawQuery = q.Encode()

	// Create HTTP header for auth token if provided
	header := http.Header{}
	if c.config.AuthToken != "" {
		header.Set("Authorization", "Bearer "+c.config.AuthToken)
	}

	c.mu.Lock()
	conn, _, err := websocket.DefaultDialer.Dial(wsURL.String(), nil)
	if err != nil {
		c.mu.Unlock()
		return "", fmt.Errorf("failed to connect to server: %v", err)
	}
	c.conn = conn
	c.mu.Unlock()

	_, message, err := conn.ReadMessage()
	if err != nil {
		c.conn.Close()
		return "", fmt.Errorf("failed to read tunnel information: %v", err)
	}

	var info map[string]string
	if err := json.Unmarshal(message, &info); err != nil {
		c.conn.Close()
		return "", fmt.Errorf("failed to parse tunnel information: %v", err)
	}

	tunnelURL, ok := info["url"]
	if !ok {
		c.conn.Close()
		return "", fmt.Errorf("missing tunnel URL in server response")
	}

	c.tunnelURL = tunnelURL

	go c.handleMessages()

	go c.reconnectLoop()

	return tunnelURL, nil
}

// Disconnect disconnects from the Burrow server
func (c *Client) Disconnect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil
	}

	close(c.done)

	err := c.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	if err != nil {
		log.Printf("Error sending close message: %v", err)
	}

	select {
	case <-ctx.Done():
		log.Printf("Context deadline exceeded during disconnect")
	case <-time.After(100 * time.Millisecond):
		//TODO: Give more info
	}

	return c.conn.Close()
}

// handleMessages handles incoming messages from the server
func (c *Client) handleMessages() {
	for {
		select {
		case <-c.done:
			return
		default:
			// Continue
		}

		c.mu.RLock()
		conn := c.conn
		c.mu.RUnlock()

		if conn == nil {
			return
		}

		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Read error: %v", err)

			c.mu.Lock()
			if !c.reconnecting {
				c.reconnecting = true
				go c.reconnect()
			}
			c.mu.Unlock()
			return
		}

		var msg tunnel.Message
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Printf("Read error: %v", err)
			continue
		}
		// Handle message based on type
		switch msg.Type {
		case tunnel.RequestMessage:
			go c.handleRequest(msg)
		case tunnel.PingMessage:
			c.sendPong()
		default:
			log.Printf("Unknown message type: %s", msg.Type)
		}
	}
}

// handleRequest handles a request message from the server
func (c *Client) handleRequest(msg tunnel.Message) {
	// Log the incoming request for debugging
	log.Printf("Received request: %s %s", msg.Method, msg.Path)

	body := []byte{}
	if msg.Body != "" {
		var err error
		body, err = base64.StdEncoding.DecodeString(msg.Body)
		if err != nil {
			log.Printf("Failed to decode body: %v", err)
			c.sendErrorResponse(msg.ID, http.StatusInternalServerError, "Invalid request body")
			return
		}
	}

	// Construct the local URL
	localURL := fmt.Sprintf("http://%s%s", c.config.LocalAddr, msg.Path)
	log.Printf("Forwarding to local service: %s", localURL)

	// Create request to local service
	req, err := http.NewRequest(msg.Method, localURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		c.sendErrorResponse(msg.ID, http.StatusInternalServerError, "Failed to create request")
		return
	}

	// Copy headers
	for key, values := range msg.Headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Add X-Forwarded headers
	req.Header.Set("X-Forwarded-Host", req.Host)
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Forwarded-For", "burrow-tunnel")

	// Timeout for request to local service
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	// Send request to local service
	resp, err := c.localClient.Do(req)
	if err != nil {
		log.Printf("Failed to forward request: %v", err)

		// Check if this is because the service isn't running
		var responseMsg string
		if strings.Contains(err.Error(), "connection refused") {
			responseMsg = "Connection refused. Is your local service running on " + c.config.LocalAddr + "?"
		} else if strings.Contains(err.Error(), "context deadline exceeded") {
			responseMsg = "Request timed out. Check if your local service is responding."
		} else {
			responseMsg = "Failed to reach local service: " + err.Error()
		}

		c.sendErrorResponse(msg.ID, http.StatusBadGateway, responseMsg)
		return
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response body: %v", err)
		c.sendErrorResponse(msg.ID, http.StatusInternalServerError, "Failed to read response from local service")
		return
	}

	// Log response status for debugging
	log.Printf("Local service responded with status: %d", resp.StatusCode)

	// Create response message
	respMsg := tunnel.Message{
		Type:    tunnel.ResponseMessage,
		ID:      msg.ID,
		Status:  resp.StatusCode,
		Headers: resp.Header,
		Body:    base64.StdEncoding.EncodeToString(respBody),
	}

	// Send response back through tunnel
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		log.Printf("Connection lost, cannot send response")
		return
	}

	if err := conn.WriteJSON(respMsg); err != nil {
		log.Printf("Failed to send response: %v", err)
	} else {
		log.Printf("Response sent successfully")
	}
}

// sendErrorResponse sends an error response for a request.
func (c *Client) sendErrorResponse(id string, status int, message string) {
	respMsg := tunnel.Message{
		Type:   tunnel.ResponseMessage,
		ID:     id,
		Status: status,
		Headers: map[string][]string{
			"Content-Type": {"text/plain"},
		},
		Body: base64.StdEncoding.EncodeToString([]byte(message)),
	}

	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		log.Printf("Connection lost, cannot send error response")
		return
	}

	if err := conn.WriteJSON(respMsg); err != nil {
		log.Printf("Failed to send error response: %v", err)
	}
}

// sendPong sends a pong message in response to a ping.
func (c *Client) sendPong() {
	pongMsg := tunnel.Message{
		Type: tunnel.PongMessage,
	}

	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		return
	}

	if err := conn.WriteJSON(pongMsg); err != nil {
		log.Printf("Failed to send pong: %v", err)
	}
}

// reconnect attempts to reconnect to the server.
func (c *Client) reconnect() {
	log.Println("Connection lost. Attempting to reconnect...")

	// Give some time before reconnecting
	time.Sleep(2 * time.Second)

	// Try to reconnect
	_, err := c.Connect()
	if err != nil {
		log.Printf("Reconnection failed: %v", err)
	} else {
		log.Println("Reconnected successfully")
	}

	c.mu.Lock()
	c.reconnecting = false
	c.mu.Unlock()
}

// reconnectLoop periodically checks the connection and reconnects if needed.
func (c *Client) reconnectLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if connection is still alive
			c.mu.RLock()
			conn := c.conn
			c.mu.RUnlock()

			if conn == nil {
				c.mu.Lock()
				if !c.reconnecting {
					c.reconnecting = true
					go c.reconnect()
				}
				c.mu.Unlock()
			}
		case <-c.done:
			return
		}
	}
}
