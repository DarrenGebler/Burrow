package tunnel

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/gorilla/websocket"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

const (
	RequestMessage  = "request"
	ResponseMessage = "response"
	PingMessage     = "ping"
	PongMessage     = "pong"
)

type Message struct {
	Type    string              `json:"type"`
	ID      string              `json:"id,omitempty"`
	Method  string              `json:"method,omitempty"`
	Path    string              `json:"path,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
	Body    string              `json:"body,omitempty"`
	Status  int                 `json:"status,omitempty"`
}

type Tunnel struct {
	ID           string
	ClientID     string
	conn         *websocket.Conn
	mu           sync.RWMutex
	writeMu      sync.Mutex
	pendingReqs  map[string]http.ResponseWriter
	pingInterval time.Duration
	done         chan struct{}
	CreatedAt    time.Time
}

func NewTunnel(id string, conn *websocket.Conn) *Tunnel {
	return &Tunnel{
		ID:           id,
		ClientID:     "anonymous",
		conn:         conn,
		pendingReqs:  make(map[string]http.ResponseWriter),
		pingInterval: 30 * time.Second,
		done:         make(chan struct{}),
		CreatedAt:    time.Now(),
	}
}

// Start stats the tunnel
func (t *Tunnel) Start() {
	go t.pingRoutine()

	for {
		_, message, err := t.conn.ReadMessage()
		if err != nil {
			log.Printf("Tunnel %s read error: %s", t.ID, err)
			break
		}

		var msg Message
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Printf("Tunnel %s unmarshal error: %s", t.ID, err)
			continue
		}

		t.handleMessage(msg)
	}

	close(t.done)
	t.conn.Close()
}

// ForwardRequest forwards an HTTP request to the client
func (t *Tunnel) ForwardRequest(w http.ResponseWriter, r *http.Request) {
	reqID := GenerateRandomID(16)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Tunnel %s read error: %s", t.ID, err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	msg := Message{
		Type:    RequestMessage,
		ID:      reqID,
		Method:  r.Method,
		Path:    r.URL.String(),
		Headers: r.Header,
		Body:    base64.StdEncoding.EncodeToString(body),
	}

	t.mu.Lock()
	t.pendingReqs[reqID] = w
	t.mu.Unlock()

	t.writeMu.Lock()
	if err := t.conn.WriteJSON(msg); err != nil {
		t.writeMu.Unlock()
		log.Printf("Tunnel %s write error: %s", t.ID, err)
		http.Error(w, "Failed to write response", http.StatusInternalServerError)

		t.mu.Lock()
		delete(t.pendingReqs, reqID)
		t.mu.Unlock()
		return
	}
	t.writeMu.Unlock()
}

func (t *Tunnel) pingRoutine() {
	ticker := time.NewTicker(t.pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			msg := Message{Type: PingMessage}
			t.writeMu.Lock()
			if err := t.conn.WriteJSON(msg); err != nil {
				t.writeMu.Unlock()
				log.Printf("Tunnel %s ping error: %s", t.ID, err)
				return
			}
			t.writeMu.Unlock()
		case <-t.done:
			return
		}
	}
}

// handleMessage handles a message from the client
func (t *Tunnel) handleMessage(msg Message) {
	switch msg.Type {
	case ResponseMessage:
		t.mu.Lock()
		w, exists := t.pendingReqs[msg.ID]
		if exists {
			delete(t.pendingReqs, msg.ID)
		}
		t.mu.Unlock()

		if !exists {
			log.Printf("Tunnel %s: response for unknown request: %s", t.ID, msg.ID)
			return
		}

		for key, values := range msg.Headers {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}

		w.WriteHeader(msg.Status)

		if msg.Body != "" {
			body, err := base64.StdEncoding.DecodeString(msg.Body)
			if err != nil {
				log.Printf("Tunnel %s: error decoding body: %s", t.ID, err)
				return
			}
			w.Write(body)
		}
	case PongMessage:
		log.Printf("Tunnel %s: received pong", t.ID)
	default:
		log.Printf("Tunnel %s: unknown message type: %s", t.ID, msg.Type)
	}
}

// GenerateRandomID generates a random ID of the specified length.
func GenerateRandomID(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "fallback" + time.Now().String()
	}
	return base64.URLEncoding.EncodeToString(b)[:length]
}
