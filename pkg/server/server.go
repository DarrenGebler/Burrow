package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/DarrenGebler/burrow/pkg/auth"
	"github.com/DarrenGebler/burrow/pkg/tunnel"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme/autocert"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const ShutdownTimeout = 10 * time.Second

type Config struct {
	TunnelPort    int
	HTTPPort      int
	HTTPSPort     int
	Domain        string
	CertDir       string
	AuthSecret    string
	AuthEnabled   bool
	TokenValidity time.Duration
}

type Server struct {
	config    *Config
	upgrader  websocket.Upgrader
	tunnelSrv *http.Server
	httpSrv   *http.Server
	httpsSrv  *http.Server
	mu        sync.RWMutex
	tunnels   map[string]*tunnel.Tunnel
	auth      *auth.Authenticator
}

type TunnelInfo struct {
	ID        string    `json:"id"`
	ClientID  string    `json:"client_id"`
	CreatedAt time.Time `json:"created_at"`
	URL       string    `json:"url"`
}

func New(config *Config) (*Server, error) {
	authConfig := auth.Config{
		Secret:        config.AuthSecret,
		TokenValidity: config.TokenValidity,
		Enabled:       config.AuthEnabled,
	}

	authenticator := auth.NewAuthenticator(authConfig)

	s := &Server{
		config: config,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				if !config.AuthEnabled {
					return true
				}

				_, err := authenticator.AuthenticateRequest(r)
				return err == nil
			},
		},
		tunnels: make(map[string]*tunnel.Tunnel),
		auth:    authenticator,
	}

	tunnelMux := http.NewServeMux()
	tunnelMux.HandleFunc("/tunnel", s.handleTunnel)
	tunnelMux.HandleFunc("/admin", s.handleAdmin)

	s.tunnelSrv = &http.Server{
		Addr:    fmt.Sprintf(":%d", config.TunnelPort),
		Handler: tunnelMux,
	}

	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/", s.handleHTTP)

	s.httpSrv = &http.Server{
		Addr:    fmt.Sprintf(":%d", config.HTTPPort),
		Handler: httpMux,
	}

	if config.Domain != "" {
		httpsMux := http.NewServeMux()
		httpsMux.HandleFunc("/", s.handleHTTP)

		if err := os.MkdirAll(config.CertDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create cert dir: %w", err)
		}

		certPath := filepath.Join(config.CertDir, "fullchain.pem")
		keyPath := filepath.Join(config.CertDir, "privkey.pem")

		var tlsConfig *tls.Config
		if fileExists(certPath) && fileExists(keyPath) {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to load cert: %w", err)
			}

			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
			}

			log.Printf("Using existing certificates from %s", config.CertDir)
		} else {
			m := &autocert.Manager{
				Cache:      autocert.DirCache(config.CertDir),
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(config.Domain, "*."+config.Domain),
			}

			tlsConfig = &tls.Config{
				GetCertificate: m.GetCertificate,
			}

			s.httpSrv.Handler = m.HTTPHandler(httpMux)

			log.Printf("Using Let's Encrypt for TLS certificates")
		}

		s.httpsSrv = &http.Server{
			Addr:      fmt.Sprintf(":%d", config.HTTPSPort),
			Handler:   httpsMux,
			TLSConfig: tlsConfig,
		}
	}

	return s, nil
}

// Start starts the server
func (s *Server) Start() error {
	go func() {
		log.Printf("Starting HTTP server on port %d", s.config.HTTPPort)
		if err := s.httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("HTTP server failed: %v", err)
		}
	}()

	if s.httpsSrv != nil {
		go func() {
			log.Printf("Starting HTTPS server on port %d", s.config.HTTPSPort)
			if err := s.httpsSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("HTTPS server failed: %v", err)
			}
		}()
	}

	log.Printf("Starting tunnel server on port %d", s.config.TunnelPort)
	return s.tunnelSrv.ListenAndServe()
}

// Shutdown stops the server gracefully.
func (s *Server) Shutdown(ctx context.Context) error {
	// Shutdown tunnel server
	if err := s.tunnelSrv.Shutdown(ctx); err != nil {
		return err
	}

	// Shutdown HTTP server
	if err := s.httpSrv.Shutdown(ctx); err != nil {
		return err
	}

	// Shutdown HTTPS server if configured
	if s.httpsSrv != nil {
		if err := s.httpsSrv.Shutdown(ctx); err != nil {
			return err
		}
	}

	return nil
}

// handleTunnel handles WebSocket connections for tunnels
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	// Authenticate the request if authentication is enabled
	clientID, err := s.auth.AuthenticateRequest(r)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	subdomain := r.URL.Query().Get("subdomain")
	if subdomain == "" {
		subdomain = tunnel.GenerateRandomID(8)
	}

	s.mu.RLock()
	_, exists := s.tunnels[subdomain]
	s.mu.RUnlock()

	if exists {
		http.Error(w, "Subdomain already exists", http.StatusConflict)
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	t := tunnel.NewTunnel(subdomain, conn)
	t.ClientID = clientID

	s.mu.Lock()
	s.tunnels[subdomain] = t
	s.mu.Unlock()

	hostname := subdomain
	if s.config.Domain != "" {
		hostname = fmt.Sprintf("%s.%s", subdomain, s.config.Domain)
	}

	conn.WriteJSON(map[string]string{
		"url": fmt.Sprintf("http://%s", hostname),
	})

	go func() {
		t.Start()

		s.mu.Lock()
		delete(s.tunnels, subdomain)
		s.mu.Unlock()

		log.Printf("Tunnel %s closed", subdomain)
	}()

	log.Printf("Tunnel %s created", subdomain)
}

// handleHTTP handles incoming HTTP requests and forwards them to the appropriate tunnel
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	var subdomain string

	log.Printf("Received HTTP request: %s %s, Host: %s", r.Method, r.URL.Path, host)
	if s.config.Domain != "" && len(host) > len(s.config.Domain) && strings.HasSuffix(host, s.config.Domain) {
		subdomain = host[:len(host)-len(s.config.Domain)-1]
		log.Printf("Extracted subdomain from domain: %s", subdomain)
	} else {
		// If no domain match, use the host directly as the subdomain identifier
		subdomain = host
		log.Printf("Using host as subdomain: %s", subdomain)
	}

	// If this is a direct IP access with no subdomain specified
	// Try to see if it's in the Host header format
	if net.ParseIP(subdomain) != nil || subdomain == "localhost" {
		// This is an IP or localhost, check if we have a subdomain in a header
		headerSubdomain := r.Header.Get("X-Burrow-Subdomain")
		if headerSubdomain != "" {
			subdomain = headerSubdomain
			log.Printf("Using subdomain from header: %s", subdomain)
		} else {
			// No subdomain specified, check if we should serve admin interface
			if r.URL.Path == "/admin" {
				s.handleAdmin(w, r)
				return
			}

			// Show a listing of available tunnels if requested
			if r.URL.Path == "/tunnels" && !s.config.AuthEnabled {
				s.listTunnels(w, r)
				return
			}

			// Default info page
			s.serveInfoPage(w, r)
			return
		}
	}

	s.mu.RLock()
	t, exists := s.tunnels[subdomain]
	s.mu.RUnlock()

	if !exists {
		log.Printf("Tunnel not found for subdomain: %s", subdomain)
		http.Error(w, "Tunnel not found. Please check the subdomain or create a new tunnel.", http.StatusNotFound)
		return
	}

	log.Printf("Forwarding request to tunnel: %s", subdomain)
	t.ForwardRequest(w, r)
}

// Add a new method to list tunnels (only when auth is disabled)
func (s *Server) listTunnels(w http.ResponseWriter, r *http.Request) {
	if s.config.AuthEnabled {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	tunnelInfos := s.getTunnelInfos()

	html := `
<!DOCTYPE html>
<html>
<head>
    <title>Burrow Tunnels</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        ul {
            list-style: none;
            padding: 0;
        }
        li {
            padding: 10px;
            border-bottom: 1px solid #eee;
        }
        a {
            color: #0366d6;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <h1>Active Tunnels</h1>
    <p>The following tunnels are currently active:</p>
    <ul>
`

	if len(tunnelInfos) == 0 {
		html += `<li>No active tunnels</li>`
	} else {
		for _, info := range tunnelInfos {
			html += fmt.Sprintf(`<li><a href="%s" target="_blank">%s</a> (Created: %s)</li>`,
				info.URL, info.URL, info.CreatedAt.Format(time.RFC3339))
		}
	}

	html += `
    </ul>
    <p><em>To connect to a tunnel, use: curl -H "Host: SUBDOMAIN" http://SERVER_IP</em></p>
</body>
</html>
`

	fmt.Fprintf(w, html)
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	// Check admin authentication
	clientID, err := s.auth.AuthenticateRequest(r)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Only allow access to admin dashboard with proper authentication
	if s.config.AuthEnabled && clientID != "admin" {
		http.Error(w, "Forbidden: Admin access required", http.StatusForbidden)
		return
	}

	// Check if requesting JSON data
	if r.URL.Query().Get("format") == "json" {
		s.handleAdminJSON(w, r)
		return
	}

	// Otherwise, serve HTML dashboard
	s.serveAdminDashboard(w, r)
}

// Handle JSON API for admin dashboard
func (s *Server) handleAdminJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get tunnel info
	tunnelInfos := s.getTunnelInfos()

	// Return as JSON
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tunnels": tunnelInfos,
		"count":   len(tunnelInfos),
	})
}

// Serve HTML admin dashboard
func (s *Server) serveAdminDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	// Get tunnel info
	tunnelInfos := s.getTunnelInfos()

	// Simple HTML template for admin dashboard
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>Burrow Admin Dashboard</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #eee;
        }
        th {
            background-color: #f5f5f5;
        }
        tr:hover {
            background-color: #f9f9f9;
        }
        .empty {
            text-align: center;
            padding: 40px;
            color: #777;
        }
        .refresh {
            float: right;
            background: #4CAF50;
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 4px;
            cursor: pointer;
        }
        .refresh:hover {
            background: #45a049;
        }
    </style>
</head>
<body>
    <h1>Burrow Admin Dashboard <button class="refresh" onclick="location.reload()">Refresh</button></h1>
    
    <div>
        <strong>Active Tunnels:</strong> %d
    </div>
    
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>URL</th>
                <th>Client ID</th>
                <th>Created</th>
            </tr>
        </thead>
        <tbody>
            %s
        </tbody>
    </table>

    <script>
        // Auto-refresh every 10 seconds
        setTimeout(() => location.reload(), 10000);
    </script>
</body>
</html>
`

	rows := ""
	if len(tunnelInfos) == 0 {
		rows = `<tr><td colspan="4" class="empty">No active tunnels</td></tr>`
	} else {
		for _, info := range tunnelInfos {
			rows += fmt.Sprintf(`
                <tr>
                    <td>%s</td>
                    <td><a href="%s" target="_blank">%s</a></td>
                    <td>%s</td>
                    <td>%s</td>
                </tr>`,
				info.ID,
				info.URL,
				info.URL,
				info.ClientID,
				info.CreatedAt.Format(time.RFC3339),
			)
		}
	}

	fmt.Fprintf(w, html, len(tunnelInfos), rows)
}

// Get information about all active tunnels
func (s *Server) getTunnelInfos() []TunnelInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	infos := make([]TunnelInfo, 0, len(s.tunnels))

	for id, t := range s.tunnels {
		hostname := id
		if s.config.Domain != "" {
			hostname = fmt.Sprintf("%s.%s", id, s.config.Domain)
		}

		protocol := "http"
		if s.httpsSrv != nil {
			protocol = "https"
		}

		url := fmt.Sprintf("%s://%s", protocol, hostname)

		infos = append(infos, TunnelInfo{
			ID:        id,
			ClientID:  t.ClientID,
			CreatedAt: t.CreatedAt,
			URL:       url,
		})
	}

	return infos
}

// Add a token generation endpoint to create authentication tokens
func (s *Server) handleTokenGeneration(w http.ResponseWriter, r *http.Request) {
	// Only allow POST method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check admin authentication
	clientID, err := s.auth.AuthenticateRequest(r)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Only allow access to token generation with admin authentication
	if s.config.AuthEnabled && clientID != "admin" {
		http.Error(w, "Forbidden: Admin access required", http.StatusForbidden)
		return
	}

	// Parse request body
	var req struct {
		ClientID string `json:"client_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Generate token
	token, err := s.auth.GenerateToken(req.ClientID)
	if err != nil {
		http.Error(w, "Failed to generate token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Return token
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": token,
	})
}

func (s *Server) serveInfoPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	html := `
<!DOCTYPE html>
<html>
<head>
    <title>Burrow Tunnel Server</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        pre {
            background: #f5f5f5;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }
        .banner {
            font-family: monospace;
            white-space: pre;
            background: #f5f5f5;
            padding: 10px;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="banner">
 ____                              
|  _ \\                             
| |_) |_   _ _ __ _ __ _____      __
|  _ <| | | | '__| '__/ _ \\ \\ /\\ / /
| |_) | |_| | |  | | | (_) \\ V  V / 
|____/ \\__,_|_|  |_|  \\___/ \\_/\\_/  
    </div>
    <h1>Burrow Tunnel Server</h1>
    <p>This is a Burrow tunnel server. To use it, you need to:</p>
    <ol>
        <li>Connect a client:
            <pre>burrow connect --server %s:%d --local localhost:3000</pre>
        </li>
        <li>Access your service through the tunnel:
            <pre>curl -H "Host: YOUR_SUBDOMAIN" http://%s</pre>
        </li>
    </ol>
    <p><a href="/tunnels">View active tunnels</a> (if enabled)</p>
</body>
</html>
`

	fmt.Fprintf(w, html, r.Host, s.config.TunnelPort, r.Host)
}

// Add this helper function to check if a file exists
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func (s *Server) GenerateToken(clientID string) (string, error) {
	return s.auth.GenerateToken(clientID)
}
