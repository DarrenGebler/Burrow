package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/DarrenGebler/burrow/pkg/config"
	"github.com/DarrenGebler/burrow/pkg/server"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	var (
		configFile      = flag.String("config", "", "Path to config file")
		port            = flag.Int("port", 8080, "Port to listen for tunnel connections")
		httpPort        = flag.Int("http-port", 80, "Port to listen for HTTP connections")
		httpsPort       = flag.Int("https-port", 443, "Port to listen for HTTPS connections")
		domain          = flag.String("domain", "", "Base domain for tunnels (optional)")
		certDir         = flag.String("cert-dir", "/etc/burrow/certs", "Directory to store certificates")
		authSecret      = flag.String("auth-secret", "", "Secret key for authentication")
		authEnabled     = flag.Bool("auth-enabled", false, "Enable authentication")
		tokenValidity   = flag.Duration("token-validity", 24*time.Hour, "Token validity duration")
		adminToken      = flag.String("admin-token", "", "Initial admin token (generated if empty)")
		version         = flag.Bool("version", false, "Print version and exit")
		subdomainOnly   = flag.Bool("subdomain-only", false, "Only serve subdomains, ignore root domain")
		tunnelSubdomain = flag.String("tunnel-subdomain", "tunnel", "Subdomain for tunnels (e.g. 'tunnel' for name.tunnel.domain.com)")
		disableHTTPS    = flag.Bool("disable-https", false, "Disable HTTPS server (useful when behind a reverse proxy)")
	)
	flag.Parse()

	if *version {
		fmt.Println("Burrow version 0.1.0")
		os.Exit(0)
	}

	// Simple approach: Load config first, then command line args take precedence
	var serverConfig *server.Config

	// First try to load config from file if specified
	if *configFile != "" {
		cfg, err := config.LoadConfig(*configFile)
		if err != nil {
			log.Printf("Warning: Failed to load config file: %v", err)
		} else {
			log.Printf("Using config file: %s", *configFile)
			// Convert config.ServerConfig to server.Config
			serverConfig = &server.Config{
				TunnelPort:      cfg.TunnelPort,
				HTTPPort:        cfg.HTTPPort,
				HTTPSPort:       cfg.HTTPSPort,
				Domain:          cfg.Domain,
				CertDir:         cfg.CertDir,
				AuthSecret:      cfg.AuthSecret,
				AuthEnabled:     cfg.AuthEnabled,
				TokenValidity:   cfg.TokenValidity,
				SubdomainOnly:   cfg.SubdomainOnly,
				TunnelSubdomain: cfg.TunnelSubdomain,
				DisableHTTPS:    cfg.DisableHTTPS,
			}
		}
	}

	// If no config file was loaded, start with default values
	if serverConfig == nil {
		serverConfig = &server.Config{
			TunnelPort:      8080,
			HTTPPort:        80,
			HTTPSPort:       443,
			Domain:          "",
			CertDir:         "/etc/burrow/certs",
			AuthSecret:      "",
			AuthEnabled:     false,
			TokenValidity:   24 * time.Hour,
			SubdomainOnly:   false,
			TunnelSubdomain: "tunnel",
			DisableHTTPS:    false,
		}
	}

	// Now apply command line arguments (these override both defaults and config file)
	serverConfig.TunnelPort = *port
	serverConfig.HTTPPort = *httpPort
	serverConfig.HTTPSPort = *httpsPort

	// Only override string values if explicitly provided (non-empty)
	if *domain != "" {
		serverConfig.Domain = *domain
	}
	if *certDir != "" {
		serverConfig.CertDir = *certDir
	}
	if *authSecret != "" {
		serverConfig.AuthSecret = *authSecret
	}
	if *tunnelSubdomain != "" {
		serverConfig.TunnelSubdomain = *tunnelSubdomain
	}

	// Boolean flags always override
	serverConfig.AuthEnabled = *authEnabled
	serverConfig.SubdomainOnly = *subdomainOnly
	serverConfig.DisableHTTPS = *disableHTTPS

	// Duration also overrides
	serverConfig.TokenValidity = *tokenValidity

	// Double-check for port conflicts
	if !serverConfig.DisableHTTPS && server.IsPortInUse(serverConfig.HTTPSPort) {
		log.Printf("Warning: HTTPS port %d is already in use, automatically disabling HTTPS", serverConfig.HTTPSPort)
		serverConfig.DisableHTTPS = true
	}

	// Create and configure the server
	srv, err := server.New(serverConfig)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if serverConfig.AuthEnabled {
		adminTokenValue := *adminToken
		if adminTokenValue == "" {
			// Generate a new admin token
			adminTokenValue, err = srv.GenerateToken("admin")
			if err != nil {
				log.Fatalf("Failed to generate admin token: %v", err)
			}
		}

		log.Printf("Admin Token: %s", adminTokenValue)
		log.Printf("Keep this token safe! It can be used to access the admin dashboard at http://localhost:%d/admin", serverConfig.TunnelPort)
	}

	// Log configuration info
	log.Printf("Starting Burrow server on port %d", serverConfig.TunnelPort)
	log.Printf("HTTP server listening on port %d", serverConfig.HTTPPort)

	if serverConfig.Domain != "" {
		if !serverConfig.DisableHTTPS {
			log.Printf("HTTPS server listening on port %d", serverConfig.HTTPSPort)
		} else {
			log.Printf("HTTPS server is disabled (using reverse proxy)")
		}
		log.Printf("Base domain: %s", serverConfig.Domain)
	}

	// Start the server in a goroutine
	go func() {
		if err := srv.Start(); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), server.ShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}

	log.Println("Server gracefully stopped")
}
