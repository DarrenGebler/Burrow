package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/DarrenGebler/burrow/pkg/server"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	var (
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

	config := &server.Config{
		TunnelPort:      *port,
		HTTPPort:        *httpPort,
		HTTPSPort:       *httpsPort,
		Domain:          *domain,
		CertDir:         *certDir,
		AuthSecret:      *authSecret,
		AuthEnabled:     *authEnabled,
		TokenValidity:   *tokenValidity,
		SubdomainOnly:   *subdomainOnly,
		TunnelSubdomain: *tunnelSubdomain,
		DisableHTTPS:    *disableHTTPS,
	}

	srv, err := server.New(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if *authEnabled {
		adminTokenValue := *adminToken
		if adminTokenValue == "" {
			// Generate a new admin token
			adminTokenValue, err = srv.GenerateToken("admin")
			if err != nil {
				log.Fatalf("Failed to generate admin token: %v", err)
			}
		}

		log.Printf("Admin Token: %s", adminTokenValue)
		log.Printf("Keep this token safe! It can be used to access the admin dashboard at http://localhost:%d/admin", *port)
	}

	go func() {
		log.Printf("Starting Burrow server on port %d", *port)
		log.Printf("HTTP server listening on port %d", *httpPort)
		if *domain != "" {
			log.Printf("HTTPS server listening on port %d", *httpsPort)
			log.Printf("Base domain: %s", *domain)
		}

		if err := srv.Start(); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}()

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
