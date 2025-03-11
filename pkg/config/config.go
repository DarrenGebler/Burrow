package config

import (
	"fmt"
	"github.com/DarrenGebler/burrow/pkg/server"
	"gopkg.in/yaml.v2"
	"os"
	"strconv"
	"time"
)

type ServerConfig struct {
	// Server ports
	TunnelPort int `yaml:"tunnel_port"`
	HTTPPort   int `yaml:"http_port"`
	HTTPSPort  int `yaml:"https_port"`

	// Domain settings
	Domain          string `yaml:"domain"`
	TunnelSubdomain string `yaml:"tunnel_subdomain"`
	SubdomainOnly   bool   `yaml:"subdomain_only"`

	// TLS settings
	CertDir      string `yaml:"cert_dir"`
	DisableHTTPS bool   `yaml:"disable_https"`

	// Authentication
	AuthEnabled   bool          `yaml:"auth_enabled"`
	AuthSecret    string        `yaml:"auth_secret"`
	TokenValidity time.Duration `yaml:"token_validity"`

	// Runtime flags
	IsNginxEnabled bool `yaml:"-"` // Detected at runtime, not from config
}

func LoadConfig(filename string) (*ServerConfig, error) {
	config := &ServerConfig{
		TunnelPort:      8080,
		HTTPPort:        80,
		HTTPSPort:       443,
		TunnelSubdomain: "tunnel",
		CertDir:         "/etc/burrow/certs",
		TokenValidity:   24 * time.Hour,
	}

	if _, err := os.Stat(filename); err == nil {
		data, err := os.ReadFile(filename)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %v", err)
		}

		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %v", err)
		}
	}

	if port := os.Getenv("BURROW_TUNNEL_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			config.TunnelPort = p
		}
	}

	if port := os.Getenv("BURROW_HTTP_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			config.HTTPPort = p
		}
	}

	config.IsNginxEnabled = isNginxRunning()

	// If nginx is running on port 80 or 443, auto-disable HTTPS
	if config.IsNginxEnabled && !config.DisableHTTPS {
		if server.IsPortInUse(80) || server.IsPortInUse(443) {
			config.DisableHTTPS = true
		}
	}

	return config, nil
}

func isNginxRunning() bool {
	// Check for common nginx process or port usage
	if _, err := os.Stat("/var/run/nginx.pid"); err == nil {
		return true
	}
	return false
}
