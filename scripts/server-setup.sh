#!/bin/bash

set -e

print_info() {
    echo -e "\e[1;34m[INFO]\e[0m $1"
}

print_success() {
    echo -e "\e[1;32m[SUCCESS]\e[0m $1"
}

print_error() {
    echo -e "\e[1;31m[ERROR]\e[0m $1"
}

if [ "$EUID" -ne 0 ]; then
  print_error "Please run as root or with sudo"
  exit
fi

cat << "EOF"
 ____
|  _ \
| |_) |_   _ _ __ _ __ _____      __
|  _ <| | | | '__| '__/ _ \ \ /\ / /
| |_) | |_| | |  | | | (_) \ V  V /
|____/ \__,_|_|  |_|  \___/ \_/\_/

EOF
print_info "Open-source secure tunneling service"
echo

DOMAIN=""
EMAIL=""
HTTP_PORT=80
HTTPS_PORT=443
TUNNEL_PORT=8080
INSTALL_DIR="/opt/burrow"
AUTH_ENABLED="false"
AUTH_SECRET=""
USE_NGINX="false"
TUNNEL_SUBDOMAIN="tunnel"
SUBDOMAIN_ONLY="true"

while [[ $# -gt 0 ]]; do
    case $1 in
        --domain)
            DOMAIN="$2"
            shift 2
            ;;
        --email)
            EMAIL="$2"
            shift 2
            ;;
        --http-port)
            HTTP_PORT="$2"
            shift 2
            ;;
        --https-port)
            HTTPS_PORT="$2"
            shift 2
            ;;
        --tunnel-port)
            TUNNEL_PORT="$2"
            shift 2
            ;;
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --auth-enabled)
            AUTH_ENABLED="$2"
            shift 2
            ;;
        --auth-secret)
            AUTH_SECRET="$2"
            shift 2
            ;;
        --use-nginx)
            USE_NGINX="$2"
            shift 2
            ;;
        --tunnel-subdomain)
            TUNNEL_SUBDOMAIN="$2"
            shift 2
            ;;
        --subdomain-only)
            SUBDOMAIN_ONLY="$2"
            shift 2
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Get server IP
SERVER_IP=$(curl -s ifconfig.me)
if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(hostname -I | awk '{print $1}')
fi

print_info "Installing dependencies..."
apt-get update
apt-get install -y git curl wget certbot libcap2-bin

if [ "$USE_NGINX" = "true" ]; then
    apt-get install -y nginx
fi

# Install Go 1.23.0
print_info "Installing Go 1.23.0..."
GO_VERSION="1.23.0"
GO_TAR_FILE="go$GO_VERSION.linux-amd64.tar.gz"
GO_DOWNLOAD_URL="https://go.dev/dl/$GO_TAR_FILE"

# Download Go
cd /tmp
wget $GO_DOWNLOAD_URL

# Remove any existing Go installation and install the new one
rm -rf /usr/local/go
tar -C /usr/local -xzf $GO_TAR_FILE
rm $GO_TAR_FILE

# Add Go to PATH for all users
echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
chmod +x /etc/profile.d/go.sh
source /etc/profile.d/go.sh

# Verify Go installation
go version

# Create burrow user
print_info "Creating burrow user..."
id -u burrow &>/dev/null || useradd -m -s /bin/bash burrow

# Create installation directory
print_info "Creating installation directory..."
mkdir -p $INSTALL_DIR
chown burrow:burrow $INSTALL_DIR

# Build from source (or download release)
print_info "Building Burrow from source..."
git clone https://github.com/DarrenGebler/burrow.git /tmp/burrow-src
cd /tmp/burrow-src

# Set GOPATH and add it to PATH
export GOPATH=/tmp/gopath
export PATH=$PATH:$GOPATH/bin
mkdir -p $GOPATH

# Download dependencies and build
go mod download
go build -o $INSTALL_DIR/burrowd cmd/burrowd/main.go
chown burrow:burrow $INSTALL_DIR/burrowd
chmod +x $INSTALL_DIR/burrowd

# Create configuration directory
print_info "Creating configuration..."
mkdir -p /etc/burrow
mkdir -p /etc/burrow/certs
chown -R burrow:burrow /etc/burrow

# Generate random auth secret if not provided
if [ -z "$AUTH_SECRET" ] && [ "$AUTH_ENABLED" = "true" ]; then
    AUTH_SECRET=$(openssl rand -hex 16)
    print_info "Generated random auth secret: $AUTH_SECRET"
fi

# If using Nginx as a reverse proxy, set up Burrow with non-privileged ports
BURROW_HTTP_PORT=$HTTP_PORT
if [ "$USE_NGINX" = "true" ]; then
    BURROW_HTTP_PORT=8080
    print_info "Using Nginx as reverse proxy. Burrow HTTP port set to $BURROW_HTTP_PORT"
fi

if [ ! -z "$DOMAIN" ] && [ ! -z "$EMAIL" ]; then
    print_info "Setting up SSL for $DOMAIN..."

    # First try to get wildcard cert for *.tunnel.domain.com
    certbot certonly --manual --preferred-challenges dns \
      --agree-tos --email $EMAIL \
      -d "$DOMAIN" -d "*.$DOMAIN" \
      --manual-public-ip-logging-ok

    # Link certificates to Burrow certificate directory
    ln -sf /etc/letsencrypt/live/$DOMAIN/fullchain.pem /etc/burrow/certs/fullchain.pem
    ln -sf /etc/letsencrypt/live/$DOMAIN/privkey.pem /etc/burrow/certs/privkey.pem
    chown -h burrow:burrow /etc/burrow/certs/fullchain.pem /etc/burrow/certs/privkey.pem

    # Set up certificate renewal
    cat > /etc/cron.d/burrow-cert-renewal << EOF
0 0 * * * root certbot renew --quiet && systemctl restart burrow
EOF

    # Show DNS configuration instructions
    echo ""
    echo "IMPORTANT: Please add these DNS records:"
    echo "    Type: A"
    echo "    Name: $DOMAIN"
    echo "    Value: $SERVER_IP"
    echo ""
    echo "Also add this record:"
    echo "    Type: A"
    echo "    Name: *.$DOMAIN"
    echo "    Value: $SERVER_IP"
    echo ""
fi

# Create systemd service
print_info "Creating systemd service..."
ADMIN_PORT=8081
cat > /etc/systemd/system/burrow.service << EOF
[Unit]
Description=Burrow Tunnel Server
After=network.target

[Service]
User=burrow
ExecStart=$INSTALL_DIR/burrowd --port $ADMIN_PORT --http-port $HTTP_PORT --https-port $HTTPS_PORT --domain "$DOMAIN" --tunnel-subdomain "$TUNNEL_SUBDOMAIN" --subdomain-only $SUBDOMAIN_ONLY --cert-dir /etc/burrow/certs --auth-enabled $AUTH_ENABLED --auth-secret "$AUTH_SECRET"
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Configure firewall
print_info "Configuring firewall..."
if command -v ufw > /dev/null; then
    ufw allow ssh
    ufw allow $HTTP_PORT/tcp
    ufw allow $HTTPS_PORT/tcp
    ufw allow $ADMIN_PORT/tcp
    ufw --force enable
elif command -v firewall-cmd > /dev/null; then
    firewall-cmd --permanent --add-port=$HTTP_PORT/tcp
    firewall-cmd --permanent --add-port=$HTTPS_PORT/tcp
    firewall-cmd --permanent --add-port=$ADMIN_PORT/tcp
    firewall-cmd --reload
else
    print_info "No firewall detected, skipping firewall configuration"
fi

# Set up SSL if domain is provided
if [ ! -z "$DOMAIN" ] && [ ! -z "$EMAIL" ]; then
    print_info "Setting up SSL for $DOMAIN..."
    certbot certonly --standalone --non-interactive --agree-tos --email $EMAIL -d $DOMAIN -d "*.$DOMAIN"

    # Link certificates to Burrow certificate directory
    ln -sf /etc/letsencrypt/live/$DOMAIN/fullchain.pem /etc/burrow/certs/fullchain.pem
    ln -sf /etc/letsencrypt/live/$DOMAIN/privkey.pem /etc/burrow/certs/privkey.pem
    chown -h burrow:burrow /etc/burrow/certs/fullchain.pem /etc/burrow/certs/privkey.pem

    # Set up certificate renewal
    cat > /etc/cron.d/burrow-cert-renewal << EOF
0 0 * * * root certbot renew --quiet && systemctl restart burrow
EOF
fi

# Setup Nginx as reverse proxy if requested
if [ "$USE_NGINX" = "true" ]; then
    print_info "Setting up Nginx as reverse proxy..."

    # Create Nginx configuration
    cat > /etc/nginx/sites-available/burrow << EOF
server {
    listen $HTTP_PORT;
    server_name $TUNNEL_SUBDOMAIN.$DOMAIN *.$TUNNEL_SUBDOMAIN.$DOMAIN;

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen $HTTPS_PORT ssl;
    server_name $TUNNEL_SUBDOMAIN.$DOMAIN *.$TUNNEL_SUBDOMAIN.$DOMAIN;

    ssl_certificate /etc/burrow/certs/fullchain.pem;
    ssl_certificate_key /etc/burrow/certs/privkey.pem;

    # Handle WebSocket connections on standard port
    location /tunnel {
        proxy_pass http://localhost:$ADMIN_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }

    # Regular HTTP traffic
    location / {
        proxy_pass http://localhost:$BURROW_HTTP_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}

server {
    listen $HTTP_PORT default_server;
    server_name _;

    location / {
        proxy_pass http://localhost:$BURROW_HTTP_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF

    # Enable the site
    ln -sf /etc/nginx/sites-available/burrow /etc/nginx/sites-enabled/default

    # Test Nginx configuration
    nginx -t || print_error "Nginx configuration test failed"

    # Restart Nginx
    systemctl restart nginx
else
    # If not using Nginx, stop and disable it if it's installed
    if systemctl list-unit-files | grep -q nginx; then
        print_info "Stopping and disabling Nginx..."
        systemctl stop nginx
        systemctl disable nginx
    fi

    # Set capability to bind to privileged ports
    print_info "Setting capability to bind to privileged ports..."
    setcap 'cap_net_bind_service=+ep' $INSTALL_DIR/burrowd
fi

# Enable and start Burrow service
print_info "Starting Burrow service..."
systemctl daemon-reload
systemctl enable burrow
systemctl start burrow

# Check if service is running
sleep 2
if systemctl is-active --quiet burrow; then
    print_success "Burrow service is running"
else
    print_error "Burrow service failed to start. Check logs with: journalctl -u burrow"
    exit 1
fi

# Print connection information
print_success "Burrow server setup complete!"
echo
echo "Server information:"
echo "==================="
if [ ! -z "$DOMAIN" ]; then
    echo "Domain: $DOMAIN"
    echo "Tunnel subdomain: $TUNNEL_SUBDOMAIN.$DOMAIN"
    echo "Tunnel URL format: https://your-tunnel-name.$TUNNEL_SUBDOMAIN.$DOMAIN"
    echo "Admin interface: https://$TUNNEL_SUBDOMAIN.$DOMAIN:$ADMIN_PORT/admin"
else
    echo "Server IP: $SERVER_IP"
    echo "Tunnel URL: http://$SERVER_IP"
fi
echo "Tunnel connection port: $ADMIN_PORT"
echo

if [ "$AUTH_ENABLED" = "true" ]; then
    echo "Authentication is enabled"
    echo "Secret: $AUTH_SECRET"
    echo
    echo "To generate a client token, run:"
    echo "curl -X POST http://$SERVER_IP:$TUNNEL_PORT/admin/token -H 'Authorization: Bearer <admin-token>' -d '{\"client_id\":\"client1\"}'"
    echo
fi

echo "Connect from your local machine:"
echo "=============================="
if [ ! -z "$DOMAIN" ]; then
    echo "burrow connect --server $TUNNEL_SUBDOMAIN.$DOMAIN --secure --local localhost:8080"
    if [ "$AUTH_ENABLED" = "true" ]; then
        echo "burrow connect --server $TUNNEL_SUBDOMAIN.$DOMAIN --secure --local localhost:8080 --auth-token <your-token>"
    fi
else
    echo "burrow connect --server $SERVER_IP:$ADMIN_PORT --local localhost:8080"
    if [ "$AUTH_ENABLED" = "true" ]; then
        echo "burrow connect --server $SERVER_IP:$ADMIN_PORT --local localhost:8080 --auth-token <your-token>"
    fi
fi

exit 0