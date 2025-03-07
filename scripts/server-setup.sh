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
apt-get install -y git curl wget certbot nginx

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

# Build the server binary
go build -o $INSTALL_DIR/burrowd cmd/burrowd/main.go
chown burrow:burrow $INSTALL_DIR/burrowd
chmod +x $INSTALL_DIR/burrowd

# Create configuration directory
print_info "Creating configuration..."
mkdir -p /etc/burrow
mkdir -p /etc/burrow/certs
chown -R burrow:burrow /etc/burrow

# Create systemd service
print_info "Creating systemd service..."
cat > /etc/systemd/system/burrow.service << EOF
[Unit]
Description=Burrow Tunnel Server
After=network.target

[Service]
User=burrow
ExecStart=$INSTALL_DIR/burrowd --port $TUNNEL_PORT --http-port $HTTP_PORT --https-port $HTTPS_PORT --domain "$DOMAIN" --cert-dir /etc/burrow/certs
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
    ufw allow $TUNNEL_PORT/tcp
    ufw --force enable
elif command -v firewall-cmd > /dev/null; then
    firewall-cmd --permanent --add-port=$HTTP_PORT/tcp
    firewall-cmd --permanent --add-port=$HTTPS_PORT/tcp
    firewall-cmd --permanent --add-port=$TUNNEL_PORT/tcp
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
    echo "Domain: $DOMAIN (Make sure DNS records point to $SERVER_IP)"
    echo "Tunnel URL: http://<subdomain>.$DOMAIN"
else
    echo "Server IP: $SERVER_IP"
    echo "Tunnel URL: http://$SERVER_IP"
fi
echo "Tunnel port: $TUNNEL_PORT"
echo
echo "Connect from your local machine:"
echo "=============================="
echo "burrow connect --server $SERVER_IP:$TUNNEL_PORT --local localhost:8080"
echo
echo "To view logs:"
echo "journalctl -u burrow -f"
echo

exit 0