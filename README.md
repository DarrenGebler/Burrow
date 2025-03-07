# Burrow: Self-hosted Secure Tunneling

Burrow is an open-source alternative to ngrok that lets you expose local services to the internet.

## Server Setup

### Quick Start with EC2

1. Launch an EC2 instance (Ubuntu recommended)
2. Configure security groups:
    - SSH (22)
    - HTTP (80)
    - HTTPS (443)
    - Tunnel (8080)
3. SSH into your instance
4. Run the setup script:

```bash
# Basic setup
sudo bash scripts/server-setup.sh

# With authentication enabled
sudo bash scripts/server-setup.sh --auth-enabled true

# With Nginx as reverse proxy (recommended for production)
sudo bash scripts/server-setup.sh --use-nginx true

# With a custom domain
sudo bash scripts/server-setup.sh --domain yourdomain.com --email your@email.com
```

### Common Issues

1. **Port 80/443 binding issues**: By default, the script will use `setcap` to allow the binary to bind to privileged ports. If you still have issues, use `--use-nginx true`.

2. **Nginx conflict**: The setup script will either stop nginx or configure it as a reverse proxy. If you see the nginx welcome page, use `sudo systemctl stop nginx`.

3. **Security groups**: Make sure your EC2 security groups allow traffic on the necessary ports (8080, 80, 443).

## Client Usage

### Install the Client

```bash
# Build from source
go build -o burrow ./cmd/burrow
```

### Connect to a Server

```bash
# Basic connection
./burrow connect --server your-server-ip:8080 --local localhost:3000

# With a custom subdomain
./burrow connect --server your-server-ip:8080 --local localhost:3000 --subdomain myapp

# With authentication
./burrow connect --server your-server-ip:8080 --local localhost:3000 --auth-token your-token
```

### Testing the Connection

Once your tunnel is established, you can access your local service through:

```bash
# Using curl with Host header
curl -H "Host: yoursubdomain" http://your-server-ip

# Or with a domain
curl http://yoursubdomain.yourdomain.com
```

### Troubleshooting Connections

Use the provided test script:

```bash
./test-tunnel.sh your-server-ip yoursubdomain
```

## Administration

### View Active Tunnels

Visit the admin dashboard:

```
http://your-server-ip:8080/admin
```

### Generate Authentication Tokens

With authentication enabled, you'll need to generate tokens for clients:

```bash
curl -X POST http://your-server-ip:8080/admin/token \
  -H 'Authorization: Bearer your-admin-token' \
  -d '{"client_id":"client1"}'
```

## Advanced Configuration

### Using a Custom Domain

1. Register a domain and point it to your server IP
2. Add wildcard DNS: `*.yourdomain.com` → your-server-ip
3. Configure Burrow with the domain:

```bash
sudo bash scripts/server-setup.sh --domain yourdomain.com --email your@email.com
```

### Using Nginx as Reverse Proxy

For production deployments, using Nginx as a reverse proxy is recommended:

```bash
sudo bash scripts/server-setup.sh --use-nginx true
```

This configuration:
- Improves stability and security
- Allows serving static content alongside tunnels
- Enables better logging and rate limiting

## Development

### Running Tests

```bash
go test ./...
```

### Building from Source

```bash
go build -o burrowd ./cmd/burrowd
go build -o burrow ./cmd/burrow
```
