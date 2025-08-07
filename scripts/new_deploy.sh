#!/bin/bash

set -e

# Configuration
DOMAIN="staging.visualaiagentsbuilder.com"
EMAIL="forwardemailforaifirstdesk@gmail.com"
DOCKER_IMAGE="forwardemailforaifirstdesk/langflow:1.4.2"
CONTAINER_NAME="langflow"

echo "[1/6] Pulling the latest Docker image..."
docker pull "$DOCKER_IMAGE"

echo "[2/6] Stopping and removing any existing container..."
docker rm -f "$CONTAINER_NAME" || true

echo "[3/6] Running Docker container on internal port 7860..."
docker run -d --name "$CONTAINER_NAME" -p 7860:7860 \
  -e LANGFLOW_AUTO_LOGIN=false \
  -e LANGFLOW_CLERK_AUTH_ENABLED=true \
  -e LANGFLOW_CLERK_PUBLISHABLE_KEY=pk_test_Y2hhcm1lZC1iYXQtNDEuY2xlcmsuYWNjb3VudHMuZGV2JA \
  "$DOCKER_IMAGE"

echo "[4/6] Installing Nginx and Certbot..."
sudo apt-get update -y
sudo apt-get install -y nginx certbot python3-certbot-nginx

echo "[5/6] Configuring Nginx reverse proxy for $DOMAIN..."
NGINX_CONF="/etc/nginx/sites-available/$DOMAIN"
sudo tee "$NGINX_CONF" > /dev/null <<EOF
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        proxy_pass http://localhost:7860;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

sudo ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

echo "[6/6] Requesting Let's Encrypt SSL certificate for $DOMAIN..."
sudo certbot --nginx --non-interactive --agree-tos --redirect \
  --email "$EMAIL" -d "$DOMAIN"

echo "✅ Deployment complete!"
echo "Visit: https://$DOMAIN to access the running application."
