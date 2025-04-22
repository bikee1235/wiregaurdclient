#!/bin/bash
# WireGuard VPN Cloud Server Setup Script
# This script sets up a WireGuard VPN server on an AWS EC2 instance
# to serve as a cloud VPN endpoint for the management server architecture.

# Exit on any error
set -e

# Display script header
echo "============================================================"
echo "  WireGuard VPN Cloud Server Setup Script"
echo "============================================================"
echo "  This script will set up a WireGuard VPN server on an AWS"
echo "  EC2 instance to work with the management server architecture."
echo "============================================================"
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
   echo "This script must be run as root" 
   exit 1
fi

# Read configuration parameters
read -p "Enter the VPN subnet (e.g., 10.1.0.0/24): " VPN_SUBNET
read -p "Enter the server port (default: 51820): " SERVER_PORT
SERVER_PORT=${SERVER_PORT:-51820}
read -p "Enter the management server public key: " MANAGEMENT_PUBLIC_KEY
read -p "Enter the management server public IP: " MANAGEMENT_IP

# Extract subnet components
SUBNET_IP=${VPN_SUBNET%/*}
SUBNET_MASK=${VPN_SUBNET#*/}
IFS='.' read -r -a IP_PARTS <<< "$SUBNET_IP"
IP_PARTS[3]=1
SERVER_IP="${IP_PARTS[0]}.${IP_PARTS[1]}.${IP_PARTS[2]}.${IP_PARTS[3]}/${SUBNET_MASK}"

# Install required packages
echo "[+] Installing required packages..."
apt update
apt install -y wireguard wireguard-tools

# Enable IP forwarding
echo "[+] Enabling IP forwarding..."
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-wireguard.conf
echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/99-wireguard.conf
sysctl -p /etc/sysctl.d/99-wireguard.conf

# Create directory
echo "[+] Creating WireGuard directory..."
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

# Generate server keys
echo "[+] Generating server keys..."
cd /etc/wireguard
umask 077
wg genkey | tee cloud_private.key | wg pubkey > cloud_public.key

# Create server configuration
echo "[+] Creating server configuration..."
cat > /etc/wireguard/wg0.conf << EOF
[Interface]
Address = $SERVER_IP
ListenPort = $SERVER_PORT
PrivateKey = $(cat cloud_private.key)
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Management Server
[Peer]
PublicKey = $MANAGEMENT_PUBLIC_KEY
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
EOF

# Start WireGuard
echo "[+] Starting WireGuard service..."
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# Add iptables rules to persist after reboot
echo "[+] Adding persistent iptables rules..."
apt install -y iptables-persistent
netfilter-persistent save

# Display success message
echo "[+] WireGuard VPN Cloud Server setup complete!"
echo ""
echo "Server Information:"
echo "  Public Key: $(cat cloud_public.key)"
echo "  Server IP: $SERVER_IP"
echo "  Listen Port: $SERVER_PORT"
echo ""
echo "Next steps:"
echo "1. Ensure your AWS security group allows UDP port $SERVER_PORT inbound"
echo "2. Add this cloud server to your management interface with the following details:"
echo "   - Public Key: $(cat cloud_public.key)"
echo "   - Endpoint: $(curl -s http://checkip.amazonaws.com):$SERVER_PORT"
echo "   - Subnet: $VPN_SUBNET"
echo ""
echo "3. To verify the connection with the management server, use:"
echo "   sudo wg show"
echo ""
