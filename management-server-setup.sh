#!/bin/bash
# WireGuard VPN Management Server Setup Script
# This script sets up a WireGuard VPN management server that can route traffic to multiple
# AWS cloud VPN servers in different locations.

# Exit on any error
set -e

# Display script header
echo "============================================================"
echo "  WireGuard VPN Management Server Setup Script"
echo "============================================================"
echo "  This script will set up a WireGuard VPN management server"
echo "  to handle connections from mobile devices and route through"
echo "  different AWS cloud VPN servers."
echo "============================================================"
echo ""

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
   echo "This script must be run as root" 
   exit 1
fi

# Configuration variables
PUBLIC_IP="182.66.251.101"
PRIVATE_IP="172.16.118.84"
SERVER_PORT=51820
VPN_SUBNET="10.0.0.0/24"
VPN_ADDRESS="10.0.0.1/24"
CLOUD_CONFIGS_DIR="/etc/wireguard/cloud_configs"

# Install required packages
echo "[+] Installing required packages..."
apt update
apt install -y wireguard wireguard-tools qrencode sqlite3 apache2 php php-sqlite3 curl

# Enable IP forwarding
echo "[+] Enabling IP forwarding..."
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-wireguard.conf
echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/99-wireguard.conf
sysctl -p /etc/sysctl.d/99-wireguard.conf

# Create directories
echo "[+] Creating directories..."
mkdir -p /etc/wireguard/clients
mkdir -p $CLOUD_CONFIGS_DIR
chmod 700 /etc/wireguard/clients
chmod 700 $CLOUD_CONFIGS_DIR

# Generate server keys
echo "[+] Generating server keys..."
cd /etc/wireguard
umask 077
wg genkey | tee server_private.key | wg pubkey > server_public.key

# Create server configuration
echo "[+] Creating server configuration..."
cat > /etc/wireguard/wg0.conf << EOF
[Interface]
Address = $VPN_ADDRESS
ListenPort = $SERVER_PORT
PrivateKey = $(cat server_private.key)
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Cloud VPN servers will be added here
EOF

# Create clients database
echo "[+] Creating clients database..."
sqlite3 /etc/wireguard/clients.db << EOF
CREATE TABLE clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL UNIQUE,
    private_key TEXT NOT NULL,
    ip_address TEXT NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    route_preference TEXT DEFAULT "management",
    cloud_server TEXT DEFAULT NULL
);

CREATE TABLE cloud_servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    public_key TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    subnet TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active INTEGER DEFAULT 1
);
EOF

# Create cloud servers table for the initial AWS cloud VPN
echo "[+] Adding initial AWS Cloud VPN to database..."
sqlite3 /etc/wireguard/clients.db << EOF
INSERT INTO cloud_servers (name, description, public_key, endpoint, subnet) 
VALUES ('aws-virginia', 'AWS US East (Virginia)', '', '34.251.70.167:51820', '10.1.0.0/24');
EOF

# Create the web management interface
echo "[+] Creating web management interface..."
mkdir -p /var/www/html/wireguard-manager
cat > /var/www/html/wireguard-manager/index.php << 'EOF'
<?php
// WireGuard VPN Manager Interface
$db = new SQLite3('/etc/wireguard/clients.db');

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'add_client':
                add_client($_POST);
                break;
            case 'update_route':
                update_client_route($_POST);
                break;
            case 'add_cloud_server':
                add_cloud_server($_POST);
                break;
            case 'toggle_cloud_server':
                toggle_cloud_server($_POST);
                break;
        }
    }
}

function add_client($data) {
    global $db;
    
    if (!isset($data['client_name']) || trim($data['client_name']) === '') {
        return;
    }
    
    // Generate keys
    $private_key = trim(shell_exec('wg genkey'));
    $public_key = trim(shell_exec('echo ' . escapeshellarg($private_key) . ' | wg pubkey'));
    
    // Assign IP (simple incremental approach)
    $result = $db->query("SELECT COUNT(*) as count FROM clients");
    $row = $result->fetchArray();
    $client_count = $row['count'] + 2; // Start from 10.0.0.2
    $ip_address = "10.0.0.{$client_count}/24";
    
    // Insert client
    $stmt = $db->prepare("INSERT INTO clients (name, public_key, private_key, ip_address) VALUES (:name, :public_key, :private_key, :ip_address)");
    $stmt->bindValue(':name', $data['client_name'], SQLITE3_TEXT);
    $stmt->bindValue(':public_key', $public_key, SQLITE3_TEXT);
    $stmt->bindValue(':private_key', $private_key, SQLITE3_TEXT);
    $stmt->bindValue(':ip_address', $ip_address, SQLITE3_TEXT);
    $stmt->execute();
    
    // Update WireGuard configuration
    update_wireguard_config();
}

function update_client_route($data) {
    global $db;
    
    if (!isset($data['client_id']) || !isset($data['route_preference'])) {
        return;
    }
    
    // Update route preference
    $stmt = $db->prepare("UPDATE clients SET route_preference = :route, cloud_server = :cloud_server WHERE id = :id");
    $stmt->bindValue(':route', $data['route_preference'], SQLITE3_TEXT);
    $stmt->bindValue(':cloud_server', isset($data['cloud_server']) ? $data['cloud_server'] : null, SQLITE3_TEXT);
    $stmt->bindValue(':id', $data['client_id'], SQLITE3_INTEGER);
    $stmt->execute();
    
    // Update WireGuard configuration
    update_wireguard_config();
}

function add_cloud_server($data) {
    global $db;
    
    if (!isset($data['server_name']) || !isset($data['endpoint']) || !isset($data['subnet'])) {
        return;
    }
    
    // Read the public key from file
    $public_key = '';
    if (file_exists("/etc/wireguard/cloud_configs/{$data['server_name']}_public.key")) {
        $public_key = trim(file_get_contents("/etc/wireguard/cloud_configs/{$data['server_name']}_public.key"));
    }
    
    // Insert cloud server
    $stmt = $db->prepare("INSERT INTO cloud_servers (name, description, public_key, endpoint, subnet) VALUES (:name, :description, :public_key, :endpoint, :subnet)");
    $stmt->bindValue(':name', $data['server_name'], SQLITE3_TEXT);
    $stmt->bindValue(':description', $data['description'], SQLITE3_TEXT);
    $stmt->bindValue(':public_key', $public_key, SQLITE3_TEXT);
    $stmt->bindValue(':endpoint', $data['endpoint'], SQLITE3_TEXT);
    $stmt->bindValue(':subnet', $data['subnet'], SQLITE3_TEXT);
    $stmt->execute();
    
    // Update WireGuard configuration
    update_wireguard_config();
}

function toggle_cloud_server($data) {
    global $db;
    
    if (!isset($data['server_id'])) {
        return;
    }
    
    // Get current status
    $stmt = $db->prepare("SELECT is_active FROM cloud_servers WHERE id = :id");
    $stmt->bindValue(':id', $data['server_id'], SQLITE3_INTEGER);
    $result = $stmt->execute();
    $row = $result->fetchArray();
    $current_status = $row['is_active'];
    
    // Toggle status
    $new_status = $current_status ? 0 : 1;
    $stmt = $db->prepare("UPDATE cloud_servers SET is_active = :status WHERE id = :id");
    $stmt->bindValue(':status', $new_status, SQLITE3_INTEGER);
    $stmt->bindValue(':id', $data['server_id'], SQLITE3_INTEGER);
    $stmt->execute();
    
    // Update WireGuard configuration
    update_wireguard_config();
}

function update_wireguard_config() {
    global $db;
    
    // Get server info
    $serverPrivateKey = trim(file_get_contents('/etc/wireguard/server_private.key'));
    
    // Basic server config
    $config = "[Interface]\n";
    $config .= "Address = 10.0.0.1/24\n";
    $config .= "ListenPort = 51820\n";
    $config .= "PrivateKey = {$serverPrivateKey}\n";
    $config .= "PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n";
    $config .= "PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE\n\n";
    
    // Add cloud server peers
    $result = $db->query("SELECT * FROM cloud_servers WHERE is_active = 1 AND public_key != ''");
    while ($server = $result->fetchArray(SQLITE3_ASSOC)) {
        $config .= "# Cloud Server: {$server['name']} - {$server['description']}\n";
        $config .= "[Peer]\n";
        $config .= "PublicKey = {$server['public_key']}\n";
        $config .= "Endpoint = {$server['endpoint']}\n";
        $config .= "AllowedIPs = {$server['subnet']}\n";
        $config .= "PersistentKeepalive = 25\n\n";
    }
    
    // Add clients
    $result = $db->query("SELECT * FROM clients");
    while ($client = $result->fetchArray(SQLITE3_ASSOC)) {
        $config .= "# Client: {$client['name']}\n";
        $config .= "[Peer]\n";
        $config .= "PublicKey = {$client['public_key']}\n";
        $config .= "AllowedIPs = " . str_replace('/24', '/32', $client['ip_address']) . "\n";
        
        if ($client['route_preference'] == 'cloud') {
            $config .= "# Route through cloud VPN: {$client['cloud_server']}\n\n";
        } else {
            $config .= "# Route through management server\n\n";
        }
    }
    
    // Write config
    file_put_contents('/etc/wireguard/wg0.conf.new', $config);
    exec('sudo mv /etc/wireguard/wg0.conf.new /etc/wireguard/wg0.conf');
    exec('sudo systemctl restart wg-quick@wg0');
}

// HTML Output
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WireGuard VPN Manager</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1, h2 { color: #333; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        table, th, td { border: 1px solid #ddd; }
        th, td { padding: 10px; text-align: left; }
        th { background-color: #f2f2f2; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; }
        input, select { padding: 8px; width: 100%; box-sizing: border-box; }
        button { padding: 10px 15px; background-color: #4CAF50; color: white; border: none; cursor: pointer; }
        button:hover { background-color: #45a049; }
        .tabs { overflow: hidden; border: 1px solid #ccc; background-color: #f1f1f1; }
        .tab-button { background-color: inherit; float: left; border: none; outline: none; cursor: pointer; padding: 14px 16px; transition: 0.3s; }
        .tab-button:hover { background-color: #ddd; }
        .tab-button.active { background-color: #ccc; }
        .tab-content { display: none; padding: 6px 12px; border: 1px solid #ccc; border-top: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>WireGuard VPN Manager</h1>
        
        <div class="tabs">
            <button class="tab-button active" onclick="openTab(event, 'clients')">Clients</button>
            <button class="tab-button" onclick="openTab(event, 'cloud-servers')">Cloud Servers</button>
            <button class="tab-button" onclick="openTab(event, 'system-status')">System Status</button>
        </div>
        
        <div id="clients" class="tab-content" style="display: block;">
            <h2>Add New Client</h2>
            <form method="post">
                <input type="hidden" name="action" value="add_client">
                <div class="form-group">
                    <label for="client_name">Client Name:</label>
                    <input type="text" id="client_name" name="client_name" required>
                </div>
                <button type="submit">Add Client</button>
            </form>
            
            <h2>Client List</h2>
            <table>
                <tr>
                    <th>Name</th>
                    <th>IP Address</th>
                    <th>Routing Preference</th>
                    <th>Actions</th>
                    <th>QR Code</th>
                </tr>
                <?php
                $result = $db->query("SELECT * FROM clients ORDER BY name");
                while ($client = $result->fetchArray(SQLITE3_ASSOC)):
                ?>
                <tr>
                    <td><?php echo htmlspecialchars($client['name']); ?></td>
                    <td><?php echo htmlspecialchars($client['ip_address']); ?></td>
                    <td>
                        <form method="post">
                            <input type="hidden" name="action" value="update_route">
                            <input type="hidden" name="client_id" value="<?php echo $client['id']; ?>">
                            <select name="route_preference" onchange="toggleCloudServerSelect(this)">
                                <option value="management" <?php echo $client['route_preference'] == 'management' ? 'selected' : ''; ?>>Via Management Server</option>
                                <option value="cloud" <?php echo $client['route_preference'] == 'cloud' ? 'selected' : ''; ?>>Via Cloud Server</option>
                            </select>
                            <div id="cloud-server-select-<?php echo $client['id']; ?>" style="<?php echo $client['route_preference'] == 'cloud' ? 'display:block;' : 'display:none;'; ?> margin-top: 5px;">
                                <select name="cloud_server">
                                    <?php
                                    $servers = $db->query("SELECT * FROM cloud_servers WHERE is_active = 1");
                                    while ($server = $servers->fetchArray(SQLITE3_ASSOC)):
                                    ?>
                                    <option value="<?php echo $server['name']; ?>" <?php echo $client['cloud_server'] == $server['name'] ? 'selected' : ''; ?>>
                                        <?php echo htmlspecialchars($server['description']); ?>
                                    </option>
                                    <?php endwhile; ?>
                                </select>
                            </div>
                            <button type="submit" style="margin-top:5px;">Update</button>
                        </form>
                    </td>
                    <td>
                        <a href="download.php?id=<?php echo $client['id']; ?>" target="_blank">Download Config</a>
                    </td>
                    <td>
                        <a href="qrcode.php?id=<?php echo $client['id']; ?>" target="_blank">Show QR Code</a>
                    </td>
                </tr>
                <?php endwhile; ?>
            </table>
        </div>
        
        <div id="cloud-servers" class="tab-content">
            <h2>Add Cloud VPN Server</h2>
            <form method="post">
                <input type="hidden" name="action" value="add_cloud_server">
                <div class="form-group">
                    <label for="server_name">Server Name (alphanumeric):</label>
                    <input type="text" id="server_name" name="server_name" required pattern="[a-zA-Z0-9\-]+" title="Alphanumeric characters only">
                </div>
                <div class="form-group">
                    <label for="description">Description:</label>
                    <input type="text" id="description" name="description" required>
                </div>
                <div class="form-group">
                    <label for="endpoint">Endpoint (IP:Port):</label>
                    <input type="text" id="endpoint" name="endpoint" required pattern="[0-9\.]+:[0-9]+" title="Format: IP:Port (e.g., 34.251.70.167:51820)">
                </div>
                <div class="form-group">
                    <label for="subnet">Subnet:</label>
                    <input type="text" id="subnet" name="subnet" required pattern="[0-9\.]+/[0-9]+" title="Format: CIDR (e.g., 10.1.0.0/24)">
                </div>
                <button type="submit">Add Cloud Server</button>
            </form>
            
            <h2>Cloud VPN Servers</h2>
            <table>
                <tr>
                    <th>Name</th>
                    <th>Description</th>
                    <th>Endpoint</th>
                    <th>Subnet</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
                <?php
                $result = $db->query("SELECT * FROM cloud_servers ORDER BY name");
                while ($server = $result->fetchArray(SQLITE3_ASSOC)):
                ?>
                <tr>
                    <td><?php echo htmlspecialchars($server['name']); ?></td>
                    <td><?php echo htmlspecialchars($server['description']); ?></td>
                    <td><?php echo htmlspecialchars($server['endpoint']); ?></td>
                    <td><?php echo htmlspecialchars($server['subnet']); ?></td>
                    <td><?php echo $server['is_active'] ? 'Active' : 'Inactive'; ?></td>
                    <td>
                        <form method="post">
                            <input type="hidden" name="action" value="toggle_cloud_server">
                            <input type="hidden" name="server_id" value="<?php echo $server['id']; ?>">
                            <button type="submit"><?php echo $server['is_active'] ? 'Deactivate' : 'Activate'; ?></button>
                        </form>
                        <a href="generate_cloud_config.php?id=<?php echo $server['id']; ?>" target="_blank">Generate Config</a>
                    </td>
                </tr>
                <?php endwhile; ?>
            </table>
        </div>
        
        <div id="system-status" class="tab-content">
            <h2>System Status</h2>
            <pre><?php echo htmlspecialchars(shell_exec('sudo wg show')); ?></pre>
            
            <h2>Connected Clients</h2>
            <pre><?php echo htmlspecialchars(shell_exec('sudo wg show wg0 dump | tail -n +2 | wc -l')); ?> client(s) connected</pre>
            
            <h2>Server Configuration</h2>
            <pre><?php echo htmlspecialchars(file_get_contents('/etc/wireguard/wg0.conf')); ?></pre>
        </div>
    </div>
    
    <script>
        function openTab(evt, tabName) {
            var i, tabcontent, tabbuttons;
            
            tabcontent = document.getElementsByClassName("tab-content");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            
            tabbuttons = document.getElementsByClassName("tab-button");
            for (i = 0; i < tabbuttons.length; i++) {
                tabbuttons[i].className = tabbuttons[i].className.replace(" active", "");
            }
            
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }
        
        function toggleCloudServerSelect(selectElement) {
            var clientId = selectElement.closest('form').querySelector('input[name="client_id"]').value;
            var cloudServerSelect = document.getElementById('cloud-server-select-' + clientId);
            
            if (selectElement.value === 'cloud') {
                cloudServerSelect.style.display = 'block';
            } else {
                cloudServerSelect.style.display = 'none';
            }
        }
    </script>
</body>
</html>
EOF

# Create download script for client configs
cat > /var/www/html/wireguard-manager/download.php << 'EOF'
<?php
$db = new SQLite3('/etc/wireguard/clients.db');

if (isset($_GET['id'])) {
    $stmt = $db->prepare("SELECT c.*, cs.endpoint AS cloud_endpoint, cs.subnet AS cloud_subnet, cs.public_key AS cloud_public_key 
                          FROM clients c 
                          LEFT JOIN cloud_servers cs ON c.cloud_server = cs.name 
                          WHERE c.id = :id");
    $stmt->bindValue(':id', $_GET['id'], SQLITE3_INTEGER);
    $result = $stmt->execute();
    $client = $result->fetchArray(SQLITE3_ASSOC);
    
    if ($client) {
        $client_config = "[Interface]\n";
        $client_config .= "PrivateKey = {$client['private_key']}\n";
        $client_config .= "Address = {$client['ip_address']}\n";
        $client_config .= "DNS = 8.8.8.8, 8.8.4.4\n\n";
        
        // Always add management server as the primary peer
        $server_public_key = trim(file_get_contents('/etc/wireguard/server_public.key'));
        $client_config .= "[Peer]\n";
        $client_config .= "PublicKey = {$server_public_key}\n";
        $client_config .= "Endpoint = 182.66.251.101:51820\n";
        
        if ($client['route_preference'] == 'management') {
            // Direct all traffic through management server
            $client_config .= "AllowedIPs = 0.0.0.0/0, ::/0\n";
        } elseif ($client['route_preference'] == 'cloud' && !empty($client['cloud_server'])) {
            // Route traffic to the VPN subnets (management & cloud)
            // But exclude the default route to allow the AWS cloud server to handle internet traffic
            $client_config .= "AllowedIPs = 10.0.0.0/24";
            
            if (!empty($client['cloud_subnet'])) {
                $client_config .= ", {$client['cloud_subnet']}";
            }
            
            $client_config .= "\n";
        }
        
        $client_config .= "PersistentKeepalive = 25\n";
        
        header('Content-Type: text/plain');
        header('Content-Disposition: attachment; filename="' . $client['name'] . '.conf"');
        echo $client_config;
        exit;
    }
}

header('Location: index.php');
?>
EOF

# Create QR code script
cat > /var/www/html/wireguard-manager/qrcode.php << 'EOF'
<?php
$db = new SQLite3('/etc/wireguard/clients.db');

if (isset($_GET['id'])) {
    $stmt = $db->prepare("SELECT c.*, cs.endpoint AS cloud_endpoint, cs.subnet AS cloud_subnet, cs.public_key AS cloud_public_key 
                          FROM clients c 
                          LEFT JOIN cloud_servers cs ON c.cloud_server = cs.name 
                          WHERE c.id = :id");
    $stmt->bindValue(':id', $_GET['id'], SQLITE3_INTEGER);
    $result = $stmt->execute();
    $client = $result->fetchArray(SQLITE3_ASSOC);
    
    if ($client) {
        $client_config = "[Interface]\n";
        $client_config .= "PrivateKey = {$client['private_key']}\n";
        $client_config .= "Address = {$client['ip_address']}\n";
        $client_config .= "DNS = 8.8.8.8, 8.8.4.4\n\n";
        
        // Always add management server as the primary peer
        $server_public_key = trim(file_get_contents('/etc/wireguard/server_public.key'));
        $client_config .= "[Peer]\n";
        $client_config .= "PublicKey = {$server_public_key}\n";
        $client_config .= "Endpoint = 182.66.251.101:51820\n";
        
        if ($client['route_preference'] == 'management') {
            $client_config .= "AllowedIPs = 0.0.0.0/0, ::/0\n";
        } elseif ($client['route_preference'] == 'cloud' && !empty($client['cloud_server'])) {
            $client_config .= "AllowedIPs = 10.0.0.0/24";
            
            if (!empty($client['cloud_subnet'])) {
                $client_config .= ", {$client['cloud_subnet']}";
            }
            
            $client_config .= "\n";
        }
        
        $client_config .= "PersistentKeepalive = 25\n";
        
        // Generate QR code
        header('Content-Type: text/html');
        echo '<!DOCTYPE html>
        <html>
        <head>
            <title>WireGuard QR Code - ' . htmlspecialchars($client['name']) . '</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; margin: 50px; }
                pre { text-align: left; background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px auto; display: inline-block; }
            </style>
        </head>
        <body>
            <h1>WireGuard QR Code for ' . htmlspecialchars($client['name']) . '</h1>
            <div>';
        
        // Use qrencode to generate QR code
        $tempfile = tempnam("/tmp", "wgqr");
        file_put_contents($tempfile, $client_config);
        system("qrencode -t PNG -o - < " . escapeshellarg($tempfile) . " | base64", $qr_output);
        unlink($tempfile);
        
        echo '<img src="data:image/png;base64,' . implode('', $qr_output) . '" alt="WireGuard QR Code">';
        echo '</div>
            <h2>Configuration:</h2>
            <pre>' . htmlspecialchars($client_config) . '</pre>
            <p><a href="index.php">Back to dashboard</a></p>
        </body>
        </html>';
        exit;
    }
}

header('Location: index.php');
?>
EOF

# Create cloud configuration generator
cat > /var/www/html/wireguard-manager/generate_cloud_config.php << 'EOF'
<?php
$db = new SQLite3('/etc/wireguard/clients.db');

if (isset($_GET['id'])) {
    $stmt = $db->prepare("SELECT * FROM cloud_servers WHERE id = :id");
    $stmt->bindValue(':id', $_GET['id'], SQLITE3_INTEGER);
    $result = $stmt->execute();
    $server = $result->fetchArray(SQLITE3_ASSOC);
    
    if ($server) {
        // Generate cloud server config
        $cloud_private_key = trim(shell_exec('wg genkey'));
        $cloud_public_key = trim(shell_exec('echo ' . escapeshellarg($cloud_private_key) . ' | wg pubkey'));
        
        // Update database with the public key
        $stmt = $db->prepare("UPDATE cloud_servers SET public_key = :public_key WHERE id = :id");
        $stmt->bindValue(':public_key', $cloud_public_key, SQLITE3_TEXT);
        $stmt->bindValue(':id', $server['id'], SQLITE3_INTEGER);
        $stmt->execute();
        
        // Save keys to file
        file_put_contents("/etc/wireguard/cloud_configs/{$server['name']}_private.key", $cloud_private_key);
        file_put_contents("/etc/wireguard/cloud_configs/{$server['name']}_public.key", $cloud_public_key);
        
        // Get management server public key
        $mgmt_public_key = trim(file_get_contents('/etc/wireguard/server_public.key'));
        
        // Create cloud server config
        $subnet_parts = explode('/', $server['subnet']);
        $subnet_ip = $subnet_parts[0];
        $subnet_ip_parts = explode('.', $subnet_ip);
        $subnet_ip_parts[3] = '1'; // Use .1 as the server address
        $cloud_ip = implode('.', $subnet_ip_parts) . '/' . $subnet_parts[1];
        
        $cloud_config = "[Interface]\n";
        $cloud_config .= "Address = {$cloud_ip}\n";
        $cloud_config .= "ListenPort = " . explode(':', $server['endpoint'])[1] . "\n";
        $cloud_config .= "PrivateKey = {$cloud_private_key}\n";
        $cloud_config .= "PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n";
        $cloud_config .= "PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE\n\n";
        
        // Add management server as peer
        $cloud_config .= "# Management Server\n";
        $cloud_config .= "[Peer]\n";
        $cloud_config .= "PublicKey = {$mgmt_public_key}\n";
        $cloud_config .= "AllowedIPs = 10.0.0.0/24\n";
        $cloud_config .= "PersistentKeepalive = 25\n";
        
        // Update WireGuard configuration to include this server
        exec('sudo php /var/www/html/wireguard-manager/update_routes.php');
        
        // Display the configuration
        header('Content-Type: text/html');
        echo '<!DOCTYPE html>
        <html>
        <head>
            <title>Cloud VPN Server Configuration - ' . htmlspecialchars($server['name']) . '</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; margin: 50px; }
                pre { text-align: left; background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px auto; display: inline-block; }
                .instructions { text-align: left; max-width: 800px; margin: 20px auto; }
            </style>
        </head>
        <body>
            <h1>Cloud VPN Server Configuration for ' . htmlspecialchars($server['name']) . '</h1>
            
            <div class="instructions">
                <h2>Setup Instructions:</h2>
                <ol>
                    <li>Create an EC2 instance in AWS for your VPN server.</li>
                    <li>Ensure security groups allow UDP port ' . explode(':', $server['endpoint'])[1] . ' inbound.</li>
                    <li>Install WireGuard: <code>sudo apt update && sudo apt install -y wireguard</code></li>
                    <li>Create the configuration file: <code>sudo nano /etc/wireguard/wg0.conf</code></li>
                    <li>Paste the configuration below into that file.</li>
                    <li>Enable IP forwarding: <code>echo "net.ipv4.ip_forward = 1" | sudo tee /etc/sysctl.d/99-wireguard.conf && sudo sysctl -p /etc/sysctl.d/99-wireguard.conf</code></li>
                    <li>Start WireGuard: <code>sudo systemctl enable wg-quick@wg0 && sudo systemctl start wg-quick@wg0</code></li>
                    <li>Verify it\'s running: <code>sudo wg show</code></li>
                </ol>
            </div>
            
            <h2>Configuration:</h2>
            <pre>' . htmlspecialchars($cloud_config) . '</pre>
            
            <p><a href="index.php">Back to dashboard</a></p>
        </body>
        </html>';
        exit;
    }
}

header('Location: index.php');
?>
EOF

# Create route update script
cat > /var/www/html/wireguard-manager/update_routes.php << 'EOF'
<?php
$db = new SQLite3('/etc/wireguard/clients.db');

// Management server base config
$serverPrivateKey = trim(file_get_contents('/etc/wireguard/server_private.key'));
$config = "[Interface]\n";
$config .= "Address = 10.0.0.1/24\n";
$config .= "ListenPort = 51820\n";
$config .= "PrivateKey = {$serverPrivateKey}\n";
$config .= "PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n";
$config .= "PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE\n\n";

// Add cloud server peers
$result = $db->query("SELECT * FROM cloud_servers WHERE is_active = 1 AND public_key != ''");
while ($server = $result->fetchArray(SQLITE3_ASSOC)) {
    $config .= "# Cloud Server: {$server['name']} - {$server['description']}\n";
    $config .= "[Peer]\n";
    $config .= "PublicKey = {$server['public_key']}\n";
    $config .= "Endpoint = {$server['endpoint']}\n";
    $config .= "AllowedIPs = {$server['subnet']}\n";
    $config .= "PersistentKeepalive = 25\n\n";
}

// Add clients
$result = $db->query("SELECT * FROM clients");
while ($client = $result->fetchArray(SQLITE3_ASSOC)) {
    $config .= "# Client: {$client['name']}\n";
    $config .= "[Peer]\n";
    $config .= "PublicKey = {$client['public_key']}\n";
    $config .= "AllowedIPs = " . str_replace('/24', '/32', $client['ip_address']) . "\n";
    
    if ($client['route_preference'] == 'cloud') {
        $config .= "# Route through cloud VPN: {$client['cloud_server']}\n\n";
    } else {
        $config .= "# Route through management server\n\n";
    }
}

// Write config
file_put_contents('/etc/wireguard/wg0.conf.new', $config);
exec('sudo mv /etc/wireguard/wg0.conf.new /etc/wireguard/wg0.conf');
exec('sudo systemctl restart wg-quick@wg0');
?>
EOF

# Set permissions
echo "[+] Setting permissions..."
chown -R www-data:www-data /var/www/html/wireguard-manager
chmod -R 755 /var/www/html/wireguard-manager
chmod 777 /etc/wireguard/clients.db
chmod 755 /etc/wireguard

# Allow www-data to restart WireGuard
echo "[+] Configuring sudo permissions for www-data..."
echo "www-data ALL=(ALL) NOPASSWD: /usr/bin/wg, /usr/bin/wg show, /bin/systemctl restart wg-quick@wg0" > /etc/sudoers.d/wireguard-manager
chmod 440 /etc/sudoers.d/wireguard-manager

# Start WireGuard
echo "[+] Starting WireGuard service..."
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# Display success message
echo "[+] WireGuard VPN Management Server setup complete!"
echo ""
echo "Management interface: http://$(hostname -I | awk '{print $1}')/wireguard-manager/"
echo "Public IP: $PUBLIC_IP"
echo "Server private key: $(cat /etc/wireguard/server_private.key)"
echo "Server public key: $(cat /etc/wireguard/server_public.key)"
echo ""
echo "Next steps:"
echo "1. Set up AWS Cloud VPN servers using the web interface"
echo "2. Add mobile device clients through the web interface"
echo "3. Scan QR codes with WireGuard mobile app to connect"
echo ""
echo "For security, consider:"
echo "- Setting up HTTPS for the web interface"
echo "- Adding basic authentication to the web management interface"
echo "- Setting up a firewall to only allow necessary traffic"
echo ""
