# WireGuard VPN Mobile Device Setup Guide

This guide provides step-by-step instructions for setting up the WireGuard VPN client on mobile devices (Android and iOS) to connect to your management server and route traffic through various cloud servers.

## Prerequisites

- Management server is properly set up and running
- At least one client profile has been created in the management interface
- WireGuard app installed on your mobile device
  - [Android - Google Play Store](https://play.google.com/store/apps/details?id=com.wireguard.android)
  - [iOS - App Store](https://apps.apple.com/us/app/wireguard/id1441195209)

## Setup Instructions

### Method 1: Using QR Code (Recommended)

1. **Access the Management Interface**
   - Open a web browser and navigate to your management server's URL:
   ```
   http://182.66.251.101/wireguard-manager/
   ```

2. **Generate QR Code**
   - Find your device in the client list
   - Click on "Show QR Code" next to your device name
   - A new page will open with the QR code

3. **Scan QR Code with Mobile Device**
   - **Android:**
     - Open the WireGuard app
     - Tap the "+" button
     - Select "Scan from QR code"
     - Point your camera at the QR code displayed on the management interface
     - Give your configuration a name when prompted

   - **iOS:**
     - Open the WireGuard app
     - Tap "Add a Tunnel"
     - Select "Create from QR code"
     - Point your camera at the QR code displayed on the management interface
     - Give your configuration a name when prompted

4. **Activate the VPN Connection**
   - Toggle the switch next to your new configuration to connect

### Method 2: Using Configuration File

1. **Download Configuration File**
   - In the management interface, find your device in the client list
   - Click on "Download Config" next to your device name
   - Save the .conf file to your device or email it to yourself

2. **Import Configuration**
   - **Android:**
     - Transfer the .conf file to your Android device
     - Open the WireGuard app
     - Tap the "+" button
     - Select "Import from file"
     - Browse to and select the configuration file
     - Give your configuration a name when prompted

   - **iOS:**
     - Transfer the .conf file to your iOS device
     - Open the WireGuard app
     - Tap "Add a Tunnel"
     - Select "Import from file"
     - Browse to and select the configuration file
     - Give your configuration a name when prompted

3. **Activate the VPN Connection**
   - Toggle the switch next to your new configuration to connect

## Switching Between VPN Servers

To switch your traffic routing between the management server and a cloud VPN server:

1. **Change Routing Preference in Management Interface**
   - Navigate to the management interface
   - Find your device in the client list
   - Change the "Routing Preference" dropdown to:
     - "Via Management Server" for direct internet access through your main server
     - "Via Cloud Server" to route traffic through a selected AWS cloud VPN server
   - If selecting "Via Cloud Server," choose the specific cloud server location from the dropdown that appears
   - Click "Update" to save your preference

2. **Download New Configuration**
   - Click "Download Config" to get the updated configuration file
   - Or click "Show QR Code" to get the updated QR code

3. **Update Mobile Device Configuration**
   - **Using QR Code:**
     - In the WireGuard app, tap the "+" button to add a new tunnel
     - Scan the new QR code
     - Give the configuration a new name (e.g., "VPN-Ireland" or "VPN-Tokyo")
     - Activate the new tunnel (this will disconnect any active tunnel)

   - **Using Configuration File:**
     - Import the new configuration file as described above
     - Give the configuration a distinctive name
     - Activate the new tunnel

## Troubleshooting

### Connection Issues

1. **Cannot Connect to Management Server**
   - Verify your mobile device has internet connectivity
   - Check that the management server is online and the WireGuard service is running
   - Confirm the server's IP address is correct in your configuration
   - Verify that port 51820 (or your configured port) is open on the server firewall

2. **Connected to Management Server but No Internet Access**
   - Check the server's internet connection
   - Verify IP forwarding is enabled on the server
   - Check iptables rules on the server to ensure NAT is working properly

3. **Cannot Connect to Cloud Server**
   - Verify the cloud server is running
   - Check that the cloud server's security group allows UDP traffic on port 51820
   - Verify the connection between the management server and cloud server

### Other Issues

- **Slow Connection Speed:**
  - Try connecting to a different cloud server location
  - Check if your ISP is throttling VPN traffic

- **App Crashes:**
  - Ensure your WireGuard app is updated to the latest version
  - Try reinstalling the app

## Advanced: Managing Multiple Configurations

You may want to keep multiple configurations on your device for different scenarios:

1. **Organization Tips:**
   - Use clear naming conventions (e.g., "Work-US", "Personal-Japan")
   - Only activate one tunnel at a time

2. **Manual Configuration Adjustment:**
   - In the WireGuard app, tap on an existing tunnel configuration
   - Tap "Edit" to modify settings manually
   - Advanced users can adjust AllowedIPs and other parameters directly

## Security Recommendations

1. **Device Security:**
   - Use a strong device passcode/biometrics
   - Configure WireGuard to connect automatically only on trusted networks

2. **Update Regularly:**
   - Keep the WireGuard app updated
   - Periodically generate new configurations for better security

3. **VPN Etiquette:**
   - Be aware of and respect the terms of service for websites you visit
   - Remember that while the VPN encrypts your traffic, you should still practice good security habits
