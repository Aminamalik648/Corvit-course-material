# MACPhantom – Automatic MAC Address Masking Tool for Kali Linux

MACPhantom is a lightweight tool for penetration testers, ethical hackers, and privacy-conscious users. It automatically changes your network interface's MAC address whenever you connect to a network, helping you stay anonymous and undetectable.

## Features
- Automatic MAC address change upon network connection
- Manual MAC change using a simple script
- Supports Ethernet (eth0) and Wi-Fi (wlan0)
- Easy to set up and lightweight

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/macphantom.git
   cd macphantom
"To enable auto MAC masking, copy 99-macphantom.sh to /etc/NetworkManager/dispatcher.d/ with sudo permissions."

