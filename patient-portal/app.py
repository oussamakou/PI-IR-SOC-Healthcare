from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
import logging
import datetime
import os

app = Flask(__name__)
# Generate a random secret key for session security on each restart
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# Security Configuration
app.config.update(
    SESSION_COOKIE_SECURE=False, # Set to True if running strictly over HTTPS (Ngrok handles this, but container is HTTP)
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(minutes=30)
)

# 1. CSRF Protection
csrf = CSRFProtect(app)

# 2. Security Headers (CSP, HSTS, etc.)
csp = {
    'default-src': ["'self'"],
    'style-src': ["'self'", "'unsafe-inline'", "fonts.googleapis.com"],
    'font-src': ["'self'", "fonts.gstatic.com"],
    'script-src': ["'self'", "'unsafe-inline'"]
}
# force_https=False because encryption is handled by Ngrok/Nginx terminators
talisman = Talisman(app, content_security_policy=csp, force_https=False)

# 3. Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# 4. Proxy Fix (Trust headers from Nginx/Ngrok for correct IP logging)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Configure logging
logging.basicConfig(
    filename='portal.log', 
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - [%(name)s] - %(message)s'
)
logger = logging.getLogger('MedCare+ Secure')

# Simulated user database
USERS = {
    'admin': {'password': 'password', 'role': 'Administrator', 'name': 'Dr. Admin'},
    'patient': {'password': 'patient', 'role': 'Patient', 'name': 'John Doe'},
    'nurse': {'password': 'nurse123', 'role': 'Nurse', 'name': 'Jane Smith'}
}

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute") # Strict generic rate limit to prevent brute force
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        logger.info(f"Login Attempt - User: {username} - IP: {request.remote_addr} - User-Agent: {request.headers.get('User-Agent', '')[:50]}")
        
        if username in USERS and USERS[username]['password'] == password:
            session.clear() # Prevent session fixation
            session['logged_in'] = True
            session['username'] = username
            session['role'] = USERS[username]['role']
            session['name'] = USERS[username]['name']
            
            # Rotate CSRF token after login
            
            logger.info(f"LOGIN SUCCESS - User: {username} - Role: {USERS[username]['role']} - IP: {request.remote_addr}")
            return redirect(url_for('dashboard'))
        else:
            logger.warning(f"LOGIN FAILED - User: {username} - IP: {request.remote_addr}")
            flash('Invalid username or password.')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    username = session.get('username')
    hour = datetime.datetime.now().hour
    return render_template('dashboard.html', username=username, hour=hour)

@app.route('/appointment', methods=['POST'])
@limiter.limit("10 per hour") # Prevent spamming appointments
def appointment():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    date = request.form.get('date')
    reason = request.form.get('reason')
    # Input sanitization would go here
    
    logger.info(f"APPOINTMENT SCHEDULED - User: {session['username']} - Date: {date}")
    flash(f'Appointment scheduled for {date}.')
    return redirect(url_for('dashboard'))

@app.route('/medical-records')
def medical_records():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    logger.warning(f"SENSITIVE DATA ACCESS - Medical Records - User: {session['username']} - IP: {request.remote_addr}")
    return render_template('medical_records.html', username=session['username'])

@app.route('/lab-results')
def lab_results():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('lab_results.html', username=session['username'])

@app.route('/prescriptions')
def prescriptions():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('prescriptions.html', username=session['username'])

@app.route('/messages')
def messages():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('messages.html', username=session['username'])

@app.route('/settings')
def settings():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('settings.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error_code=404, error_message='Page not found'), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning(f"RATE LIMIT EXCEEDED - IP: {request.remote_addr}")
    return render_template('error.html', error_code=429, error_message='Too many requests. Please try again later.'), 429

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
